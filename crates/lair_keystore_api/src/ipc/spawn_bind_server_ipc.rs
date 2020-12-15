use super::*;
use crate::internal::ipc::*;
use crate::internal::wire::*;
use futures::{future::FutureExt, sink::SinkExt, stream::StreamExt};

pub(crate) async fn spawn_bind_server_ipc<S>(
    config: Arc<Config>,
    api_sender: S,
    incoming_send: futures::channel::mpsc::Sender<LairClientEventSenderType>,
) -> LairResult<()>
where
    S: ghost_actor::GhostChannelSender<LairClientApi>,
{
    let (kill_switch, mut incoming_ipc_recv) = spawn_bind_ipc(config).await?;

    let builder = ghost_actor::actor_builder::GhostActorBuilder::new();

    let channel_factory = builder.channel_factory().clone();

    let i_s = channel_factory.create_channel::<InternalApi>().await?;

    let kill_sender = i_s.clone();
    kill_switch
        .register_kill_callback(Box::new(move || {
            Box::pin(async move {
                use ghost_actor::GhostControlSender;
                if let Err(err) = kill_sender.ghost_actor_shutdown().await {
                    ghost_actor::dependencies::tracing::error!(?err);
                }
            })
        }))
        .await;

    let i_kill_switch = kill_switch.clone();
    err_spawn("srv-ipc-incoming-loop", async move {
        while let Ok((k, s, r)) = i_kill_switch
            .mix(async {
                incoming_ipc_recv
                    .next()
                    .await
                    .ok_or_else::<LairError, _>(|| "stream end".into())
            })
            .await
        {
            if i_kill_switch.mix(i_s.incoming(k, s, r)).await.is_err() {
                break;
            }
        }
        Ok(())
    });

    err_spawn("srv-ipc-actor", async move {
        builder
            .spawn(Internal {
                kill_switch,
                channel_factory,
                api_sender,
                incoming_send,
            })
            .await
            .map_err(LairError::other)
    });

    Ok(())
}

ghost_actor::ghost_chan! {
    chan InternalApi<LairError> {
        fn incoming(
            con_kill_switch: KillSwitch,
            ipc_send: IpcSender,
            ipc_recv: IpcReceiver,
        ) -> ();
    }
}

struct Internal<S>
where
    S: ghost_actor::GhostChannelSender<LairClientApi>,
{
    kill_switch: KillSwitch,
    channel_factory: ghost_actor::actor_builder::GhostActorChannelFactory<Self>,
    api_sender: S,
    incoming_send: futures::channel::mpsc::Sender<LairClientEventSenderType>,
}

impl<S> ghost_actor::GhostControlHandler for Internal<S> where
    S: ghost_actor::GhostChannelSender<LairClientApi>
{
}

impl<S> ghost_actor::GhostHandler<InternalApi> for Internal<S> where
    S: ghost_actor::GhostChannelSender<LairClientApi>
{
}

impl<S> InternalApiHandler for Internal<S>
where
    S: ghost_actor::GhostChannelSender<LairClientApi>,
{
    #[allow(clippy::single_match)]
    fn handle_incoming(
        &mut self,
        mut con_kill_switch: KillSwitch,
        ipc_send: IpcSender,
        ipc_recv: IpcReceiver,
    ) -> InternalApiHandlerResult<()> {
        // We don't actually want to kill this connection if the server
        // decides to drop the event sender. Make this kill switch weak.
        con_kill_switch.make_weak();

        let (evt_send, mut evt_recv) = futures::channel::mpsc::channel(10);
        let evt_ipc_send = ipc_send;
        err_spawn("srv-con-evt-loop", async move {
            while let Ok(msg) = evt_recv
                .next()
                .await
                .ok_or_else::<LairError, _>(|| "stream end".into())
            {
                match msg {
                    LairClientEvent::RequestUnlockPassphrase {
                        respond,
                        ..
                    } => {
                        match evt_ipc_send.request(LairWire::ToCliRequestUnlockPassphrase {
                            msg_id: next_msg_id(),
                        }).await {
                            Ok(LairWire::ToLairRequestUnlockPassphraseResponse {
                                passphrase,
                                ..
                            }) => {
                                respond.respond(Ok(async move {
                                    Ok(passphrase)
                                }.boxed().into()));
                            }
                            _ => (),
                        }
                    }
                }
            }
            Ok(())
        });
        let channel_factory = self.channel_factory.clone();
        let mut in_send_clone = self.incoming_send.clone();
        Ok(async move {
            channel_factory.attach_receiver(ipc_recv).await?;
            in_send_clone
                .send(evt_send)
                .await
                .map_err(LairError::other)?;
            Ok(())
        }
        .boxed()
        .into())
    }
}

impl<S> ghost_actor::GhostHandler<IpcWireApi> for Internal<S> where
    S: ghost_actor::GhostChannelSender<LairClientApi>
{
}

impl<S> IpcWireApiHandler for Internal<S>
where
    S: ghost_actor::GhostChannelSender<LairClientApi>,
{
    fn handle_request(
        &mut self,
        msg: LairWire,
    ) -> IpcWireApiHandlerResult<LairWire> {
        match msg {
            LairWire::ToLairLairGetServerInfo { msg_id } => {
                let fut = self
                    .kill_switch
                    .mix_static(self.api_sender.lair_get_server_info());
                Ok(async move {
                    fut.await.map(|info| {
                        LairWire::ToCliLairGetServerInfoResponse {
                            msg_id,
                            info,
                        }
                    })
                }
                .boxed()
                .into())
            }
            LairWire::ToLairLairGetLastEntryIndex { msg_id } => {
                let fut = self
                    .kill_switch
                    .mix_static(self.api_sender.lair_get_last_entry_index());
                Ok(async move {
                    fut.await.map(|last_keystore_index| {
                        LairWire::ToCliLairGetLastEntryIndexResponse {
                            msg_id,
                            last_keystore_index,
                        }
                    })
                }
                .boxed()
                .into())
            }
            LairWire::ToLairLairGetEntryType {
                msg_id,
                keystore_index,
            } => {
                let fut = self.kill_switch.mix_static(
                    self.api_sender.lair_get_entry_type(keystore_index),
                );
                Ok(async move {
                    fut.await.map(|lair_entry_type| {
                        LairWire::ToCliLairGetEntryTypeResponse {
                            msg_id,
                            lair_entry_type,
                        }
                    })
                }
                .boxed()
                .into())
            }
            LairWire::ToLairTlsCertNewSelfSignedFromEntropy {
                msg_id,
                cert_alg,
            } => {
                let options = TlsCertOptions { alg: cert_alg };
                let fut = self.kill_switch.mix_static(
                    self.api_sender
                        .tls_cert_new_self_signed_from_entropy(options),
                );
                Ok(async move {
                    fut.await.map(|(keystore_index, cert_sni, cert_digest)| {
                        LairWire::ToCliTlsCertNewSelfSignedFromEntropyResponse {
                            msg_id,
                            keystore_index,
                            cert_sni,
                            cert_digest,
                        }
                    })
                }
                .boxed()
                .into())
            }
            LairWire::ToLairTlsCertGet {
                msg_id,
                keystore_index,
            } => {
                let fut = self
                    .kill_switch
                    .mix_static(self.api_sender.tls_cert_get(keystore_index));
                Ok(async move {
                    fut.await.map(|(cert_sni, cert_digest)| {
                        LairWire::ToCliTlsCertGetResponse {
                            msg_id,
                            cert_sni,
                            cert_digest,
                        }
                    })
                }
                .boxed()
                .into())
            }
            LairWire::ToLairTlsCertGetCertByIndex {
                msg_id,
                keystore_index,
            } => {
                let fut = self.kill_switch.mix_static(
                    self.api_sender.tls_cert_get_cert_by_index(keystore_index),
                );
                Ok(async move {
                    fut.await.map(|cert| {
                        LairWire::ToCliTlsCertGetCertByIndexResponse {
                            msg_id,
                            cert,
                        }
                    })
                }
                .boxed()
                .into())
            }
            LairWire::ToLairTlsCertGetCertByDigest {
                msg_id,
                cert_digest,
            } => {
                let fut = self.kill_switch.mix_static(
                    self.api_sender.tls_cert_get_cert_by_digest(cert_digest),
                );
                Ok(async move {
                    fut.await.map(|cert| {
                        LairWire::ToCliTlsCertGetCertByDigestResponse {
                            msg_id,
                            cert,
                        }
                    })
                }
                .boxed()
                .into())
            }
            LairWire::ToLairTlsCertGetCertBySni { msg_id, cert_sni } => {
                let fut = self.kill_switch.mix_static(
                    self.api_sender.tls_cert_get_cert_by_sni(cert_sni),
                );
                Ok(async move {
                    fut.await.map(|cert| {
                        LairWire::ToCliTlsCertGetCertBySniResponse {
                            msg_id,
                            cert,
                        }
                    })
                }
                .boxed()
                .into())
            }
            LairWire::ToLairTlsCertGetPrivKeyByIndex {
                msg_id,
                keystore_index,
            } => {
                let fut = self.kill_switch.mix_static(
                    self.api_sender
                        .tls_cert_get_priv_key_by_index(keystore_index),
                );
                Ok(async move {
                    fut.await.map(|cert_priv_key| {
                        LairWire::ToCliTlsCertGetPrivKeyByIndexResponse {
                            msg_id,
                            cert_priv_key,
                        }
                    })
                }
                .boxed()
                .into())
            }
            LairWire::ToLairTlsCertGetPrivKeyByDigest {
                msg_id,
                cert_digest,
            } => {
                let fut = self.kill_switch.mix_static(
                    self.api_sender
                        .tls_cert_get_priv_key_by_digest(cert_digest),
                );
                Ok(async move {
                    fut.await.map(|cert_priv_key| {
                        LairWire::ToCliTlsCertGetPrivKeyByDigestResponse {
                            msg_id,
                            cert_priv_key,
                        }
                    })
                }
                .boxed()
                .into())
            }
            LairWire::ToLairTlsCertGetPrivKeyBySni { msg_id, cert_sni } => {
                let fut = self.kill_switch.mix_static(
                    self.api_sender.tls_cert_get_priv_key_by_sni(cert_sni),
                );
                Ok(async move {
                    fut.await.map(|cert_priv_key| {
                        LairWire::ToCliTlsCertGetPrivKeyBySniResponse {
                            msg_id,
                            cert_priv_key,
                        }
                    })
                }
                .boxed()
                .into())
            }
            LairWire::ToLairSignEd25519NewFromEntropy { msg_id } => {
                let fut = self.kill_switch.mix_static(
                    self.api_sender.sign_ed25519_new_from_entropy(),
                );
                Ok(async move {
                    fut.await.map(|(keystore_index, pub_key)| {
                        LairWire::ToCliSignEd25519NewFromEntropyResponse {
                            msg_id,
                            keystore_index,
                            pub_key,
                        }
                    })
                }
                .boxed()
                .into())
            }
            LairWire::ToLairSignEd25519Get {
                msg_id,
                keystore_index,
            } => {
                let fut = self.kill_switch.mix_static(
                    self.api_sender.sign_ed25519_get(keystore_index),
                );
                Ok(async move {
                    fut.await.map(|pub_key| {
                        LairWire::ToCliSignEd25519GetResponse {
                            msg_id,
                            pub_key,
                        }
                    })
                }
                .boxed()
                .into())
            }
            LairWire::ToLairSignEd25519SignByIndex {
                msg_id,
                keystore_index,
                message,
            } => {
                let fut = self.kill_switch.mix_static(
                    self.api_sender
                        .sign_ed25519_sign_by_index(keystore_index, message),
                );
                Ok(async move {
                    fut.await.map(|signature| {
                        LairWire::ToCliSignEd25519SignByIndexResponse {
                            msg_id,
                            signature,
                        }
                    })
                }
                .boxed()
                .into())
            }
            LairWire::ToLairSignEd25519SignByPubKey {
                msg_id,
                pub_key,
                message,
            } => {
                let fut = self.kill_switch.mix_static(
                    self.api_sender
                        .sign_ed25519_sign_by_pub_key(pub_key, message),
                );
                Ok(async move {
                    fut.await.map(|signature| {
                        LairWire::ToCliSignEd25519SignByPubKeyResponse {
                            msg_id,
                            signature,
                        }
                    })
                }
                .boxed()
                .into())
            }
            LairWire::ToLairX25519NewFromEntropy { msg_id } => {
                let fut = self
                    .kill_switch
                    .mix_static(self.api_sender.x25519_new_from_entropy());
                Ok(async move {
                    fut.await.map(|(keystore_index, pub_key)| {
                        LairWire::ToCliX25519NewFromEntropyResponse {
                            msg_id,
                            keystore_index,
                            pub_key,
                        }
                    })
                }
                .boxed()
                .into())
            }
            LairWire::ToLairX25519Get {
                msg_id,
                keystore_index,
            } => {
                let fut = self
                    .kill_switch
                    .mix_static(self.api_sender.x25519_get(keystore_index));
                Ok(async move {
                    fut.await.map(|pub_key| LairWire::ToCliX25519GetResponse {
                        msg_id,
                        pub_key,
                    })
                }
                .boxed()
                .into())
            }
            LairWire::ToLairCryptoBoxByIndex {
                msg_id,
                keystore_index,
                recipient,
                data,
            } => {
                let fut = self.kill_switch.mix_static(
                    self.api_sender.crypto_box_by_index(
                        keystore_index,
                        recipient,
                        data,
                    ),
                );
                Ok(async move {
                    fut.await.map(|encrypted_data| {
                        LairWire::ToCliCryptoBoxByIndexResponse {
                            msg_id,
                            encrypted_data,
                        }
                    })
                }
                .boxed()
                .into())
            }
            LairWire::ToLairCryptoBoxByPubKey {
                msg_id,
                pub_key,
                recipient,
                data,
            } => {
                let fut = self.kill_switch.mix_static(
                    self.api_sender
                        .crypto_box_by_pub_key(pub_key, recipient, data),
                );
                Ok(async move {
                    fut.await.map(|encrypted_data| {
                        LairWire::ToCliCryptoBoxByPubKeyResponse {
                            msg_id,
                            encrypted_data,
                        }
                    })
                }
                .boxed()
                .into())
            }
            LairWire::ToLairCryptoBoxOpenByIndex {
                msg_id,
                keystore_index,
                sender,
                encrypted_data,
            } => {
                let fut = self.kill_switch.mix_static(
                    self.api_sender.crypto_box_open_by_index(
                        keystore_index,
                        sender,
                        encrypted_data,
                    ),
                );
                Ok(async move {
                    fut.await.map(|data| {
                        LairWire::ToCliCryptoBoxOpenByIndexResponse {
                            msg_id,
                            data,
                        }
                    })
                }
                .boxed()
                .into())
            }
            LairWire::ToLairCryptoBoxOpenByPubKey {
                msg_id,
                pub_key,
                sender,
                encrypted_data,
            } => {
                let fut = self.kill_switch.mix_static(
                    self.api_sender.crypto_box_open_by_pub_key(
                        pub_key,
                        sender,
                        encrypted_data,
                    ),
                );
                Ok(async move {
                    fut.await.map(|data| {
                        LairWire::ToCliCryptoBoxOpenByPubKeyResponse {
                            msg_id,
                            data,
                        }
                    })
                }
                .boxed()
                .into())
            }
            o => Err(format!("unexpected: {:?}", o).into()),
        }
    }
}
