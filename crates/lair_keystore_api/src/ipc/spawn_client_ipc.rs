use super::*;
use crate::internal::ipc::*;
use crate::internal::wire::*;
use crate::internal::sign_ed25519;
use futures::{future::FutureExt, stream::StreamExt};

#[allow(clippy::single_match)]
pub(crate) async fn spawn_client_ipc(
    config: Arc<Config>,
    evt_send: futures::channel::mpsc::Sender<LairClientEvent>,
) -> LairResult<ghost_actor::GhostSender<LairClientApi>> {
    let (kill_switch, ipc_send, mut ipc_recv) =
        spawn_ipc_connection(config).await?;

    let evt_kill_switch = kill_switch.clone();
    err_spawn("client-ipc-evt-loop", async move {
        while let Ok(msg) = evt_kill_switch
            .mix(async {
                ipc_recv
                    .next()
                    .await
                    .ok_or_else::<LairError, _>(|| "stream end".into())
            })
            .await
        {
            match msg {
                IpcWireApi::Request { respond, msg, .. } => match msg {
                    LairWire::ToCliRequestUnlockPassphrase { msg_id } => {
                        let res = evt_kill_switch.mix(evt_send
                                .request_unlock_passphrase()).await
                                .map(|passphrase| {
                                    LairWire::ToLairRequestUnlockPassphraseResponse {
                                        msg_id,
                                        passphrase,
                                    }
                                });
                        respond.respond(Ok(async move { res }.boxed().into()));
                    }
                    _ => (),
                },
            }
        }
        Ok(())
    });

    let builder = ghost_actor::actor_builder::GhostActorBuilder::new();

    let sender = builder
        .channel_factory()
        .create_channel::<LairClientApi>()
        .await?;

    let kill_sender = sender.clone();
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

    err_spawn("client-ipc-actor", async move {
        builder
            .spawn(Internal {
                kill_switch,
                ipc_send,
            })
            .await
            .map_err(LairError::other)
    });

    Ok(sender)
}

struct Internal {
    kill_switch: KillSwitch,
    ipc_send: IpcSender,
}

impl ghost_actor::GhostControlHandler for Internal {}

impl ghost_actor::GhostHandler<LairClientApi> for Internal {}

impl LairClientApiHandler for Internal {
    fn handle_lair_get_server_info(
        &mut self,
    ) -> LairClientApiHandlerResult<LairServerInfo> {
        let fut = self.kill_switch.mix_static(self.ipc_send.request(
            LairWire::ToLairLairGetServerInfo {
                msg_id: next_msg_id(),
            },
        ));
        Ok(async move {
            trace!("awaiting server info");
            match fut.await? {
                LairWire::ToCliLairGetServerInfoResponse { info, .. } => {
                    trace!(?info, "GOT SERVER INFO");
                    Ok(info)
                }
                o => Err(format!("unexpected: {:?}", o).into()),
            }
        }
        .boxed()
        .into())
    }

    fn handle_lair_get_last_entry_index(
        &mut self,
    ) -> LairClientApiHandlerResult<KeystoreIndex> {
        let fut = self.kill_switch.mix_static(self.ipc_send.request(
            LairWire::ToLairLairGetLastEntryIndex {
                msg_id: next_msg_id(),
            },
        ));
        Ok(async move {
            match fut.await? {
                LairWire::ToCliLairGetLastEntryIndexResponse {
                    last_keystore_index,
                    ..
                } => Ok(last_keystore_index),
                o => Err(format!("unexpected: {:?}", o).into()),
            }
        }
        .boxed()
        .into())
    }

    fn handle_lair_get_entry_type(
        &mut self,
        keystore_index: KeystoreIndex,
    ) -> LairClientApiHandlerResult<LairEntryType> {
        let fut = self.kill_switch.mix_static(self.ipc_send.request(
            LairWire::ToLairLairGetEntryType {
                msg_id: next_msg_id(),
                keystore_index,
            },
        ));
        Ok(async move {
            match fut.await? {
                LairWire::ToCliLairGetEntryTypeResponse {
                    lair_entry_type,
                    ..
                } => Ok(lair_entry_type),
                o => Err(format!("unexpected: {:?}", o).into()),
            }
        }
        .boxed()
        .into())
    }

    fn handle_tls_cert_new_self_signed_from_entropy(
        &mut self,
        options: TlsCertOptions,
    ) -> LairClientApiHandlerResult<(KeystoreIndex, CertSni, CertDigest)> {
        let fut = self.kill_switch.mix_static(self.ipc_send.request(
            LairWire::ToLairTlsCertNewSelfSignedFromEntropy {
                msg_id: next_msg_id(),
                cert_alg: options.alg,
            },
        ));
        Ok(async move {
            match fut.await? {
                LairWire::ToCliTlsCertNewSelfSignedFromEntropyResponse {
                    keystore_index,
                    cert_sni,
                    cert_digest,
                    ..
                } => Ok((keystore_index, cert_sni, cert_digest)),
                o => Err(format!("unexpected: {:?}", o).into()),
            }
        }
        .boxed()
        .into())
    }

    fn handle_tls_cert_get(
        &mut self,
        keystore_index: KeystoreIndex,
    ) -> LairClientApiHandlerResult<(CertSni, CertDigest)> {
        let fut = self.kill_switch.mix_static(self.ipc_send.request(
            LairWire::ToLairTlsCertGet {
                msg_id: next_msg_id(),
                keystore_index,
            },
        ));
        Ok(async move {
            match fut.await? {
                LairWire::ToCliTlsCertGetResponse {
                    cert_sni,
                    cert_digest,
                    ..
                } => Ok((cert_sni, cert_digest)),
                o => Err(format!("unexpected: {:?}", o).into()),
            }
        }
        .boxed()
        .into())
    }

    fn handle_tls_cert_get_cert_by_index(
        &mut self,
        keystore_index: KeystoreIndex,
    ) -> LairClientApiHandlerResult<Cert> {
        let fut = self.kill_switch.mix_static(self.ipc_send.request(
            LairWire::ToLairTlsCertGetCertByIndex {
                msg_id: next_msg_id(),
                keystore_index,
            },
        ));
        Ok(async move {
            match fut.await? {
                LairWire::ToCliTlsCertGetCertByIndexResponse {
                    cert, ..
                } => Ok(cert),
                o => Err(format!("unexpected: {:?}", o).into()),
            }
        }
        .boxed()
        .into())
    }

    fn handle_tls_cert_get_cert_by_digest(
        &mut self,
        cert_digest: CertDigest,
    ) -> LairClientApiHandlerResult<Cert> {
        let fut = self.kill_switch.mix_static(self.ipc_send.request(
            LairWire::ToLairTlsCertGetCertByDigest {
                msg_id: next_msg_id(),
                cert_digest,
            },
        ));
        Ok(async move {
            match fut.await? {
                LairWire::ToCliTlsCertGetCertByDigestResponse {
                    cert, ..
                } => Ok(cert),
                o => Err(format!("unexpected: {:?}", o).into()),
            }
        }
        .boxed()
        .into())
    }

    fn handle_tls_cert_get_cert_by_sni(
        &mut self,
        cert_sni: CertSni,
    ) -> LairClientApiHandlerResult<Cert> {
        let fut = self.kill_switch.mix_static(self.ipc_send.request(
            LairWire::ToLairTlsCertGetCertBySni {
                msg_id: next_msg_id(),
                cert_sni,
            },
        ));
        Ok(async move {
            match fut.await? {
                LairWire::ToCliTlsCertGetCertBySniResponse { cert, .. } => {
                    Ok(cert)
                }
                o => Err(format!("unexpected: {:?}", o).into()),
            }
        }
        .boxed()
        .into())
    }

    fn handle_tls_cert_get_priv_key_by_index(
        &mut self,
        keystore_index: KeystoreIndex,
    ) -> LairClientApiHandlerResult<CertPrivKey> {
        let fut = self.kill_switch.mix_static(self.ipc_send.request(
            LairWire::ToLairTlsCertGetPrivKeyByIndex {
                msg_id: next_msg_id(),
                keystore_index,
            },
        ));
        Ok(async move {
            match fut.await? {
                LairWire::ToCliTlsCertGetPrivKeyByIndexResponse {
                    cert_priv_key,
                    ..
                } => Ok(cert_priv_key),
                o => Err(format!("unexpected: {:?}", o).into()),
            }
        }
        .boxed()
        .into())
    }

    fn handle_tls_cert_get_priv_key_by_digest(
        &mut self,
        cert_digest: CertDigest,
    ) -> LairClientApiHandlerResult<CertPrivKey> {
        let fut = self.kill_switch.mix_static(self.ipc_send.request(
            LairWire::ToLairTlsCertGetPrivKeyByDigest {
                msg_id: next_msg_id(),
                cert_digest,
            },
        ));
        Ok(async move {
            match fut.await? {
                LairWire::ToCliTlsCertGetPrivKeyByDigestResponse {
                    cert_priv_key,
                    ..
                } => Ok(cert_priv_key),
                o => Err(format!("unexpected: {:?}", o).into()),
            }
        }
        .boxed()
        .into())
    }

    fn handle_tls_cert_get_priv_key_by_sni(
        &mut self,
        cert_sni: CertSni,
    ) -> LairClientApiHandlerResult<CertPrivKey> {
        let fut = self.kill_switch.mix_static(self.ipc_send.request(
            LairWire::ToLairTlsCertGetPrivKeyBySni {
                msg_id: next_msg_id(),
                cert_sni,
            },
        ));
        Ok(async move {
            match fut.await? {
                LairWire::ToCliTlsCertGetPrivKeyBySniResponse {
                    cert_priv_key,
                    ..
                } => Ok(cert_priv_key),
                o => Err(format!("unexpected: {:?}", o).into()),
            }
        }
        .boxed()
        .into())
    }

    fn handle_sign_ed25519_new_from_entropy(
        &mut self,
    ) -> LairClientApiHandlerResult<(KeystoreIndex, sign_ed25519::SignEd25519PubKey)> {
        let fut = self.kill_switch.mix_static(self.ipc_send.request(
            LairWire::ToLairSignEd25519NewFromEntropy {
                msg_id: next_msg_id(),
            },
        ));
        Ok(async move {
            match fut.await? {
                LairWire::ToCliSignEd25519NewFromEntropyResponse {
                    keystore_index,
                    pub_key,
                    ..
                } => Ok((keystore_index, pub_key)),
                o => Err(format!("unexpected: {:?}", o).into()),
            }
        }
        .boxed()
        .into())
    }

    fn handle_sign_ed25519_get(
        &mut self,
        keystore_index: KeystoreIndex,
    ) -> LairClientApiHandlerResult<sign_ed25519::SignEd25519PubKey> {
        let fut = self.kill_switch.mix_static(self.ipc_send.request(
            LairWire::ToLairSignEd25519Get {
                msg_id: next_msg_id(),
                keystore_index,
            },
        ));
        Ok(async move {
            match fut.await? {
                LairWire::ToCliSignEd25519GetResponse { pub_key, .. } => {
                    Ok(pub_key)
                }
                o => Err(format!("unexpected: {:?}", o).into()),
            }
        }
        .boxed()
        .into())
    }

    fn handle_sign_ed25519_sign_by_index(
        &mut self,
        keystore_index: KeystoreIndex,
        message: Arc<Vec<u8>>,
    ) -> LairClientApiHandlerResult<sign_ed25519::SignEd25519Signature> {
        let fut = self.kill_switch.mix_static(self.ipc_send.request(
            LairWire::ToLairSignEd25519SignByIndex {
                msg_id: next_msg_id(),
                keystore_index,
                message,
            },
        ));
        Ok(async move {
            match fut.await? {
                LairWire::ToCliSignEd25519SignByIndexResponse {
                    signature,
                    ..
                } => Ok(signature),
                o => Err(format!("unexpected: {:?}", o).into()),
            }
        }
        .boxed()
        .into())
    }

    fn handle_sign_ed25519_sign_by_pub_key(
        &mut self,
        pub_key: sign_ed25519::SignEd25519PubKey,
        message: Arc<Vec<u8>>,
    ) -> LairClientApiHandlerResult<sign_ed25519::SignEd25519Signature> {
        let fut = self.kill_switch.mix_static(self.ipc_send.request(
            LairWire::ToLairSignEd25519SignByPubKey {
                msg_id: next_msg_id(),
                pub_key,
                message,
            },
        ));
        Ok(async move {
            match fut.await? {
                LairWire::ToCliSignEd25519SignByPubKeyResponse {
                    signature,
                    ..
                } => Ok(signature),
                o => Err(format!("unexpected: {:?}", o).into()),
            }
        }
        .boxed()
        .into())
    }
}
