use super::*;
use crate::internal::ipc::*;
use crate::internal::wire::*;
use futures::stream::StreamExt;
use ghost_actor::dependencies::tracing;

pub(crate) async fn spawn_bind_server_ipc<S>(
    config: Arc<Config>,
    api_sender: S,
    unlock_cb: UnlockCb,
) -> LairResult<()>
where
    S: ghost_actor::GhostChannelSender<LairClientApi>,
{
    let incoming_ipc_recv = spawn_bind_ipc(config)?;

    err_spawn("srv-ipc-incoming-loop", async move {
        let unlock_cb = &unlock_cb;
        let api_sender = &api_sender;
        incoming_ipc_recv
            .for_each_concurrent(4096, move |res| async move {
                let (passphrase, ipc_send, ipc_recv) = match res.await {
                    Ok(res) => res,
                    Err(err) => {
                        tracing::warn!(?err, "err requesting passphrase");
                        return;
                    }
                };

                if let Err(err) = unlock_cb(passphrase).await {
                    tracing::warn!(?err, "err validating passphrase");
                    return;
                }

                spawn_srv_con_evt_loop(api_sender.clone(), ipc_send, ipc_recv);
            })
            .await;

        Ok(())
    });

    Ok(())
}

fn spawn_srv_con_evt_loop<S>(
    api_sender: S,
    ipc_send: IpcSender,
    ipc_recv: IpcReceiver,
) where
    S: ghost_actor::GhostChannelSender<LairClientApi>,
{
    tokio::task::spawn(async move {
        let api_sender = &api_sender;
        let ipc_send = &ipc_send;
        ipc_recv.for_each_concurrent(4096, move |res| async move {
            let res = match res {
                Ok(res) => res,
                Err(err) => {
                    tracing::warn!(?err, "err processing request");
                    return;
                }
            };

            let msg_id = res.get_msg_id();

            let res = async move {
                match res {
                    LairWire::ToLairLairGetServerInfo { .. } => {
                        let info = api_sender.lair_get_server_info().await?;
                        LairResult::Ok(LairWire::ToCliLairGetServerInfoResponse {
                            msg_id,
                            info,
                        })
                    }
                    LairWire::ToLairLairGetLastEntryIndex { .. } => {
                        let last_keystore_index = api_sender.lair_get_last_entry_index().await?;
                        Ok(LairWire::ToCliLairGetLastEntryIndexResponse {
                            msg_id,
                            last_keystore_index,
                        })
                    }
                    LairWire::ToLairLairGetEntryType { keystore_index, .. } => {
                        let lair_entry_type = api_sender.lair_get_entry_type(keystore_index).await?;
                        Ok(LairWire::ToCliLairGetEntryTypeResponse {
                            msg_id,
                            lair_entry_type,
                        })
                    }
                    LairWire::ToLairTlsCertNewSelfSignedFromEntropy {
                        cert_alg,
                        ..
                    } => {
                        let options = TlsCertOptions { alg: cert_alg };
                        let (keystore_index, cert_sni, cert_digest) =
                            api_sender
                                .tls_cert_new_self_signed_from_entropy(options).await?;
                        Ok(LairWire::ToCliTlsCertNewSelfSignedFromEntropyResponse {
                            msg_id,
                            keystore_index,
                            cert_sni,
                            cert_digest,
                        })
                    }
                    LairWire::ToLairTlsCertGet {
                        keystore_index,
                        ..
                    } => {
                        let (cert_sni, cert_digest) = api_sender.tls_cert_get(keystore_index).await?;
                        Ok(LairWire::ToCliTlsCertGetResponse {
                            msg_id,
                            cert_sni,
                            cert_digest,
                        })
                    }
                    LairWire::ToLairTlsCertGetCertByIndex {
                        keystore_index,
                        ..
                    } => {
                        let cert = api_sender.tls_cert_get_cert_by_index(keystore_index).await?;
                        Ok(LairWire::ToCliTlsCertGetCertByIndexResponse {
                            msg_id,
                            cert,
                        })
                    }
                    LairWire::ToLairTlsCertGetCertByDigest {
                        cert_digest,
                        ..
                    } => {
                        let cert = api_sender.tls_cert_get_cert_by_digest(cert_digest).await?;
                        Ok(LairWire::ToCliTlsCertGetCertByDigestResponse {
                            msg_id,
                            cert,
                        })
                    }
                    LairWire::ToLairTlsCertGetCertBySni { cert_sni, .. } => {
                        let cert = api_sender.tls_cert_get_cert_by_sni(cert_sni).await?;
                        Ok(LairWire::ToCliTlsCertGetCertBySniResponse {
                            msg_id,
                            cert,
                        })
                    }
                    LairWire::ToLairTlsCertGetPrivKeyByIndex {
                        keystore_index,
                        ..
                    } => {
                        let cert_priv_key = api_sender
                                .tls_cert_get_priv_key_by_index(keystore_index).await?;
                        Ok(LairWire::ToCliTlsCertGetPrivKeyByIndexResponse {
                            msg_id,
                            cert_priv_key,
                        })
                    }
                    LairWire::ToLairTlsCertGetPrivKeyByDigest {
                        cert_digest,
                        ..
                    } => {
                        let cert_priv_key = api_sender
                                .tls_cert_get_priv_key_by_digest(cert_digest).await?;
                        Ok(LairWire::ToCliTlsCertGetPrivKeyByDigestResponse {
                            msg_id,
                            cert_priv_key,
                        })
                    }
                    LairWire::ToLairTlsCertGetPrivKeyBySni { cert_sni, .. } => {
                        let cert_priv_key = api_sender.tls_cert_get_priv_key_by_sni(cert_sni).await?;
                        Ok(LairWire::ToCliTlsCertGetPrivKeyBySniResponse {
                            msg_id,
                            cert_priv_key,
                        })
                    }
                    LairWire::ToLairSignEd25519NewFromEntropy { .. } => {
                        let (keystore_index, pub_key) = api_sender.sign_ed25519_new_from_entropy().await?;
                        Ok(LairWire::ToCliSignEd25519NewFromEntropyResponse {
                            msg_id,
                            keystore_index,
                            pub_key,
                        })
                    }
                    LairWire::ToLairSignEd25519Get {
                        keystore_index,
                        ..
                    } => {
                        let pub_key = api_sender.sign_ed25519_get(keystore_index).await?;
                        Ok(LairWire::ToCliSignEd25519GetResponse {
                            msg_id,
                            pub_key,
                        })
                    }
                    LairWire::ToLairSignEd25519SignByIndex {
                        keystore_index,
                        message,
                        ..
                    } => {
                        let signature = api_sender
                                .sign_ed25519_sign_by_index(keystore_index, message).await?;
                        Ok(LairWire::ToCliSignEd25519SignByIndexResponse {
                            msg_id,
                            signature,
                        })
                    }
                    LairWire::ToLairSignEd25519SignByPubKey {
                        pub_key,
                        message,
                        ..
                    } => {
                        let signature = api_sender
                                .sign_ed25519_sign_by_pub_key(pub_key, message).await?;
                        Ok(LairWire::ToCliSignEd25519SignByPubKeyResponse {
                            msg_id,
                            signature,
                        })
                    }
                    LairWire::ToLairX25519NewFromEntropy { .. } => {
                        let (keystore_index, pub_key) = api_sender.x25519_new_from_entropy().await?;
                        Ok(LairWire::ToCliX25519NewFromEntropyResponse {
                            msg_id,
                            keystore_index,
                            pub_key,
                        })
                    }
                    LairWire::ToLairX25519Get { keystore_index, .. } => {
                        let pub_key = api_sender.x25519_get(keystore_index).await?;
                        Ok(LairWire::ToCliX25519GetResponse {
                            msg_id,
                            pub_key,
                        })
                    }
                    LairWire::ToLairCryptoBoxByIndex {
                        keystore_index,
                        recipient,
                        data,
                        ..
                    } => {
                        let encrypted_data = api_sender.crypto_box_by_index(
                            keystore_index,
                            recipient,
                            data,
                        ).await?;
                        Ok(LairWire::ToCliCryptoBoxByIndexResponse {
                            msg_id,
                            encrypted_data,
                        })
                    }
                    LairWire::ToLairCryptoBoxByPubKey {
                        pub_key,
                        recipient,
                        data,
                        ..
                    } => {
                        let encrypted_data = api_sender
                                .crypto_box_by_pub_key(pub_key, recipient, data).await?;
                        Ok(LairWire::ToCliCryptoBoxByPubKeyResponse {
                            msg_id,
                            encrypted_data,
                        })
                    }
                    LairWire::ToLairCryptoBoxOpenByIndex {
                        keystore_index,
                        sender,
                        encrypted_data,
                        ..
                    } => {
                        let data = api_sender.crypto_box_open_by_index(
                            keystore_index,
                            sender,
                            encrypted_data,
                        ).await?;
                        Ok(LairWire::ToCliCryptoBoxOpenByIndexResponse {
                            msg_id,
                            data,
                        })
                    }
                    LairWire::ToLairCryptoBoxOpenByPubKey {
                        pub_key,
                        sender,
                        encrypted_data,
                        ..
                    } => {
                        let data = api_sender.crypto_box_open_by_pub_key(
                            pub_key,
                            sender,
                            encrypted_data,
                        ).await?;
                        Ok(LairWire::ToCliCryptoBoxOpenByPubKeyResponse {
                            msg_id,
                            data,
                        })
                    }
                    o => Err(format!("unexpected: {:?}", o).into()),
                }
            }.await.unwrap_or_else(move |err| {
                let message = format!("{:?}", err);
                LairWire::ErrorResponse {
                    msg_id,
                    message,
                }
            });

            if let Err(err) = ipc_send.respond(res).await {
                tracing::warn!(?err, "err sending request response");
                ipc_send.close();
            }
        }).await;

        tracing::warn!("spawn-bind-server-con-loop ENDED");
    });
}
