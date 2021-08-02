use super::*;
use crate::internal::crypto_box;
use crate::internal::ipc::*;
use crate::internal::sign_ed25519;
use crate::internal::wire::*;
use crate::internal::x25519;
use futures::{future::FutureExt, stream::StreamExt};

pub(crate) async fn spawn_client_ipc(
    config: Arc<Config>,
    evt_send: futures::channel::mpsc::Sender<LairClientEvent>,
) -> LairResult<ghost_actor::GhostSender<LairClientApi>> {
    let (ipc_send, mut ipc_recv) = spawn_ipc_connection(config).await?;

    let ipc_send2 = ipc_send.clone();
    err_spawn("client-ipc-evt-loop", async move {
        // note - if we are ever handling more than unlock passphrase
        //        consider a for_each_concurrent here.
        while let Some(msg) = ipc_recv.next().await {
            match msg? {
                LairWire::ToCliRequestUnlockPassphrase { msg_id } => {
                    let res = evt_send
                        .request_unlock_passphrase()
                        .await
                        .map(|passphrase| {
                            LairWire::ToLairRequestUnlockPassphraseResponse {
                                msg_id,
                                passphrase,
                            }
                        })
                        .unwrap_or_else(|err| {
                            let message = format!("{:?}", err);
                            LairWire::ErrorResponse { msg_id, message }
                        });
                    ipc_send2.respond(res).await?;
                }
                oth => {
                    let msg_id = oth.get_msg_id();
                    let message = format!("unexpected {:?}", oth);
                    ipc_send2
                        .respond(LairWire::ErrorResponse { msg_id, message })
                        .await?;
                }
            }
        }

        Ok(())
    });

    let builder = ghost_actor::actor_builder::GhostActorBuilder::new();

    let sender = builder
        .channel_factory()
        .create_channel::<LairClientApi>()
        .await?;

    err_spawn("client-ipc-actor", async move {
        builder
            .spawn(Internal { ipc_send })
            .await
            .map_err(LairError::other)
    });

    Ok(sender)
}

struct Internal {
    ipc_send: IpcSender,
}

impl ghost_actor::GhostControlHandler for Internal {}

impl ghost_actor::GhostHandler<LairClientApi> for Internal {}

impl LairClientApiHandler for Internal {
    fn handle_lair_get_server_info(
        &mut self,
    ) -> LairClientApiHandlerResult<LairServerInfo> {
        let fut = self.ipc_send.request(LairWire::ToLairLairGetServerInfo {
            msg_id: next_msg_id(),
        });
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
        let fut =
            self.ipc_send
                .request(LairWire::ToLairLairGetLastEntryIndex {
                    msg_id: next_msg_id(),
                });
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
        let fut = self.ipc_send.request(LairWire::ToLairLairGetEntryType {
            msg_id: next_msg_id(),
            keystore_index,
        });
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
        let fut = self.ipc_send.request(
            LairWire::ToLairTlsCertNewSelfSignedFromEntropy {
                msg_id: next_msg_id(),
                cert_alg: options.alg,
            },
        );
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
        let fut = self.ipc_send.request(LairWire::ToLairTlsCertGet {
            msg_id: next_msg_id(),
            keystore_index,
        });
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
        let fut =
            self.ipc_send
                .request(LairWire::ToLairTlsCertGetCertByIndex {
                    msg_id: next_msg_id(),
                    keystore_index,
                });
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
        let fut =
            self.ipc_send
                .request(LairWire::ToLairTlsCertGetCertByDigest {
                    msg_id: next_msg_id(),
                    cert_digest,
                });
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
        let fut = self.ipc_send.request(LairWire::ToLairTlsCertGetCertBySni {
            msg_id: next_msg_id(),
            cert_sni,
        });
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
        let fut =
            self.ipc_send
                .request(LairWire::ToLairTlsCertGetPrivKeyByIndex {
                    msg_id: next_msg_id(),
                    keystore_index,
                });
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
        let fut =
            self.ipc_send
                .request(LairWire::ToLairTlsCertGetPrivKeyByDigest {
                    msg_id: next_msg_id(),
                    cert_digest,
                });
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
        let fut =
            self.ipc_send
                .request(LairWire::ToLairTlsCertGetPrivKeyBySni {
                    msg_id: next_msg_id(),
                    cert_sni,
                });
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
    ) -> LairClientApiHandlerResult<(
        KeystoreIndex,
        sign_ed25519::SignEd25519PubKey,
    )> {
        let fut =
            self.ipc_send
                .request(LairWire::ToLairSignEd25519NewFromEntropy {
                    msg_id: next_msg_id(),
                });
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
        let fut = self.ipc_send.request(LairWire::ToLairSignEd25519Get {
            msg_id: next_msg_id(),
            keystore_index,
        });
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
        let fut =
            self.ipc_send
                .request(LairWire::ToLairSignEd25519SignByIndex {
                    msg_id: next_msg_id(),
                    keystore_index,
                    message,
                });
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
        let fut =
            self.ipc_send
                .request(LairWire::ToLairSignEd25519SignByPubKey {
                    msg_id: next_msg_id(),
                    pub_key,
                    message,
                });
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

    fn handle_x25519_new_from_entropy(
        &mut self,
    ) -> LairClientApiHandlerResult<(KeystoreIndex, x25519::X25519PubKey)> {
        let fut = self.ipc_send.request(LairWire::ToLairX25519NewFromEntropy {
            msg_id: next_msg_id(),
        });
        Ok(async move {
            match fut.await? {
                LairWire::ToCliX25519NewFromEntropyResponse {
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

    fn handle_x25519_get(
        &mut self,
        keystore_index: KeystoreIndex,
    ) -> LairClientApiHandlerResult<x25519::X25519PubKey> {
        let fut = self.ipc_send.request(LairWire::ToLairX25519Get {
            msg_id: next_msg_id(),
            keystore_index,
        });
        Ok(async move {
            match fut.await? {
                LairWire::ToCliX25519GetResponse { pub_key, .. } => Ok(pub_key),
                o => Err(format!("unexpected: {:?}", o).into()),
            }
        }
        .boxed()
        .into())
    }

    fn handle_crypto_box_by_index(
        &mut self,
        keystore_index: KeystoreIndex,
        recipient: x25519::X25519PubKey,
        data: Arc<crypto_box::CryptoBoxData>,
    ) -> LairClientApiHandlerResult<crypto_box::CryptoBoxEncryptedData> {
        let fut = self.ipc_send.request(LairWire::ToLairCryptoBoxByIndex {
            msg_id: next_msg_id(),
            keystore_index,
            recipient,
            data,
        });
        Ok(async move {
            match fut.await? {
                LairWire::ToCliCryptoBoxByIndexResponse {
                    encrypted_data,
                    ..
                } => Ok(encrypted_data),
                o => Err(format!("unexpected: {:?}", o).into()),
            }
        }
        .boxed()
        .into())
    }

    fn handle_crypto_box_by_pub_key(
        &mut self,
        pub_key: x25519::X25519PubKey,
        recipient: x25519::X25519PubKey,
        data: Arc<crypto_box::CryptoBoxData>,
    ) -> LairClientApiHandlerResult<crypto_box::CryptoBoxEncryptedData> {
        let fut = self.ipc_send.request(LairWire::ToLairCryptoBoxByPubKey {
            msg_id: next_msg_id(),
            pub_key,
            recipient,
            data,
        });
        Ok(async move {
            match fut.await? {
                LairWire::ToCliCryptoBoxByPubKeyResponse {
                    encrypted_data,
                    ..
                } => Ok(encrypted_data),
                o => Err(format!("unexpected: {:?}", o).into()),
            }
        }
        .boxed()
        .into())
    }

    fn handle_crypto_box_open_by_index(
        &mut self,
        keystore_index: KeystoreIndex,
        sender: x25519::X25519PubKey,
        encrypted_data: Arc<crypto_box::CryptoBoxEncryptedData>,
    ) -> LairClientApiHandlerResult<Option<crypto_box::CryptoBoxData>> {
        let fut = self.ipc_send.request(LairWire::ToLairCryptoBoxOpenByIndex {
            msg_id: next_msg_id(),
            keystore_index,
            sender,
            encrypted_data,
        });
        Ok(async move {
            match fut.await? {
                LairWire::ToCliCryptoBoxOpenByIndexResponse {
                    data, ..
                } => Ok(data),
                o => Err(format!("unexpected: {:?}", o).into()),
            }
        }
        .boxed()
        .into())
    }

    fn handle_crypto_box_open_by_pub_key(
        &mut self,
        pub_key: x25519::X25519PubKey,
        sender: x25519::X25519PubKey,
        encrypted_data: Arc<crypto_box::CryptoBoxEncryptedData>,
    ) -> LairClientApiHandlerResult<Option<crypto_box::CryptoBoxData>> {
        let fut =
            self.ipc_send
                .request(LairWire::ToLairCryptoBoxOpenByPubKey {
                    msg_id: next_msg_id(),
                    pub_key,
                    sender,
                    encrypted_data,
                });
        Ok(async move {
            match fut.await? {
                LairWire::ToCliCryptoBoxOpenByPubKeyResponse {
                    data, ..
                } => Ok(data),
                o => Err(format!("unexpected: {:?}", o).into()),
            }
        }
        .boxed()
        .into())
    }
}
