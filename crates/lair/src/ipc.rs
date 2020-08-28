//! Ipc communication bindings.

use crate::entry::LairEntry;
use crate::store::EntryStoreSender;
use crate::*;
use futures::future::FutureExt;
use lair_api::actor::*;

/// Spawn a new IPC server binding to serve out the Lair client api.
pub async fn spawn_bind_server_ipc(
    config: Arc<Config>,
    store_file: tokio::fs::File,
) -> LairResult<()> {
    let store_actor =
        store::spawn_entry_store_actor(config.clone(), store_file).await?;

    let builder = ghost_actor::actor_builder::GhostActorBuilder::new();

    let _api_sender = builder
        .channel_factory()
        .create_channel::<LairClientApi>()
        .await?;

    tokio::task::spawn(builder.spawn(Internal::new(config, store_actor)?));

    Ok(())
}

struct Internal {
    #[allow(dead_code)]
    store_actor: ghost_actor::GhostSender<store::EntryStore>,
}

impl Internal {
    pub fn new(
        _config: Arc<Config>,
        store_actor: ghost_actor::GhostSender<store::EntryStore>,
    ) -> LairResult<Self> {
        Ok(Internal { store_actor })
    }
}

impl ghost_actor::GhostControlHandler for Internal {}

impl ghost_actor::GhostHandler<LairClientApi> for Internal {}

impl lair_api::actor::LairClientApiHandler for Internal {
    fn handle_lair_get_last_entry_index(
        &mut self,
    ) -> LairClientApiHandlerResult<KeystoreIndex> {
        Ok(self.store_actor.get_last_entry_index().boxed().into())
    }

    fn handle_lair_get_entry_type(
        &mut self,
        keystore_index: KeystoreIndex,
    ) -> LairClientApiHandlerResult<LairEntryType> {
        let fut = self.store_actor.get_entry_by_index(keystore_index);
        Ok(async move {
            match fut.await {
                Err(_) => Ok(LairEntryType::Invalid),
                Ok(entry) => match &*entry {
                    LairEntry::TlsCert(_) => Ok(LairEntryType::TlsCert),
                    LairEntry::SignEd25519(_) => Ok(LairEntryType::SignEd25519),
                },
            }
        }
        .boxed()
        .into())
    }

    fn handle_tls_cert_new_self_signed_from_entropy(
        &mut self,
        options: TlsCertOptions,
    ) -> LairClientApiHandlerResult<(KeystoreIndex, CertSni, CertDigest)> {
        let fut = self
            .store_actor
            .tls_cert_self_signed_new_from_entropy(options);
        Ok(async move {
            let (keystore_index, entry) = fut.await?;
            match &*entry {
                LairEntry::TlsCert(entry) => Ok((
                    keystore_index,
                    entry.sni.clone(),
                    entry.cert_digest.clone(),
                )),
                _ => Err("invalid entry type".into()),
            }
        }
        .boxed()
        .into())
    }

    fn handle_tls_cert_get(
        &mut self,
        keystore_index: KeystoreIndex,
    ) -> LairClientApiHandlerResult<(CertSni, CertDigest)> {
        let fut = self.store_actor.get_entry_by_index(keystore_index);
        Ok(async move {
            let entry = fut.await?;
            match &*entry {
                LairEntry::TlsCert(entry) => {
                    Ok((entry.sni.clone(), entry.cert_digest.clone()))
                }
                _ => Err("invalid entry type".into()),
            }
        }
        .boxed()
        .into())
    }

    fn handle_tls_cert_get_cert_by_index(
        &mut self,
        keystore_index: KeystoreIndex,
    ) -> LairClientApiHandlerResult<Cert> {
        let fut = self.store_actor.get_entry_by_index(keystore_index);
        Ok(async move {
            let entry = fut.await?;
            match &*entry {
                LairEntry::TlsCert(entry) => Ok(entry.cert_der.clone()),
                _ => Err("invalid entry type".into()),
            }
        }
        .boxed()
        .into())
    }

    fn handle_tls_cert_get_cert_by_digest(
        &mut self,
        cert_digest: CertDigest,
    ) -> LairClientApiHandlerResult<Cert> {
        let fut = self.store_actor.get_entry_by_pub_id(cert_digest.0);
        Ok(async move {
            let (_, entry) = fut.await?;
            match &*entry {
                LairEntry::TlsCert(entry) => Ok(entry.cert_der.clone()),
                _ => Err("invalid entry type".into()),
            }
        }
        .boxed()
        .into())
    }

    fn handle_tls_cert_get_cert_by_sni(
        &mut self,
        cert_sni: CertSni,
    ) -> LairClientApiHandlerResult<Cert> {
        let fut = self.store_actor.get_entry_by_sni(cert_sni);
        Ok(async move {
            let (_, entry) = fut.await?;
            match &*entry {
                LairEntry::TlsCert(entry) => Ok(entry.cert_der.clone()),
                _ => Err("invalid entry type".into()),
            }
        }
        .boxed()
        .into())
    }

    fn handle_tls_cert_get_priv_key_by_index(
        &mut self,
        keystore_index: KeystoreIndex,
    ) -> LairClientApiHandlerResult<CertPrivKey> {
        let fut = self.store_actor.get_entry_by_index(keystore_index);
        Ok(async move {
            let entry = fut.await?;
            match &*entry {
                LairEntry::TlsCert(entry) => Ok(entry.priv_key_der.clone()),
                _ => Err("invalid entry type".into()),
            }
        }
        .boxed()
        .into())
    }

    fn handle_tls_cert_get_priv_key_by_digest(
        &mut self,
        cert_digest: CertDigest,
    ) -> LairClientApiHandlerResult<CertPrivKey> {
        let fut = self.store_actor.get_entry_by_pub_id(cert_digest.0);
        Ok(async move {
            let (_, entry) = fut.await?;
            match &*entry {
                LairEntry::TlsCert(entry) => Ok(entry.priv_key_der.clone()),
                _ => Err("invalid entry type".into()),
            }
        }
        .boxed()
        .into())
    }

    fn handle_tls_cert_get_priv_key_by_sni(
        &mut self,
        cert_sni: CertSni,
    ) -> LairClientApiHandlerResult<CertPrivKey> {
        let fut = self.store_actor.get_entry_by_sni(cert_sni);
        Ok(async move {
            let (_, entry) = fut.await?;
            match &*entry {
                LairEntry::TlsCert(entry) => Ok(entry.priv_key_der.clone()),
                _ => Err("invalid entry type".into()),
            }
        }
        .boxed()
        .into())
    }

    fn handle_sign_ed25519_new_from_entropy(
        &mut self,
    ) -> LairClientApiHandlerResult<(KeystoreIndex, SignEd25519PubKey)> {
        let fut = self.store_actor.sign_ed25519_keypair_new_from_entropy();
        Ok(async move {
            let (keystore_index, entry) = fut.await?;
            match &*entry {
                LairEntry::SignEd25519(entry) => {
                    Ok((keystore_index, entry.pub_key.clone()))
                }
                _ => Err("invalid entry type".into()),
            }
        }
        .boxed()
        .into())
    }

    fn handle_sign_ed25519_get(
        &mut self,
        keystore_index: KeystoreIndex,
    ) -> LairClientApiHandlerResult<SignEd25519PubKey> {
        let fut = self.store_actor.get_entry_by_index(keystore_index);
        Ok(async move {
            let entry = fut.await?;
            match &*entry {
                LairEntry::SignEd25519(entry) => Ok(entry.pub_key.clone()),
                _ => Err("invalid entry type".into()),
            }
        }
        .boxed()
        .into())
    }

    fn handle_sign_ed25519_sign_by_index(
        &mut self,
        keystore_index: KeystoreIndex,
        message: Arc<Vec<u8>>,
    ) -> LairClientApiHandlerResult<SignEd25519Signature> {
        let fut = self.store_actor.get_entry_by_index(keystore_index);
        Ok(async move {
            let entry = fut.await?;
            match &*entry {
                LairEntry::SignEd25519(entry) => {
                    internal::sign_ed25519::sign_ed25519(
                        entry.priv_key.clone(),
                        message,
                    )
                    .await
                }
                _ => Err("invalid entry type".into()),
            }
        }
        .boxed()
        .into())
    }

    fn handle_sign_ed25519_sign_by_pub_key(
        &mut self,
        pub_key: SignEd25519PubKey,
        message: Arc<Vec<u8>>,
    ) -> LairClientApiHandlerResult<SignEd25519Signature> {
        let fut = self.store_actor.get_entry_by_pub_id(pub_key.0);
        Ok(async move {
            let (_, entry) = fut.await?;
            match &*entry {
                LairEntry::SignEd25519(entry) => {
                    internal::sign_ed25519::sign_ed25519(
                        entry.priv_key.clone(),
                        message,
                    )
                    .await
                }
                _ => Err("invalid entry type".into()),
            }
        }
        .boxed()
        .into())
    }
}
