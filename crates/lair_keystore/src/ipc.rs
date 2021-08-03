//! Ipc communication bindings.

use crate::entry::LairEntry;
use crate::store::EntryStoreSender;
use crate::*;
use futures::future::Shared;
use futures::future::{BoxFuture, FutureExt};
use lair_keystore_api::ipc::{Passphrase, UnlockCb};
use lair_keystore_api::{actor::*, internal::*};
use std::future::Future;

/// Spawn a new IPC server binding to serve out the Lair client api.
pub async fn spawn_bind_server_ipc(config: Arc<Config>) -> LairResult<()> {
    /*
    let store_actor =
        store::spawn_entry_store_actor(config.clone(), sql_db_path).await?;
    */

    let builder = ghost_actor::actor_builder::GhostActorBuilder::new();

    let api_sender = builder
        .channel_factory()
        .create_channel::<LairClientApi>()
        .await?;

    let i_s = builder
        .channel_factory()
        .create_channel::<InternalApi>()
        .await?;

    let i_s2 = i_s.clone();
    let unlock_cb: UnlockCb = Arc::new(move |passphrase| {
        let i_s2 = i_s2.clone();
        async move {
            i_s2.incoming_passphrase(passphrase).await?;
            Ok(())
        }
        .boxed()
    });

    lair_keystore_api::ipc::spawn_bind_server_ipc(
        config.clone(),
        api_sender,
        unlock_cb,
    )
    .await?;

    tokio::task::spawn(builder.spawn(Internal::new(config, i_s)?));

    Ok(())
}

ghost_actor::ghost_chan! {
    chan InternalApi<LairError> {
        fn incoming_passphrase(passphrase: Passphrase) -> ();
        fn incoming_db_key(db_key: sodoken::BufRead) -> ();
    }
}

struct Internal {
    config: Arc<Config>,
    i_s: ghost_actor::GhostSender<InternalApi>,
    #[allow(clippy::type_complexity)]
    store_actor: Option<
        Shared<
            BoxFuture<
                'static,
                Result<ghost_actor::GhostSender<store::EntryStore>, String>,
            >,
        >,
    >,
}

impl Internal {
    pub fn new(
        config: Arc<Config>,
        i_s: ghost_actor::GhostSender<InternalApi>,
    ) -> LairResult<Self> {
        Ok(Internal {
            config,
            i_s,
            store_actor: None,
        })
    }

    fn wait_store(
        &self,
    ) -> impl Future<
        Output = LairResult<ghost_actor::GhostSender<store::EntryStore>>,
    >
           + 'static
           + Send {
        let fut = self
            .store_actor
            .as_ref()
            .cloned()
            .ok_or_else(|| LairError::from("uninitialized store"));
        async move { Ok(fut?.await?) }
    }
}

impl ghost_actor::GhostControlHandler for Internal {}

impl ghost_actor::GhostHandler<InternalApi> for Internal {}

impl InternalApiHandler for Internal {
    fn handle_incoming_passphrase(
        &mut self,
        passphrase: Passphrase,
    ) -> InternalApiHandlerResult<()> {
        let db_key_path = self.config.get_db_key_path().to_owned();
        let i_s = self.i_s.clone();
        Ok(async move {
            let db_key = match tokio::fs::read(db_key_path.clone()).await {
                Ok(content) => {
                    use sodoken::argon2id::SALTBYTES;

                    // read the salt from the file
                    let salt: sodoken::BufReadSized<SALTBYTES> =
                        (&content[0..SALTBYTES]).into();

                    // calculate the pre_key given salt and passphrase
                    let pre_key = sodoken::BufWriteSized::new_mem_locked()?;
                    sodoken::argon2id::hash(
                        pre_key.clone(),
                        passphrase,
                        salt,
                        sodoken::argon2id::OPSLIMIT_SENSITIVE,
                        sodoken::argon2id::MEMLIMIT_SENSITIVE,
                    )
                    .await?;

                    // extract our message parts
                    use sodoken::secretstream_xchacha20poly1305::*;
                    let header: sodoken::BufReadSized<
                        SECRETSTREAM_HEADERBYTES,
                    > = (&content[32..32 + SECRETSTREAM_HEADERBYTES]).into();
                    let cipher = sodoken::BufRead::new_no_lock(
                        &content[32 + SECRETSTREAM_HEADERBYTES..],
                    );

                    // decrypt the db key given our calculated pre_key
                    let mut dec = SecretStreamDecrypt::new(pre_key, header)?;
                    let db_key = sodoken::BufWrite::new_mem_locked(32)?;
                    dec.pull(
                        cipher,
                        <Option<sodoken::BufRead>>::None,
                        db_key.clone(),
                    )
                    .await?;

                    db_key
                }
                Err(_) => {
                    // generate a new random salt
                    let salt = sodoken::BufWriteSized::new_no_lock();
                    sodoken::random::randombytes_buf(salt.clone()).await?;

                    // calculate the pre_key given salt and passphrase
                    let pre_key = sodoken::BufWriteSized::new_mem_locked()?;
                    sodoken::argon2id::hash(
                        pre_key.clone(),
                        passphrase,
                        salt.clone(),
                        sodoken::argon2id::OPSLIMIT_SENSITIVE,
                        sodoken::argon2id::MEMLIMIT_SENSITIVE,
                    )
                    .await?;

                    // generate a new random db_key
                    let db_key = sodoken::BufWrite::new_mem_locked(32)?;
                    sodoken::random::randombytes_buf(db_key.clone()).await?;

                    // encrypt the db_key with the pre_key
                    use sodoken::secretstream_xchacha20poly1305::*;
                    let cipher = sodoken::BufWrite::new_unbound_no_lock();
                    cipher
                        .to_extend()
                        .extend_lock()
                        .extend_mut_from_slice(&*salt.read_lock())?;

                    let mut enc =
                        SecretStreamEncrypt::new(pre_key, cipher.clone())?;
                    enc.push_final(
                        db_key.clone(),
                        <Option<sodoken::BufRead>>::None,
                        cipher.clone(),
                    )
                    .await?;

                    // write the salt and cipher to the db key file
                    // erm... this is annoying...
                    let data = cipher.read_lock().to_vec();
                    tokio::fs::write(db_key_path, &data).await?;

                    db_key
                }
            };

            i_s.incoming_db_key(db_key.to_read()).await?;

            Ok(())
        }
        .boxed()
        .into())
    }

    fn handle_incoming_db_key(
        &mut self,
        _db_key: sodoken::BufRead,
    ) -> InternalApiHandlerResult<()> {
        if self.store_actor.is_none() {
            let config = self.config.clone();
            self.store_actor = Some(
                async move {
                    store::spawn_entry_store_actor(config)
                        .await
                        .map_err(|e| format!("{:?}", e))
                }
                .boxed()
                .shared(),
            );
        };

        let store = self.wait_store();

        Ok(async move {
            store.await?;
            Ok(())
        }
        .boxed()
        .into())
    }
}

impl ghost_actor::GhostHandler<LairClientApi> for Internal {}

impl lair_keystore_api::actor::LairClientApiHandler for Internal {
    #[allow(clippy::field_reassign_with_default)]
    fn handle_lair_get_server_info(
        &mut self,
    ) -> LairClientApiHandlerResult<LairServerInfo> {
        let mut out = LairServerInfo::default();
        out.name = "lair-keystore".to_string();
        out.version = crate::LAIR_VER.to_string();

        Ok(async move { Ok(out) }.boxed().into())
    }

    fn handle_lair_get_last_entry_index(
        &mut self,
    ) -> LairClientApiHandlerResult<KeystoreIndex> {
        let store = self.wait_store();
        Ok(async move { store.await?.get_last_entry_index().await }
            .boxed()
            .into())
    }

    fn handle_lair_get_entry_type(
        &mut self,
        keystore_index: KeystoreIndex,
    ) -> LairClientApiHandlerResult<LairEntryType> {
        let store = self.wait_store();
        Ok(async move {
            match store.await?.get_entry_by_index(keystore_index).await {
                Err(_) => Ok(LairEntryType::Invalid),
                Ok(entry) => match &*entry {
                    LairEntry::TlsCert(_) => Ok(LairEntryType::TlsCert),
                    LairEntry::SignEd25519(_) => Ok(LairEntryType::SignEd25519),
                    LairEntry::X25519(_) => Ok(LairEntryType::X25519),
                    _ => {
                        Err(format!("unhandled entry type {:?}", entry).into())
                    }
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
        let store = self.wait_store();
        Ok(async move {
            let (keystore_index, entry) = store
                .await?
                .tls_cert_self_signed_new_from_entropy(options)
                .await?;
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
        let store = self.wait_store();
        Ok(async move {
            let entry = store.await?.get_entry_by_index(keystore_index).await?;
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
        let store = self.wait_store();
        Ok(async move {
            let entry = store.await?.get_entry_by_index(keystore_index).await?;
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
        let store = self.wait_store();
        Ok(async move {
            let (_, entry) =
                store.await?.get_entry_by_pub_id(cert_digest.0).await?;
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
        let store = self.wait_store();
        Ok(async move {
            let (_, entry) = store.await?.get_entry_by_sni(cert_sni).await?;
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
        let store = self.wait_store();
        Ok(async move {
            let entry = store.await?.get_entry_by_index(keystore_index).await?;
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
        let store = self.wait_store();
        Ok(async move {
            let (_, entry) =
                store.await?.get_entry_by_pub_id(cert_digest.0).await?;
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
        let store = self.wait_store();
        Ok(async move {
            let (_, entry) = store.await?.get_entry_by_sni(cert_sni).await?;
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
    ) -> LairClientApiHandlerResult<(
        KeystoreIndex,
        sign_ed25519::SignEd25519PubKey,
    )> {
        let store = self.wait_store();
        Ok(async move {
            let (keystore_index, entry) =
                store.await?.sign_ed25519_keypair_new_from_entropy().await?;
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
    ) -> LairClientApiHandlerResult<sign_ed25519::SignEd25519PubKey> {
        let store = self.wait_store();
        Ok(async move {
            let entry = store.await?.get_entry_by_index(keystore_index).await?;
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
    ) -> LairClientApiHandlerResult<sign_ed25519::SignEd25519Signature> {
        let store = self.wait_store();
        Ok(async move {
            let entry = store.await?.get_entry_by_index(keystore_index).await?;
            match &*entry {
                LairEntry::SignEd25519(entry) => {
                    sign_ed25519::sign_ed25519(entry.priv_key.clone(), message)
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
        pub_key: sign_ed25519::SignEd25519PubKey,
        message: Arc<Vec<u8>>,
    ) -> LairClientApiHandlerResult<sign_ed25519::SignEd25519Signature> {
        let store = self.wait_store();
        Ok(async move {
            let (_, entry) =
                store.await?.get_entry_by_pub_id(pub_key.0).await?;
            match &*entry {
                LairEntry::SignEd25519(entry) => {
                    sign_ed25519::sign_ed25519(entry.priv_key.clone(), message)
                        .await
                }
                _ => Err("invalid entry type".into()),
            }
        }
        .boxed()
        .into())
    }

    fn handle_x25519_new_from_entropy(
        &mut self,
    ) -> LairClientApiHandlerResult<(KeystoreIndex, x25519::X25519PubKey)> {
        let store = self.wait_store();
        Ok(async move {
            let (keystore_index, entry) =
                store.await?.x25519_keypair_new_from_entropy().await?;
            match &*entry {
                LairEntry::X25519(entry) => {
                    Ok((keystore_index, entry.pub_key.clone()))
                }
                _ => Err("invalid entry type".into()),
            }
        }
        .boxed()
        .into())
    }

    fn handle_x25519_get(
        &mut self,
        keystore_index: KeystoreIndex,
    ) -> LairClientApiHandlerResult<x25519::X25519PubKey> {
        let store = self.wait_store();
        Ok(async move {
            let entry = store.await?.get_entry_by_index(keystore_index).await?;
            match &*entry {
                LairEntry::X25519(entry) => Ok(entry.pub_key.clone()),
                _ => Err("invalid entry type".into()),
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
        let store = self.wait_store();
        Ok(async move {
            let entry = store.await?.get_entry_by_index(keystore_index).await?;
            match &*entry {
                LairEntry::X25519(entry) => {
                    crypto_box::crypto_box(
                        entry.priv_key.clone(),
                        recipient,
                        data,
                    )
                    .await
                }
                _ => Err("invalid entry type".into()),
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
        let store = self.wait_store();
        Ok(async move {
            let (_, entry) = store
                .await?
                .get_entry_by_pub_id(Arc::new(pub_key.to_bytes().to_vec()))
                .await?;
            match &*entry {
                LairEntry::X25519(entry) => {
                    crypto_box::crypto_box(
                        entry.priv_key.clone(),
                        recipient,
                        data,
                    )
                    .await
                }
                _ => Err("invalid entry type".into()),
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
        let store = self.wait_store();
        Ok(async move {
            let entry = store.await?.get_entry_by_index(keystore_index).await?;
            match &*entry {
                LairEntry::X25519(entry) => {
                    crypto_box::crypto_box_open(
                        entry.priv_key.clone(),
                        sender,
                        encrypted_data,
                    )
                    .await
                }
                _ => Err("invalid entry type".into()),
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
        let store = self.wait_store();
        Ok(async move {
            let (_, entry) = store
                .await?
                .get_entry_by_pub_id(Arc::new(pub_key.to_bytes().to_vec()))
                .await?;
            match &*entry {
                LairEntry::X25519(entry) => {
                    crypto_box::crypto_box_open(
                        entry.priv_key.clone(),
                        sender,
                        encrypted_data,
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
