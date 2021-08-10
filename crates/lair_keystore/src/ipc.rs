//! Ipc communication bindings.

use crate::entry::LairEntry;
use crate::store::EntryStoreSender;
use crate::*;
use futures::future::FutureExt;
use lair_keystore_api::ipc::{Passphrase, UnlockCb};
use lair_keystore_api::{actor::*, internal::*};
use parking_lot::Mutex;
use std::future::Future;

/// Spawn a new IPC server binding to serve out the Lair client api.
pub async fn spawn_bind_server_ipc(config: Arc<Config>) -> LairResult<()> {
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

    tokio::task::spawn(builder.spawn(Internal::new(config, i_s).await?));

    Ok(())
}

ghost_actor::ghost_chan! {
    chan InternalApi<LairError> {
        fn incoming_passphrase(passphrase: Passphrase) -> ();
    }
}

#[derive(Clone)]
enum PendingStoreActor {
    /// this keystore has never been initialized
    /// tasks should generate new db_keys,
    /// the first one complete wins, and all others
    /// will see "Unlocked" and have to re-validate against the winner.
    Unset { notify: Arc<tokio::sync::Notify> },

    /// this keystore has previously been initialized,
    /// tasks should generate a db_key, if successful and if this is still
    /// locked, unlock it and call notify.notify_wakers().
    Locked {
        notify: Arc<tokio::sync::Notify>,
        dbk_enc: DbKeyEnc,
    },

    /// this keystore is unlocked,
    /// tasks should generate a db_key to verify the passphrase,
    /// but do nothing else.
    Unlocked {
        dbk_enc: DbKeyEnc,
        store_actor: ghost_actor::GhostSender<store::EntryStore>,
    },
}

struct Internal {
    config: Arc<Config>,
    pending_store_actor: Arc<Mutex<PendingStoreActor>>,
}

impl Internal {
    pub async fn new(
        config: Arc<Config>,
        _i_s: ghost_actor::GhostSender<InternalApi>,
    ) -> LairResult<Self> {
        let pending_store_actor = match DbKeyEnc::read(&config).await {
            Ok(dbk_enc) => {
                tracing::info!("(db_key) file valid, initial: LOCKED");
                PendingStoreActor::Locked {
                    notify: Arc::new(tokio::sync::Notify::new()),
                    dbk_enc,
                }
            }
            Err(_) => {
                tracing::info!("(db_key) file invalid, initial: UNSET");
                PendingStoreActor::Unset {
                    notify: Arc::new(tokio::sync::Notify::new()),
                }
            }
        };
        Ok(Internal {
            config,
            pending_store_actor: Arc::new(Mutex::new(pending_store_actor)),
        })
    }

    fn wait_store(
        &self,
    ) -> impl Future<
        Output = LairResult<ghost_actor::GhostSender<store::EntryStore>>,
    >
           + 'static
           + Send {
        let pending_store_actor = self.pending_store_actor.clone();

        let notify = match &*pending_store_actor.lock() {
            PendingStoreActor::Unset { notify } => notify.clone(),
            PendingStoreActor::Locked { notify, .. } => notify.clone(),
            PendingStoreActor::Unlocked { store_actor, .. } => {
                let store_actor = store_actor.clone();
                return async move { Ok(store_actor) }.boxed();
            }
        };

        async move {
            tokio::time::timeout(
                std::time::Duration::from_secs(30),
                notify.notified(),
            )
            .await
            .map_err(LairError::other)?;
            match &*pending_store_actor.lock() {
                PendingStoreActor::Unlocked { store_actor, .. } => {
                    Ok(store_actor.clone())
                }
                _ => Err("uninitialized store".into()),
            }
        }
        .boxed()
    }
}

async fn try_check_unset(
    pending_store_actor: Arc<Mutex<PendingStoreActor>>,
    config: Arc<Config>,
    passphrase: Passphrase,
) -> LairResult<()> {
    tracing::debug!("(db_key) check: GENERATE");
    let (dbk_enc, db_key) = DbKeyEnc::generate(passphrase.clone()).await?;

    let (dbk_enc, did_succeed) = {
        let mut lock = pending_store_actor.lock();
        match &*lock {
            PendingStoreActor::Unset { notify } => {
                // we claimed it, go ahead an mark it so
                *lock = PendingStoreActor::Locked {
                    notify: notify.clone(),
                    dbk_enc: dbk_enc.clone(),
                };
                (dbk_enc, true)
            }
            PendingStoreActor::Locked { dbk_enc, .. }
            | PendingStoreActor::Unlocked { dbk_enc, .. } => {
                // someone else got to it first... we need to re-check
                // with the existing data
                (dbk_enc.clone(), false)
            }
        }
    };

    if did_succeed {
        // if this fails, our db is unreadable
        dbk_enc
            .write(&config)
            .await
            .expect("fatal failure to write db_key");

        tracing::info!(
            "(db_key) WRITE file. salt: {:02x?}, header: {:02x?}",
            &*dbk_enc.salt.read_lock(),
            &*dbk_enc.header.read_lock()
        );

        try_check_finalize(pending_store_actor, config, dbk_enc, db_key).await
    } else {
        try_check_maybe_locked(
            pending_store_actor,
            config,
            passphrase,
            dbk_enc.clone(),
        )
        .await
    }
}

async fn try_check_maybe_locked(
    pending_store_actor: Arc<Mutex<PendingStoreActor>>,
    config: Arc<Config>,
    passphrase: Passphrase,
    dbk_enc: DbKeyEnc,
) -> LairResult<()> {
    tracing::debug!("(db_key) check: MAYBE LOCKED");
    let db_key = dbk_enc.calc_db_key(passphrase).await?;
    try_check_finalize(pending_store_actor, config, dbk_enc, db_key).await
}

async fn try_check_finalize(
    pending_store_actor: Arc<Mutex<PendingStoreActor>>,
    config: Arc<Config>,
    dbk_enc: DbKeyEnc,
    db_key: sodoken::BufReadSized<32>,
) -> LairResult<()> {
    tracing::debug!("(db_key) check: FINALIZE");
    if let PendingStoreActor::Unlocked { .. } = &*pending_store_actor.lock() {
        return Ok(());
    }
    let store_actor = store::spawn_entry_store_actor(config, db_key).await?;
    let mut lock = pending_store_actor.lock();
    let notify = match &*lock {
        PendingStoreActor::Unset { notify } => notify.clone(),
        PendingStoreActor::Locked { notify, .. } => notify.clone(),
        PendingStoreActor::Unlocked { .. } => return Ok(()),
    };
    tracing::info!(
        "(db_key) UNLOCKED. salt: {:02x?}, header: {:02x?}",
        &*dbk_enc.salt.read_lock(),
        &*dbk_enc.header.read_lock()
    );
    *lock = PendingStoreActor::Unlocked {
        dbk_enc,
        store_actor,
    };
    notify.notify_waiters();
    Ok(())
}

impl ghost_actor::GhostControlHandler for Internal {}

impl ghost_actor::GhostHandler<InternalApi> for Internal {}

impl InternalApiHandler for Internal {
    fn handle_incoming_passphrase(
        &mut self,
        passphrase: Passphrase,
    ) -> InternalApiHandlerResult<()> {
        let config = self.config.clone();
        let pending_store_actor = self.pending_store_actor.clone();

        let cur = pending_store_actor.lock().clone();

        Ok(match cur {
            PendingStoreActor::Unset { .. } => {
                try_check_unset(pending_store_actor, config, passphrase)
                    .boxed()
                    .into()
            }
            PendingStoreActor::Locked { dbk_enc, .. } => {
                try_check_maybe_locked(
                    pending_store_actor,
                    config,
                    passphrase,
                    dbk_enc,
                )
                .boxed()
                .into()
            }
            PendingStoreActor::Unlocked { dbk_enc, .. } => {
                try_check_maybe_locked(
                    pending_store_actor,
                    config,
                    passphrase,
                    dbk_enc,
                )
                .boxed()
                .into()
            }
        })
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
