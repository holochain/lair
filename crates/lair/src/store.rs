//! persistence manager for entry storage

use crate::*;
use entry::LairEntry;
use futures::future::FutureExt;
use std::collections::HashMap;

/// Keystore index type.
pub type KeystoreIndex = u32;

ghost_actor::ghost_chan! {
    /// persistence manager for entry storage
    pub chan EntryStore<LairError> {
        /// fetch an entry from the store by keystore index
        fn get_entry_by_index(index: KeystoreIndex) -> Arc<LairEntry>;

        /// generate a new tls cert entry && return it
        fn tls_cert_self_signed_new_from_entropy(
            options: internal::tls::TlsCertOptions,
        ) -> (KeystoreIndex, Arc<LairEntry>);

        /// generate a new signature ed25519 keypair entry && return it
        fn sign_ed25519_keypair_new_from_entropy() ->
            (KeystoreIndex, Arc<LairEntry>);
    }
}

ghost_actor::ghost_chan! {
    chan EntryStoreInternal<LairError> {
        fn finalize_new_entry(
            entry_index: KeystoreIndex,
            entry: Arc<LairEntry>,
        ) -> ();
    }
}

/// Spawn a new entry store actor.
pub async fn spawn_entry_actor(
    config: Arc<Config>,
    store_file: tokio::fs::File,
) -> LairResult<ghost_actor::GhostSender<EntryStore>> {
    let builder = ghost_actor::actor_builder::GhostActorBuilder::new();

    let sender = builder
        .channel_factory()
        .create_channel::<EntryStore>()
        .await?;

    let i_s = builder
        .channel_factory()
        .create_channel::<EntryStoreInternal>()
        .await?;

    tokio::task::spawn(
        builder.spawn(EntryStoreImpl::new(i_s, config, store_file).await?),
    );

    Ok(sender)
}

// -- internal -- //

mod store_file;
use store_file::EntryStoreFileSender;

#[allow(dead_code)]
struct EntryStoreImpl {
    i_s: ghost_actor::GhostSender<EntryStoreInternal>,
    config: Arc<Config>,
    store_file: futures::channel::mpsc::Sender<store_file::EntryStoreFile>,
    entries_by_index: HashMap<KeystoreIndex, Arc<LairEntry>>,
}

impl EntryStoreImpl {
    pub async fn new(
        i_s: ghost_actor::GhostSender<EntryStoreInternal>,
        config: Arc<Config>,
        store_file: tokio::fs::File,
    ) -> LairResult<Self> {
        let store_file =
            store_file::spawn_entry_store_file_task(store_file).await?;

        match store_file.init_load_unlock().await? {
            None => {
                // write a STUB unlock entry of all zeroes for now
                let unlock_entry = vec![0_u8; entry::ENTRY_SIZE];
                store_file.write_unlock(unlock_entry).await?;
            }
            Some(_unlock_entry) => {
                // someday, do some crypto stuff to read other entries
            }
        }

        let mut out = Self {
            i_s,
            config,
            store_file,
            entries_by_index: HashMap::new(),
        };

        // load / decode all entries
        for (entry_index, entry) in out.store_file.load_all_entries().await? {
            let entry = Arc::new(entry::LairEntry::decode(&entry)?);
            out.track_new_entry(entry_index, entry);
        }

        Ok(out)
    }

    fn track_new_entry(
        &mut self,
        entry_index: KeystoreIndex,
        entry: Arc<LairEntry>,
    ) {
        self.entries_by_index.insert(entry_index, entry);
    }
}

impl ghost_actor::GhostControlHandler for EntryStoreImpl {}

impl ghost_actor::GhostHandler<EntryStore> for EntryStoreImpl {}

impl EntryStoreHandler for EntryStoreImpl {
    fn handle_get_entry_by_index(
        &mut self,
        index: KeystoreIndex,
    ) -> EntryStoreHandlerResult<Arc<LairEntry>> {
        match self.entries_by_index.get(&index) {
            Some(entry) => {
                let entry = entry.clone();
                Ok(async move { Ok(entry) }.boxed().into())
            }
            None => Err(format!("invalid KeystoreIndex: {}", index).into()),
        }
    }

    fn handle_tls_cert_self_signed_new_from_entropy(
        &mut self,
        options: internal::tls::TlsCertOptions,
    ) -> EntryStoreHandlerResult<(KeystoreIndex, Arc<LairEntry>)> {
        Ok(
            new_tls_cert(self.i_s.clone(), self.store_file.clone(), options)
                .boxed()
                .into(),
        )
    }

    fn handle_sign_ed25519_keypair_new_from_entropy(
        &mut self,
    ) -> EntryStoreHandlerResult<(KeystoreIndex, Arc<LairEntry>)> {
        Ok(
            new_sign_ed25519_keypair(self.i_s.clone(), self.store_file.clone())
                .boxed()
                .into(),
        )
    }
}

impl ghost_actor::GhostHandler<EntryStoreInternal> for EntryStoreImpl {}

impl EntryStoreInternalHandler for EntryStoreImpl {
    fn handle_finalize_new_entry(
        &mut self,
        entry_index: KeystoreIndex,
        entry: Arc<LairEntry>,
    ) -> EntryStoreInternalHandlerResult<()> {
        self.track_new_entry(entry_index, entry);
        Ok(async move { Ok(()) }.boxed().into())
    }
}

async fn new_tls_cert(
    i_s: ghost_actor::GhostSender<EntryStoreInternal>,
    store_file: futures::channel::mpsc::Sender<store_file::EntryStoreFile>,
    options: internal::tls::TlsCertOptions,
) -> LairResult<(KeystoreIndex, Arc<LairEntry>)> {
    let cert = Arc::new(LairEntry::TlsCert(
        internal::tls::tls_cert_self_signed_new_from_entropy(options).await?,
    ));
    let encoded_cert = cert.encode()?;
    let entry_index = store_file.write_next_entry(encoded_cert).await?;
    i_s.finalize_new_entry(entry_index, cert.clone()).await?;
    Ok((entry_index, cert))
}

async fn new_sign_ed25519_keypair(
    i_s: ghost_actor::GhostSender<EntryStoreInternal>,
    store_file: futures::channel::mpsc::Sender<store_file::EntryStoreFile>,
) -> LairResult<(KeystoreIndex, Arc<LairEntry>)> {
    let entry = Arc::new(LairEntry::SignEd25519(
        internal::sign_ed25519::sign_ed25519_keypair_new_from_entropy().await?,
    ));
    let encoded_entry = entry.encode()?;
    let entry_index = store_file.write_next_entry(encoded_entry).await?;
    i_s.finalize_new_entry(entry_index, entry.clone()).await?;
    Ok((entry_index, entry))
}
