//! persistence manager for entry storage

use crate::*;
use entry::LairEntry;
use futures::future::FutureExt;
use lair_keystore_api::{actor::*, internal::*};
use std::collections::HashMap;

ghost_actor::ghost_chan! {
    /// persistence manager for entry storage
    pub chan EntryStore<LairError> {
        /// generate a new tls cert entry && save it && return it
        fn tls_cert_self_signed_new_from_entropy(
            options: TlsCertOptions,
        ) -> (KeystoreIndex, Arc<LairEntry>);

        /// generate a new signature ed25519 keypair entry && save it && return it
        fn sign_ed25519_keypair_new_from_entropy() ->
            (KeystoreIndex, Arc<LairEntry>);

        /// generate a new x25519 keypair entry && save it && return it
        fn x25519_keypair_new_from_entropy() -> (KeystoreIndex, Arc<LairEntry>);

        /// fetch the highest / most recently added keystore_index
        fn get_last_entry_index() -> KeystoreIndex;

        /// fetch an entry from the store by keystore index
        fn get_entry_by_index(index: KeystoreIndex) -> Arc<LairEntry>;

        /// fetch an entry by its 32 byte public identifier
        /// for kepair, this is the pub key
        /// for tls cert, this is the digest
        fn get_entry_by_pub_id(id: Arc<Vec<u8>>) -> (KeystoreIndex, Arc<LairEntry>);

        /// get a tls cert entry by sni
        fn get_entry_by_sni(sni: CertSni) -> (KeystoreIndex, Arc<LairEntry>);
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
pub async fn spawn_entry_store_actor(
    config: Arc<Config>,
    sql_db_path: std::path::PathBuf,
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
        builder.spawn(EntryStoreImpl::new(i_s, config, sql_db_path).await?),
    );

    Ok(sender)
}

// -- internal -- //

#[allow(dead_code)]
mod store_sqlite;
use store_sqlite::SqlPool;

//mod store_file;
//use store_file::EntryStoreFileSender;

struct EntryStoreImpl {
    i_s: ghost_actor::GhostSender<EntryStoreInternal>,
    #[allow(dead_code)]
    config: Arc<Config>,
    //store_file: futures::channel::mpsc::Sender<store_file::EntryStoreFile>,
    db: SqlPool,
    last_entry_index: KeystoreIndex,
    entries_by_index: HashMap<KeystoreIndex, Arc<LairEntry>>,
    #[allow(clippy::rc_buffer)]
    entries_by_pub_id: HashMap<Arc<Vec<u8>>, (KeystoreIndex, Arc<LairEntry>)>,
    entries_by_sni: HashMap<CertSni, (KeystoreIndex, Arc<LairEntry>)>,
}

impl EntryStoreImpl {
    pub async fn new(
        i_s: ghost_actor::GhostSender<EntryStoreInternal>,
        config: Arc<Config>,
        sql_db_file: std::path::PathBuf,
    ) -> LairResult<Self> {
        let db = SqlPool::new(sql_db_file).await?;

        match db.init_load_unlock().await? {
            None => {
                // write a STUB unlock entry of all zeroes for now
                let unlock_entry = vec![0_u8; entry::ENTRY_SIZE];
                db.write_unlock(unlock_entry).await?;
            }
            Some(_unlock_entry) => {
                // someday, do some crypto stuff to read other entries
            }
        }

        let mut out = Self {
            i_s,
            config,
            db,
            last_entry_index: 0.into(),
            entries_by_index: HashMap::new(),
            entries_by_pub_id: HashMap::new(),
            entries_by_sni: HashMap::new(),
        };

        // load / decode all entries
        for (entry_index, entry) in out.db.load_all_entries().await? {
            let entry = Arc::new(entry::LairEntry::decode(&entry)?);
            out.track_new_entry(entry_index, entry);
            if entry_index.0 > out.last_entry_index.0 {
                out.last_entry_index = entry_index;
            }
        }

        Ok(out)
    }

    fn track_new_entry(
        &mut self,
        entry_index: KeystoreIndex,
        entry: Arc<LairEntry>,
    ) {
        self.entries_by_index.insert(entry_index, entry.clone());

        match &*entry {
            LairEntry::TlsCert(e) => {
                self.entries_by_sni
                    .insert(e.sni.clone(), (entry_index, entry.clone()));
                self.entries_by_pub_id
                    .insert(e.cert_digest.0.clone(), (entry_index, entry));
            }
            LairEntry::SignEd25519(e) => {
                self.entries_by_pub_id
                    .insert(e.pub_key.0.clone(), (entry_index, entry));
            }
            LairEntry::X25519(e) => {
                self.entries_by_pub_id.insert(
                    Arc::new(e.pub_key.to_bytes().to_vec()),
                    (entry_index, entry),
                );
            }
            _ => {
                tracing::warn!(
                    "silently ignoring unhandled entry type {:?}",
                    entry
                );
            }
        }

        if entry_index.0 > self.last_entry_index.0 {
            self.last_entry_index = entry_index;
        }
    }
}

impl ghost_actor::GhostControlHandler for EntryStoreImpl {}

impl ghost_actor::GhostHandler<EntryStore> for EntryStoreImpl {}

impl EntryStoreHandler for EntryStoreImpl {
    fn handle_tls_cert_self_signed_new_from_entropy(
        &mut self,
        options: TlsCertOptions,
    ) -> EntryStoreHandlerResult<(KeystoreIndex, Arc<LairEntry>)> {
        Ok(
            new_tls_cert(self.i_s.clone(), self.db.clone(), options)
                .boxed()
                .into(),
        )
    }

    fn handle_sign_ed25519_keypair_new_from_entropy(
        &mut self,
    ) -> EntryStoreHandlerResult<(KeystoreIndex, Arc<LairEntry>)> {
        Ok(
            new_sign_ed25519_keypair(self.i_s.clone(), self.db.clone())
                .boxed()
                .into(),
        )
    }

    fn handle_x25519_keypair_new_from_entropy(
        &mut self,
    ) -> EntryStoreHandlerResult<(KeystoreIndex, Arc<LairEntry>)> {
        Ok(
            new_x25519_keypair(self.i_s.clone(), self.db.clone())
                .boxed()
                .into(),
        )
    }

    fn handle_get_last_entry_index(
        &mut self,
    ) -> EntryStoreHandlerResult<KeystoreIndex> {
        let idx = self.last_entry_index;
        Ok(async move { Ok(idx) }.boxed().into())
    }

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

    fn handle_get_entry_by_pub_id(
        &mut self,
        id: Arc<Vec<u8>>,
    ) -> EntryStoreHandlerResult<(KeystoreIndex, Arc<LairEntry>)> {
        match self.entries_by_pub_id.get(&id) {
            Some(entry) => {
                let entry = entry.clone();
                Ok(async move { Ok(entry) }.boxed().into())
            }
            None => Err(format!("invalid pub id: {:?}", id).into()),
        }
    }

    fn handle_get_entry_by_sni(
        &mut self,
        sni: CertSni,
    ) -> EntryStoreHandlerResult<(KeystoreIndex, Arc<LairEntry>)> {
        match self.entries_by_sni.get(&sni) {
            Some(entry) => {
                let entry = entry.clone();
                Ok(async move { Ok(entry) }.boxed().into())
            }
            None => Err(format!("invalid sni: {:?}", sni).into()),
        }
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
    db: SqlPool,
    options: TlsCertOptions,
) -> LairResult<(KeystoreIndex, Arc<LairEntry>)> {
    let cert = Arc::new(LairEntry::TlsCert(
        tls::tls_cert_self_signed_new_from_entropy(options).await?,
    ));
    let encoded_cert = cert.encode()?;
    let entry_index = db.write_next_entry(encoded_cert).await?;
    i_s.finalize_new_entry(entry_index, cert.clone()).await?;
    Ok((entry_index, cert))
}

async fn new_sign_ed25519_keypair(
    i_s: ghost_actor::GhostSender<EntryStoreInternal>,
    db: SqlPool,
) -> LairResult<(KeystoreIndex, Arc<LairEntry>)> {
    let entry = Arc::new(LairEntry::SignEd25519(
        sign_ed25519::sign_ed25519_keypair_new_from_entropy().await?,
    ));
    let encoded_entry = entry.encode()?;
    let entry_index = db.write_next_entry(encoded_entry).await?;
    i_s.finalize_new_entry(entry_index, entry.clone()).await?;
    Ok((entry_index, entry))
}

async fn new_x25519_keypair(
    i_s: ghost_actor::GhostSender<EntryStoreInternal>,
    db: SqlPool,
) -> LairResult<(KeystoreIndex, Arc<LairEntry>)> {
    let entry = Arc::new(LairEntry::X25519(
        x25519::x25519_keypair_new_from_entropy().await?,
    ));
    let encoded_entry = entry.encode()?;
    let entry_index = db.write_next_entry(encoded_entry).await?;
    i_s.finalize_new_entry(entry_index, entry.clone()).await?;
    Ok((entry_index, entry))
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! as_cert {
        ($e:ident) => {
            let $e = match &*$e {
                LairEntry::TlsCert(e) => e,
                _ => panic!("unexpected"),
            };
        };
    }

    macro_rules! as_sign {
        ($e:ident) => {
            let $e = match &*$e {
                LairEntry::SignEd25519(e) => e,
                _ => panic!("unexpected"),
            };
        };
    }

    macro_rules! as_x25519 {
        ($e:ident) => {
            let $e = match &*$e {
                LairEntry::X25519(e) => e,
                _ => panic!("unexpected"),
            };
        };
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn it_can_store_and_retrieve_entries_from_disk() {
        let tmpdir = tempfile::tempdir().unwrap();

        let (cert, sign, x25519) = {
            let config = Config::builder().set_root_path(tmpdir.path()).build();

            let sql_db_path = config.get_store_path().to_owned();

            let store =
                spawn_entry_store_actor(config, sql_db_path).await.unwrap();

            let (cert_index, cert) =
                store
                    .tls_cert_self_signed_new_from_entropy(
                        TlsCertOptions::default(),
                    )
                    .await
                    .unwrap();
            assert_eq!(1, cert_index.0);

            let (sign_index, sign) =
                store.sign_ed25519_keypair_new_from_entropy().await.unwrap();
            assert_eq!(2, sign_index.0);

            let (x25519_index, x25519) =
                store.x25519_keypair_new_from_entropy().await.unwrap();
            assert_eq!(3, x25519_index.0);

            use ghost_actor::GhostControlSender;
            store.ghost_actor_shutdown().await.unwrap();
            drop(store);

            (cert, sign, x25519)
        };
        as_cert!(cert);
        as_sign!(sign);
        as_x25519!(x25519);

        let config = Config::builder().set_root_path(tmpdir.path()).build();

        let sql_db_path = config.get_store_path().to_owned();

        let store = spawn_entry_store_actor(config, sql_db_path).await.unwrap();

        let r_cert = store.get_entry_by_index(1.into()).await.unwrap();
        let r_sign = store.get_entry_by_index(2.into()).await.unwrap();
        let r_x25519 = store.get_entry_by_index(3.into()).await.unwrap();
        as_cert!(r_cert);
        as_sign!(r_sign);
        as_x25519!(r_x25519);

        assert_eq!(cert.cert_digest, r_cert.cert_digest);
        assert_eq!(sign.pub_key, r_sign.pub_key);
        assert_eq!(x25519.pub_key, r_x25519.pub_key);

        let (r_cert_index, r_cert) = store
            .get_entry_by_pub_id(cert.cert_digest.0.clone())
            .await
            .unwrap();
        as_cert!(r_cert);
        assert_eq!(1, r_cert_index.0);
        assert_eq!(cert.cert_digest, r_cert.cert_digest);

        let (r_sign_index, r_sign) = store
            .get_entry_by_pub_id(sign.pub_key.0.clone())
            .await
            .unwrap();
        as_sign!(r_sign);
        assert_eq!(2, r_sign_index.0);
        assert_eq!(sign.pub_key, r_sign.pub_key);

        let (r_x25519_index, r_x25519) = store
            .get_entry_by_pub_id(Arc::new(x25519.pub_key.to_bytes().to_vec()))
            .await
            .unwrap();
        as_x25519!(r_x25519);
        assert_eq!(3, r_x25519_index.0);
        assert_eq!(x25519.pub_key, r_x25519.pub_key);

        let (r_cert_index, r_cert) =
            store.get_entry_by_sni(cert.sni.clone()).await.unwrap();
        as_cert!(r_cert);
        assert_eq!(1, r_cert_index.0);
        assert_eq!(cert.cert_digest, r_cert.cert_digest);

        use ghost_actor::GhostControlSender;
        store.ghost_actor_shutdown().await.unwrap();
        drop(store);
        drop(tmpdir);
    }
}
