//! Lair in-memory store - usually for testing

use crate::lair_store::traits::*;
use crate::prelude::*;
use futures::future::{BoxFuture, FutureExt};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

/// create an in-memory LairStore
pub fn create_mem_store_factory() -> LairStoreFactory {
    LairStoreFactory(Arc::new(PrivMemStoreFactory))
}

// -- private -- //

struct PrivMemStoreFactory;

impl AsLairStoreFactory for PrivMemStoreFactory {
    fn connect_to_store(
        &self,
        unlock_secret: sodoken::BufReadSized<32>,
    ) -> BoxFuture<'static, LairResult<LairStore>> {
        async move {
            // construct a new in-memory store
            // use the unlock_secret directly as our bidi context key
            let inner = PrivMemStoreInner {
                bidi_key: unlock_secret,
                entry_by_tag: HashMap::new(),
                ed_pk_to_tag: HashMap::new(),
                x_pk_to_tag: HashMap::new(),
            };

            Ok(LairStore(Arc::new(PrivMemStore(Arc::new(RwLock::new(
                inner,
            ))))))
        }
        .boxed()
    }
}

struct PrivMemStoreInner {
    /// key for encryption / decryption of secrets
    bidi_key: sodoken::BufReadSized<32>,
    /// the actual entry store, keyed by tag
    entry_by_tag: HashMap<Arc<str>, LairEntry>,
    /// index for signature pub key to tag
    ed_pk_to_tag: HashMap<Ed25519PubKey, Arc<str>>,
    /// index for encryption pub key to tag
    x_pk_to_tag: HashMap<X25519PubKey, Arc<str>>,
}

struct PrivMemStore(Arc<RwLock<PrivMemStoreInner>>);

impl AsLairStore for PrivMemStore {
    fn get_bidi_ctx_key(&self) -> sodoken::BufReadSized<32> {
        self.0.read().bidi_key.clone()
    }

    fn list_entries(
        &self,
    ) -> BoxFuture<'static, LairResult<Vec<LairEntryInfo>>> {
        // generate / list entry info for all entries in the store
        let list = self
            .0
            .read()
            .entry_by_tag
            .values()
            .map(|e| match &**e {
                LairEntryInner::Seed { tag, seed_info, .. } => {
                    LairEntryInfo::Seed {
                        tag: tag.clone(),
                        seed_info: seed_info.clone(),
                    }
                }
                LairEntryInner::DeepLockedSeed { tag, seed_info, .. } => {
                    LairEntryInfo::DeepLockedSeed {
                        tag: tag.clone(),
                        seed_info: seed_info.clone(),
                    }
                }
                LairEntryInner::WkaTlsCert { tag, cert_info, .. } => {
                    LairEntryInfo::WkaTlsCert {
                        tag: tag.clone(),
                        cert_info: cert_info.clone(),
                    }
                }
            })
            .collect();
        async move { Ok(list) }.boxed()
    }

    fn write_entry(
        &self,
        entry: LairEntry,
    ) -> BoxFuture<'static, LairResult<()>> {
        // pull out the tag / indexes of the entry
        let (tag, ed, x) = match &*entry {
            LairEntryInner::Seed { tag, seed_info, .. } => (
                tag.clone(),
                Some(seed_info.ed25519_pub_key.clone()),
                Some(seed_info.x25519_pub_key.clone()),
            ),
            LairEntryInner::DeepLockedSeed { tag, seed_info, .. } => (
                tag.clone(),
                Some(seed_info.ed25519_pub_key.clone()),
                Some(seed_info.x25519_pub_key.clone()),
            ),
            LairEntryInner::WkaTlsCert { tag, .. } => (tag.clone(), None, None),
        };

        let mut lock = self.0.write();

        // refuse to overwrite entries
        if lock.entry_by_tag.contains_key(&tag) {
            return async move { Err("tag already registered".into()) }.boxed();
        }

        // if we have a signature pub key, add that index
        if let Some(ed) = ed {
            lock.ed_pk_to_tag.insert(ed, tag.clone());
        }

        // if we have an encryption pub key, add that index
        if let Some(x) = x {
            lock.x_pk_to_tag.insert(x, tag.clone());
        }

        // insert the actual entry by tag
        lock.entry_by_tag.insert(tag, entry);

        drop(lock);
        async move { Ok(()) }.boxed()
    }

    fn get_entry_by_tag(
        &self,
        tag: Arc<str>,
    ) -> BoxFuture<'static, LairResult<LairEntry>> {
        // look up / return an entry by tag
        let res = self
            .0
            .read()
            .entry_by_tag
            .get(&tag)
            .cloned()
            .ok_or_else(|| "tag not found".into());
        async move { res }.boxed()
    }

    fn get_entry_by_ed25519_pub_key(
        &self,
        ed25519_pub_key: Ed25519PubKey,
    ) -> BoxFuture<'static, LairResult<LairEntry>> {
        // look up / return an entry by signature pub key
        let inner = self.0.clone();
        async move {
            let lock = inner.read();
            let tag = lock
                .ed_pk_to_tag
                .get(&ed25519_pub_key)
                .cloned()
                .ok_or_else(|| one_err::OneErr::new("pub key not found"))?;
            lock.entry_by_tag
                .get(&tag)
                .cloned()
                .ok_or_else(|| "tag not found".into())
        }
        .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_mem_store_sanity() {
        // this is just a sanity / smoke test
        // the store gets a more thorough workout in the in-proc server tests

        let factory = create_mem_store_factory();

        let store = factory
            .connect_to_store(sodoken::BufReadSized::from([0xff; 32]))
            .await
            .unwrap();

        let seed_info = store.new_seed("test-seed".into()).await.unwrap();
        println!("generated new seed: {:#?}", seed_info);

        let list = store.list_entries().await.unwrap();
        println!("list_entries: {:#?}", list);
        assert_eq!(1, list.len());

        println!(
            "entry: {:#?}",
            store.get_entry_by_tag("test-seed".into()).await.unwrap()
        );
    }
}
