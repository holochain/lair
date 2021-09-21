//! Lair in-memory store - usually for testing

use crate::lair_core::traits::*;
use crate::lair_core::*;
use crate::LairResult;
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
    bidi_key: sodoken::BufReadSized<32>,
    entry_by_tag: HashMap<Arc<str>, LairEntry>,
    ed_pk_to_tag: HashMap<Ed25519PubKey, Arc<str>>,
    x_pk_to_tag: HashMap<X25519PubKey, Arc<str>>,
}

struct PrivMemStore(Arc<RwLock<PrivMemStoreInner>>);

impl AsLairStore for PrivMemStore {
    fn get_bidi_context_key(&self) -> sodoken::BufReadSized<32> {
        self.0.read().bidi_key.clone()
    }

    fn list_entries(
        &self,
    ) -> BoxFuture<'static, LairResult<Vec<LairEntryInfo>>> {
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
                LairEntryInner::TlsCert { tag, cert_info, .. } => {
                    LairEntryInfo::TlsCert {
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
            LairEntryInner::TlsCert { tag, .. } => (tag.clone(), None, None),
        };
        let mut lock = self.0.write();
        if lock.entry_by_tag.contains_key(&tag) {
            return async move { Err("tag already registered".into()) }.boxed();
        }
        if let Some(ed) = ed {
            lock.ed_pk_to_tag.insert(ed, tag.clone());
        }
        if let Some(x) = x {
            lock.x_pk_to_tag.insert(x, tag.clone());
        }
        lock.entry_by_tag.insert(tag, entry);
        drop(lock);
        async move { Ok(()) }.boxed()
    }

    fn get_entry_by_tag(
        &self,
        tag: Arc<str>,
    ) -> BoxFuture<'static, LairResult<LairEntry>> {
        let res = self
            .0
            .read()
            .entry_by_tag
            .get(&tag)
            .cloned()
            .ok_or_else(|| "tag not found".into());
        async move { res }.boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_mem_store() {
        let factory = create_mem_store_factory();
        let store = factory
            .connect_to_store(sodoken::BufReadSized::from([0xff; 32]))
            .await
            .unwrap();
        let seed_info = store.new_seed("test-seed".into()).await.unwrap();
        println!("generated new seed: {:#?}", seed_info);
        println!("list_entries: {:#?}", store.list_entries().await.unwrap());
        println!(
            "entry: {:#?}",
            store.get_entry_by_tag("test-seed".into()).await.unwrap()
        );
    }
}
