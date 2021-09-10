//! Lair core types

use crate::LairResult2 as LairResult;
use futures::future::BoxFuture;
use std::future::Future;
use std::sync::Arc;

/// Helper traits for core types - you probably don't need these unless
/// you are implementing new lair core instance logic.
pub mod traits {
    use super::*;

    /// Defines a lair storage mechanism.
    pub trait AsLairStore: 'static + Send + Sync {
        /// List the entries tracked by the lair store.
        fn list_entries(
            &self,
        ) -> BoxFuture<'static, LairResult<Vec<LairEntryListItem>>>;

        /// Write a new entry to the lair store.
        fn write_entry(
            &self,
            entry: LairEntry,
        ) -> BoxFuture<'static, LairResult<()>>;

        /// Get an entry from the lair store by tag.
        fn get_entry_by_tag(
            &self,
            tag: &str,
        ) -> BoxFuture<'static, LairResult<LairEntry>>;
    }

    /// Defines a factory that produces lair storage mechanism instances.
    pub trait AsLairStoreFactory: 'static + Send + Sync {
        /// Open a store connection with given config / passphrase.
        fn connect_to_store(
            &self,
            config: LairConfig,
            passphrase: sodoken::BufRead,
        ) -> BoxFuture<'static, LairResult<LairStore>>;
    }

    /// Defines the lair client API.
    pub trait AsLairClient: 'static + Send + Sync {
        /// List the entries tracked by lair.
        /// This operation is a bit expensive, causing a lot of data cloning.
        fn list_entries(
            &self,
        ) -> BoxFuture<'static, LairResult<Vec<LairEntryListItem>>>;

        /// Generate a new cryptographically secure random seed.
        /// This will return the public 'SeedInfo' associated with this seed.
        fn new_seed(
            &self,
            tag: String,
        ) -> BoxFuture<'static, LairResult<SeedInfo>>;
    }
}
use traits::*;

/// Lair Configuration Inner Struct
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct LairConfigInner {}

/// Lair Configuration Type
pub type LairConfig = Arc<LairConfigInner>;

/// Public information associated with a given seed
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct SeedInfo {
    /// The ed25519 signature public key derived from this seed.
    pub ed25519_pub_key: [u8; 32],

    /// The x25519 encryption public key derived from this seed.
    pub x25519_pub_key: [u8; 32],
}

/// The Type and Tag of this lair entry.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum LairEntryListItem {
    /// This entry is type 'Seed' (see LairEntryInner).
    Seed(String),
    /// This entry is type 'DeepLockedSeed' (see LairEntryInner).
    DeepLockedSeed(String),
    /// This entry is type 'TlsCert' (see LairEntryInner).
    TlsCert(String),
}

/// The raw lair entry inner types that can be stored.
pub enum LairEntryInner {
    /// This seed can be
    /// - derived
    /// - used for ed25519 signatures
    /// - used for x25519 encryption
    Seed {
        /// user-supplied tag for this seed
        tag: String,
        /// the seed itself
        seed: sodoken::BufReadSized<32>,
    },
    /// As 'Seed' but requires an additional access-time passphrase to use
    DeepLockedSeed {
        /// user-supplied tag for this seed
        tag: String,
        /// salt for argon2id encrypted seed
        salt: [u8; 16],
        /// argon2id ops limit used when encrypting this seed
        ops_limit: u32,
        /// argon2id mem limit used when encrypting this seed
        mem_limit: u32,
        /// the secretstream header for this seed encryption
        seed_header: [u8; 24],
        /// the secretstream cipher seed content bytes
        seed_cipher: [u8; 49],
    },
    /// This tls cert and private key can be used to establish tls cryptography
    TlsCert {
        /// user-supplied tag for this tls certificate
        tag: String,
        /// random sni used in the generation of this tls certificate
        sni: String,
        /// the private key bytes for the keypair of this certificate
        priv_key_der: sodoken::BufRead,
        /// the der-encoded certificate bytes
        cert_der: Box<[u8]>,
    },
}

/// The LairEntry enum.
pub type LairEntry = Arc<LairEntryInner>;

/// Lair store concrete struct
pub struct LairStore(Arc<dyn AsLairStore>);

impl LairStore {
    /// Write a new entry to the lair store.
    pub fn write_entry(
        &self,
        entry: LairEntry,
    ) -> impl Future<Output = LairResult<()>> + 'static + Send {
        AsLairStore::write_entry(&*self.0, entry)
    }

    /// List the entries tracked by the lair store.
    pub fn list_entries(
        &self,
    ) -> impl Future<Output = LairResult<Vec<LairEntryListItem>>> + 'static + Send
    {
        AsLairStore::list_entries(&*self.0)
    }

    /// Get an entry from the lair store by tag.
    pub fn get_entry_by_tag(
        &self,
        tag: &str,
    ) -> impl Future<Output = LairResult<LairEntry>> + 'static + Send {
        AsLairStore::get_entry_by_tag(&*self.0, tag)
    }
}

/// Lair store factory concrete struct
pub struct LairStoreFactory(Arc<dyn AsLairStoreFactory>);

impl LairStoreFactory {
    /// Open a store connection with given config / passphrase.
    pub fn connect_to_store(
        &self,
        config: LairConfig,
        passphrase: sodoken::BufRead,
    ) -> impl Future<Output = LairResult<LairStore>> + 'static + Send {
        AsLairStoreFactory::connect_to_store(&*self.0, config, passphrase)
    }
}
