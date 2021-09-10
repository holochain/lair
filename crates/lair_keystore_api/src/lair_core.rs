//! Lair core types

use crate::LairResult2 as LairResult;
use futures::future::BoxFuture;
use std::sync::Arc;

/// Helper traits for core types - you probably don't need these unless
/// you are implementing new lair core instance logic.
pub mod traits {
    use super::*;

    /// Defines a lair storage mechanism.
    pub trait AsLairStore: 'static + Send + Sync {
        /// Write a new entry to the lair store.
        fn write_entry(
            &self,
            entry: LairEntry,
        ) -> BoxFuture<'static, LairResult<()>>;

        /// List the entries tracked by the lair store.
        /// This operation is a bit expensive, causing a lot of data cloning.
        fn list_entries(
            &self,
        ) -> BoxFuture<'static, LairResult<Vec<LairEntryListItem>>>;

        /// Get an entry from the lair store by ref_blob.
        fn get_entry_by_ref_blob(
            &self,
            ref_blob: [u8; 32],
        ) -> BoxFuture<'static, LairResult<LairEntry>>;

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
}
use traits::*;

/// Lair store concrete struct
pub struct LairStore(Arc<dyn AsLairStore>);

/// Lair Configuration Inner Struct
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct LairConfigInner {
}

/// Lair Configuration Type
pub type LairConfig = Arc<LairConfigInner>;

/// Line-item for listing Lair Entries.
pub enum LairEntryListItem {
    /// This entry is type 'Seed' (see LairEntryInner).
    Seed {
        /// ref_blob for Seed is the ed25519 signature pub-key
        ref_blob: [u8; 32],
        /// user-supplied tag for this seed
        tag: String,
    },
    /// This entry is type 'DeepLockedSeed' (see LairEntryInner).
    DeepLockedSeed {
        /// ref_blob for Seed is the ed25519 signature pub-key
        ref_blob: [u8; 32],
        /// user-supplied tag for this seed
        tag: String,
    },
    /// This entry is type 'TlsCert' (see LairEntryInner).
    TlsCert {
        /// ref_blob for TlsCert is a blake2b hash of the cert_der bytes
        ref_blob: [u8; 32],
        /// user-supplied tag for this tls certificate
        tag: String,
    },
}

/// The raw lair entry inner types that can be stored.
pub enum LairEntryInner {
    /// This seed can be
    /// - derived
    /// - used for ed25519 signatures
    /// - used for x25519 encryption
    Seed {
        /// ref_blob for Seed is the ed25519 signature pub-key
        ref_blob: [u8; 32],
        /// user-supplied tag for this seed
        tag: String,
        /// the seed itself
        seed: sodoken::BufReadSized<32>,
    },
    /// As 'Seed' but requires an additional access-time passphrase to use
    DeepLockedSeed {
        /// ref_blob for Seed is the ed25519 signature pub-key
        ref_blob: [u8; 32],
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
        /// ref_blob for TlsCert is a blake2b hash of the cert_der bytes
        ref_blob: [u8; 32],
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
