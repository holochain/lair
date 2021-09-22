//! lair persistance

use crate::prelude::*;
use futures::future::BoxFuture;
use std::future::Future;
use std::sync::Arc;

/// Helper traits for store types - you probably don't need these unless
/// you are implementing new lair core instance logic.
pub mod traits {
    use super::*;

    /// Defines a lair storage mechanism.
    pub trait AsLairStore: 'static + Send + Sync {
        /// Return the context key for both encryption and decryption
        /// of secret data within the store that is NOT deep_locked.
        fn get_bidi_context_key(&self) -> sodoken::BufReadSized<32>;

        /// List the entries tracked by the lair store.
        fn list_entries(
            &self,
        ) -> BoxFuture<'static, LairResult<Vec<LairEntryInfo>>>;

        /// Write a new entry to the lair store.
        fn write_entry(
            &self,
            entry: LairEntry,
        ) -> BoxFuture<'static, LairResult<()>>;

        /// Get an entry from the lair store by tag.
        fn get_entry_by_tag(
            &self,
            tag: Arc<str>,
        ) -> BoxFuture<'static, LairResult<LairEntry>>;

        /// Get an entry from the lair store by ed25519 pub key.
        fn get_entry_by_ed25519_pub_key(
            &self,
            ed25519_pub_key: Ed25519PubKey,
        ) -> BoxFuture<'static, LairResult<LairEntry>>;
    }

    /// Defines a factory that produces lair storage mechanism instances.
    pub trait AsLairStoreFactory: 'static + Send + Sync {
        /// Open a store connection with given config / passphrase.
        fn connect_to_store(
            &self,
            unlock_secret: sodoken::BufReadSized<32>,
        ) -> BoxFuture<'static, LairResult<LairStore>>;
    }
}
use traits::*;

/// Public information associated with a given seed
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SeedInfo {
    /// The ed25519 signature public key derived from this seed.
    pub ed25519_pub_key: Ed25519PubKey,

    /// The x25519 encryption public key derived from this seed.
    pub x25519_pub_key: X25519PubKey,
}

/// The 32 byte blake2b digest of the der encoded tls certificate.
pub type CertDigest = BinDataSized<32>;

/// Public information associated with a given tls certificate.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CertInfo {
    /// The random sni that was generated for this certificate.
    pub sni: Arc<str>,

    /// The 32 byte blake2b digest of the der encoded tls certificate.
    pub digest: CertDigest,

    /// The der-encoded tls certificate bytes.
    pub cert: BinData,
}

/// The Type and Tag of this lair entry.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
#[non_exhaustive]
pub enum LairEntryInfo {
    /// This entry is type 'Seed' (see LairEntryInner).
    Seed {
        /// user-supplied tag for this seed
        tag: Arc<str>,
        /// the seed info associated with this seed
        seed_info: SeedInfo,
    },

    /// This entry is type 'DeepLockedSeed' (see LairEntryInner).
    DeepLockedSeed {
        /// user-supplied tag for this seed
        tag: Arc<str>,
        /// the seed info associated with this seed
        seed_info: SeedInfo,
    },

    /// This entry is type 'TlsCert' (see LairEntryInner).
    WkaTlsCert {
        /// user-supplied tag for this seed
        tag: Arc<str>,
        /// the certificate info
        cert_info: CertInfo,
    },
}

/// The raw lair entry inner types that can be stored.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
#[non_exhaustive]
pub enum LairEntryInner {
    /// This seed can be
    /// - derived
    /// - used for ed25519 signatures
    /// - used for x25519 encryption
    /// The secretstream seed uses the base passphrase-derived secret
    /// for decryption.
    Seed {
        /// user-supplied tag for this seed
        tag: Arc<str>,
        /// the seed info associated with this seed
        seed_info: SeedInfo,
        /// the actual seed, encrypted with context key
        seed: SecretDataSized<32, 49>,
    },

    /// As 'Seed' but requires an additional access-time passphrase to use
    DeepLockedSeed {
        /// user-supplied tag for this seed
        tag: Arc<str>,
        /// the seed info associated with this seed
        seed_info: SeedInfo,
        /// salt for argon2id encrypted seed
        salt: BinDataSized<16>,
        /// argon2id ops limit used when encrypting this seed
        ops_limit: u32,
        /// argon2id mem limit used when encrypting this seed
        mem_limit: u32,
        /// the actual seed, encrypted with deep passphrase
        seed: SecretDataSized<32, 49>,
    },

    /// This tls cert and private key can be used to establish tls cryptography
    /// The secretstream priv_key uses the base passphrase-derived secret
    /// for decryption.
    WkaTlsCert {
        /// user-supplied tag for this tls certificate
        tag: Arc<str>,
        /// the certificate info
        cert_info: CertInfo,
        /// the certificate private key, encrypted with context key
        priv_key: SecretData,
    },
}

impl LairEntryInner {
    /// encode this LairEntry as bytes
    pub fn encode(&self) -> LairResult<Box<[u8]>> {
        use serde::Serialize;
        let mut se = rmp_serde::encode::Serializer::new(Vec::new())
            .with_struct_map()
            .with_string_variants();
        self.serialize(&mut se).map_err(one_err::OneErr::new)?;
        Ok(se.into_inner().into_boxed_slice())
    }

    /// decode a LairEntry from bytes
    pub fn decode(bytes: &[u8]) -> LairResult<LairEntryInner> {
        let item: LairEntryInner =
            rmp_serde::from_read(bytes).map_err(one_err::OneErr::new)?;
        Ok(item)
    }

    /// get the tag associated with this entry
    pub fn tag(&self) -> Arc<str> {
        match self {
            Self::Seed { tag, .. } => tag.clone(),
            Self::DeepLockedSeed { tag, .. } => tag.clone(),
            Self::WkaTlsCert { tag, .. } => tag.clone(),
        }
    }
}

/// The LairEntry enum.
pub type LairEntry = Arc<LairEntryInner>;

/// Lair store concrete struct
#[derive(Clone)]
pub struct LairStore(pub Arc<dyn AsLairStore>);

impl LairStore {
    /// Return the context key for both encryption and decryption
    /// of secret data within the store that is NOT deep_locked.
    pub fn get_bidi_context_key(&self) -> sodoken::BufReadSized<32> {
        AsLairStore::get_bidi_context_key(&*self.0)
    }

    /// Generate a new cryptographically secure random seed,
    /// and associate it with the given tag, returning the
    /// seed_info derived from the generated seed.
    pub fn new_seed(
        &self,
        tag: Arc<str>,
    ) -> impl Future<Output = LairResult<SeedInfo>> + 'static + Send {
        let inner = self.0.clone();
        async move {
            let seed = sodoken::BufWriteSized::new_mem_locked()?;
            sodoken::random::bytes_buf(seed.clone()).await?;

            let ed_pk = sodoken::BufWriteSized::new_no_lock();
            let ed_sk = sodoken::BufWriteSized::new_mem_locked()?;
            sodoken::sign::seed_keypair(ed_pk.clone(), ed_sk, seed.clone())
                .await?;

            let x_pk = sodoken::BufWriteSized::new_no_lock();
            let x_sk = sodoken::BufWriteSized::new_mem_locked()?;
            sodoken::sealed_box::curve25519xchacha20poly1305::seed_keypair(
                x_pk.clone(),
                x_sk,
                seed.clone(),
            )
            .await?;

            let key = inner.get_bidi_context_key();
            let seed =
                SecretDataSized::encrypt(key, seed.to_read_sized()).await?;

            let seed_info = SeedInfo {
                ed25519_pub_key: ed_pk.try_unwrap_sized().unwrap().into(),
                x25519_pub_key: x_pk.try_unwrap_sized().unwrap().into(),
            };

            let entry = LairEntryInner::Seed {
                tag,
                seed_info: seed_info.clone(),
                seed,
            };

            inner.write_entry(Arc::new(entry)).await?;

            Ok(seed_info)
        }
    }

    /// Generate a new cryptographically secure random seed,
    /// and associate it with the given tag, returning the
    /// seed_info derived from the generated seed.
    /// This seed is deep_locked, meaning it needs an additional
    /// runtime passphrase to be decrypted / used.
    pub fn new_deep_locked_seed(
        &self,
        tag: Arc<str>,
        ops_limit: u32,
        mem_limit: u32,
        deep_lock_passphrase: sodoken::BufRead,
    ) -> impl Future<Output = LairResult<SeedInfo>> + 'static + Send {
        let inner = self.0.clone();
        async move {
            let seed = sodoken::BufWriteSized::new_mem_locked()?;
            sodoken::random::bytes_buf(seed.clone()).await?;

            let ed_pk = sodoken::BufWriteSized::new_no_lock();
            let ed_sk = sodoken::BufWriteSized::new_mem_locked()?;
            sodoken::sign::seed_keypair(ed_pk.clone(), ed_sk, seed.clone())
                .await?;

            let x_pk = sodoken::BufWriteSized::new_no_lock();
            let x_sk = sodoken::BufWriteSized::new_mem_locked()?;
            sodoken::sealed_box::curve25519xchacha20poly1305::seed_keypair(
                x_pk.clone(),
                x_sk,
                seed.clone(),
            )
            .await?;

            let salt = <sodoken::BufWriteSized<16>>::new_no_lock();
            sodoken::random::bytes_buf(salt.clone()).await?;

            let key = <sodoken::BufWriteSized<32>>::new_mem_locked()?;
            sodoken::hash::argon2id::hash(
                key.clone(),
                deep_lock_passphrase,
                salt.clone(),
                ops_limit,
                mem_limit,
            )
            .await?;

            let seed = SecretDataSized::encrypt(
                key.to_read_sized(),
                seed.to_read_sized(),
            )
            .await?;

            let seed_info = SeedInfo {
                ed25519_pub_key: ed_pk.try_unwrap_sized().unwrap().into(),
                x25519_pub_key: x_pk.try_unwrap_sized().unwrap().into(),
            };

            let entry = LairEntryInner::DeepLockedSeed {
                tag,
                seed_info: seed_info.clone(),
                salt: salt.try_unwrap_sized().unwrap().into(),
                ops_limit,
                mem_limit,
                seed,
            };

            inner.write_entry(Arc::new(entry)).await?;

            Ok(seed_info)
        }
    }

    /// Generate a new cryptographically secure random wka tls cert,
    /// and associate it with the given tag, returning the
    /// cert_info derived from the generated cert.
    pub fn new_wka_tls_cert(
        &self,
        tag: Arc<str>,
    ) -> impl Future<Output = LairResult<CertInfo>> + 'static + Send {
        let inner = self.0.clone();
        async move {
            use crate::internal::tls::*;

            let TlsCertGenResult {
                sni,
                priv_key,
                cert,
                digest,
            } = tls_cert_self_signed_new().await?;

            let key = inner.get_bidi_context_key();
            let priv_key = SecretData::encrypt(key, priv_key).await?;

            let cert_info = CertInfo {
                sni,
                digest: digest.into(),
                cert: cert.into(),
            };

            let entry = LairEntryInner::WkaTlsCert {
                tag,
                cert_info: cert_info.clone(),
                priv_key,
            };

            inner.write_entry(Arc::new(entry)).await?;

            Ok(cert_info)
        }
    }

    /// List the entries tracked by the lair store.
    pub fn list_entries(
        &self,
    ) -> impl Future<Output = LairResult<Vec<LairEntryInfo>>> + 'static + Send
    {
        AsLairStore::list_entries(&*self.0)
    }

    /// Get an entry from the lair store by tag.
    pub fn get_entry_by_tag(
        &self,
        tag: Arc<str>,
    ) -> impl Future<Output = LairResult<LairEntry>> + 'static + Send {
        AsLairStore::get_entry_by_tag(&*self.0, tag)
    }

    /// Get an entry from the lair store by ed25519 pub key.
    pub fn get_entry_by_ed25519_pub_key(
        &self,
        ed25519_pub_key: Ed25519PubKey,
    ) -> impl Future<Output = LairResult<LairEntry>> + 'static + Send {
        AsLairStore::get_entry_by_ed25519_pub_key(&*self.0, ed25519_pub_key)
    }
}

/// Lair store factory concrete struct
#[derive(Clone)]
pub struct LairStoreFactory(pub Arc<dyn AsLairStoreFactory>);

impl LairStoreFactory {
    /// Connect to an existing store with the given unlock_secret.
    pub fn connect_to_store(
        &self,
        unlock_secret: sodoken::BufReadSized<32>,
    ) -> impl Future<Output = LairResult<LairStore>> + 'static + Send {
        AsLairStoreFactory::connect_to_store(&*self.0, unlock_secret)
    }
}
