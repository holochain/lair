//! Items related to securely persisting keystore secrets (e.g. to disk).

use crate::*;
use futures::future::BoxFuture;
use std::future::Future;
use std::sync::Arc;

fn is_false(b: impl std::borrow::Borrow<bool>) -> bool {
    !b.borrow()
}

/// Helper traits for store types - you probably don't need these unless
/// you are implementing new lair core instance logic.
pub mod traits {
    use super::*;

    /// Defines a lair storage mechanism.
    pub trait AsLairStore: 'static + Send + Sync {
        /// Return the context key for both encryption and decryption
        /// of secret data within the store that is NOT deep_locked.
        fn get_bidi_ctx_key(&self) -> sodoken::BufReadSized<32>;

        /// List the entries tracked by the lair store.
        fn list_entries(
            &self,
        ) -> BoxFuture<'static, LairResult<Vec<LairEntryInfo>>>;

        /// Write a new entry to the lair store.
        /// Should error if the tag already exists.
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

        /// Get an entry from the lair store by x25519 pub key.
        fn get_entry_by_x25519_pub_key(
            &self,
            x25519_pub_key: X25519PubKey,
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

/// Public information associated with a given seed.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SeedInfo {
    /// The ed25519 signature public key derived from this seed.
    pub ed25519_pub_key: Ed25519PubKey,

    /// The x25519 encryption public key derived from this seed.
    pub x25519_pub_key: X25519PubKey,

    /// Flag indicating if this seed is allowed to be exported.
    #[serde(skip_serializing_if = "is_false", default)]
    pub exportable: bool,
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

/// The type and tag of this lair entry.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
#[non_exhaustive]
pub enum LairEntryInfo {
    /// This entry is type 'Seed' (see LairEntryInner).
    Seed {
        /// User-supplied tag for this seed.
        tag: Arc<str>,

        /// The seed info associated with this seed.
        seed_info: SeedInfo,
    },

    /// This entry is type 'DeepLockedSeed' (see LairEntryInner).
    DeepLockedSeed {
        /// User-supplied tag for this seed.
        tag: Arc<str>,

        /// The seed info associated with this seed
        seed_info: SeedInfo,
    },

    /// This entry is type 'TlsCert' (see LairEntryInner).
    WkaTlsCert {
        /// User-supplied tag for this seed.
        tag: Arc<str>,

        /// The certificate info.
        cert_info: CertInfo,
    },
}

/// Data type for secret seed
pub type Seed = SecretDataSized<32, 49>;

/// The raw lair entry inner types that can be stored. This is generally
/// wrapped by an `Arc`. See the typedef [LairEntry].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
#[non_exhaustive]
pub enum LairEntryInner {
    /// This seed can be
    /// - derived
    /// - used for ed25519 signatures
    /// - used for x25519 encryption
    ///
    /// The secretstream seed uses the base passphrase-derived secret
    /// for decryption.
    Seed {
        /// User-supplied tag for this seed.
        tag: Arc<str>,

        /// The seed info associated with this seed.
        seed_info: SeedInfo,

        /// The actual seed, encrypted with context key.
        seed: Seed,
    },

    /// As 'Seed' but requires an additional access-time passphrase.
    DeepLockedSeed {
        /// User-supplied tag for this seed.
        tag: Arc<str>,

        /// The seed info associated with this seed.
        seed_info: SeedInfo,

        /// Salt for argon2id encrypted seed.
        salt: BinDataSized<16>,

        /// Argon2id ops limit used when encrypting this seed.
        ops_limit: u32,

        /// Argon2id mem limit used when encrypting this seed.
        mem_limit: u32,

        /// The actual seed, encrypted with deep passphrase.
        seed: Seed,
    },

    /// This tls cert and private key can be used to establish tls cryptography
    /// The secretstream priv_key uses the base passphrase-derived secret
    /// for decryption.
    WkaTlsCert {
        /// User-supplied tag for this tls certificate.
        tag: Arc<str>,

        /// The certificate info.
        cert_info: CertInfo,

        /// The certificate private key, encrypted with context key.
        priv_key: SecretData,
    },
}

impl LairEntryInner {
    /// Encode this LairEntry as bytes.
    pub fn encode(&self) -> LairResult<Box<[u8]>> {
        use serde::Serialize;
        let mut se =
            rmp_serde::encode::Serializer::new(Vec::new()).with_struct_map();
        self.serialize(&mut se).map_err(one_err::OneErr::new)?;
        Ok(se.into_inner().into_boxed_slice())
    }

    /// Decode a LairEntry from bytes.
    pub fn decode(bytes: &[u8]) -> LairResult<LairEntryInner> {
        let item: LairEntryInner =
            rmp_serde::from_read(bytes).map_err(one_err::OneErr::new)?;
        Ok(item)
    }

    /// Get the tag associated with this entry.
    pub fn tag(&self) -> Arc<str> {
        match self {
            Self::Seed { tag, .. } => tag.clone(),
            Self::DeepLockedSeed { tag, .. } => tag.clone(),
            Self::WkaTlsCert { tag, .. } => tag.clone(),
        }
    }
}

/// An actual LairEntry. Unlike [LairEntryInfo], this type contains the
/// actual secrets associated with the keystore entry.
pub type LairEntry = Arc<LairEntryInner>;

/// A handle to a running lair keystore backend persistance instance.
/// Allows storing, listing, and retrieving keystore secrets.
#[derive(Clone)]
pub struct LairStore(pub Arc<dyn AsLairStore>);

impl LairStore {
    /// Return the context key for both encryption and decryption
    /// of secret data within the store that is NOT deep_locked.
    pub fn get_bidi_ctx_key(&self) -> sodoken::BufReadSized<32> {
        AsLairStore::get_bidi_ctx_key(&*self.0)
    }

    /// Inject a pre-generated seed,
    /// and associate it with the given tag, returning the
    /// seed_info derived from the generated seed.
    pub fn insert_seed(
        &self,
        seed: sodoken::BufReadSized<32>,
        tag: Arc<str>,
        exportable: bool,
    ) -> impl Future<Output = LairResult<SeedInfo>> + 'static + Send {
        let inner = self.0.clone();
        async move {
            // derive the ed25519 signature keypair from this seed
            let ed_pk = sodoken::BufWriteSized::new_no_lock();
            let ed_sk = sodoken::BufWriteSized::new_mem_locked()?;
            sodoken::sign::seed_keypair(ed_pk.clone(), ed_sk, seed.clone())
                .await?;

            // derive the x25519 encryption keypair from this seed
            let x_pk = sodoken::BufWriteSized::new_no_lock();
            let x_sk = sodoken::BufWriteSized::new_mem_locked()?;
            sodoken::crypto_box::curve25519xchacha20poly1305::seed_keypair(
                x_pk.clone(),
                x_sk,
                seed.clone(),
            )
            .await?;

            // encrypt the seed with our bidi context key
            let key = inner.get_bidi_ctx_key();
            let seed = SecretDataSized::encrypt(key, seed).await?;

            // populate our seed info with the derived public keys
            let seed_info = SeedInfo {
                ed25519_pub_key: ed_pk.try_unwrap_sized().unwrap().into(),
                x25519_pub_key: x_pk.try_unwrap_sized().unwrap().into(),
                exportable,
            };

            // construct the entry for the keystore
            let entry = LairEntryInner::Seed {
                tag,
                seed_info: seed_info.clone(),
                seed,
            };

            // write the entry to the store
            inner.write_entry(Arc::new(entry)).await?;

            // return the seed info
            Ok(seed_info)
        }
    }

    /// Generate a new cryptographically secure random seed,
    /// and associate it with the given tag, returning the
    /// seed_info derived from the generated seed.
    pub fn new_seed(
        &self,
        tag: Arc<str>,
        exportable: bool,
    ) -> impl Future<Output = LairResult<SeedInfo>> + 'static + Send {
        let this = self.clone();
        async move {
            // generate a new random seed
            let seed = sodoken::BufWriteSized::new_mem_locked()?;
            sodoken::random::bytes_buf(seed.clone()).await?;

            this.insert_seed(seed.to_read_sized(), tag, exportable)
                .await
        }
    }

    /// Inject a pre-generated seed,
    /// and associate it with the given tag, returning the
    /// seed_info derived from the generated seed.
    /// This seed is deep_locked, meaning it needs an additional
    /// runtime passphrase to be decrypted / used.
    pub fn insert_deep_locked_seed(
        &self,
        seed: sodoken::BufReadSized<32>,
        tag: Arc<str>,
        ops_limit: u32,
        mem_limit: u32,
        deep_lock_passphrase: sodoken::BufReadSized<64>,
        exportable: bool,
    ) -> impl Future<Output = LairResult<SeedInfo>> + 'static + Send {
        let inner = self.0.clone();
        async move {
            // derive the ed25519 signature keypair from this seed
            let ed_pk = sodoken::BufWriteSized::new_no_lock();
            let ed_sk = sodoken::BufWriteSized::new_mem_locked()?;
            sodoken::sign::seed_keypair(ed_pk.clone(), ed_sk, seed.clone())
                .await?;

            // derive the x25519 encryption keypair from this seed
            let x_pk = sodoken::BufWriteSized::new_no_lock();
            let x_sk = sodoken::BufWriteSized::new_mem_locked()?;
            sodoken::crypto_box::curve25519xchacha20poly1305::seed_keypair(
                x_pk.clone(),
                x_sk,
                seed.clone(),
            )
            .await?;

            // generate the salt for the pwhash deep locking
            let salt = <sodoken::BufWriteSized<16>>::new_no_lock();
            sodoken::random::bytes_buf(salt.clone()).await?;

            // generate the deep lock key from the passphrase
            let key = <sodoken::BufWriteSized<32>>::new_mem_locked()?;
            sodoken::hash::argon2id::hash(
                key.clone(),
                deep_lock_passphrase,
                salt.clone(),
                ops_limit,
                mem_limit,
            )
            .await?;

            // encrypt the seed with the deep lock key
            let seed =
                SecretDataSized::encrypt(key.to_read_sized(), seed).await?;

            // populate our seed info with the derived public keys
            let seed_info = SeedInfo {
                ed25519_pub_key: ed_pk.try_unwrap_sized().unwrap().into(),
                x25519_pub_key: x_pk.try_unwrap_sized().unwrap().into(),
                exportable,
            };

            // construct the entry for the keystore
            let entry = LairEntryInner::DeepLockedSeed {
                tag,
                seed_info: seed_info.clone(),
                salt: salt.try_unwrap_sized().unwrap().into(),
                ops_limit,
                mem_limit,
                seed,
            };

            // write the entry to the store
            inner.write_entry(Arc::new(entry)).await?;

            // return the seed info
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
        deep_lock_passphrase: sodoken::BufReadSized<64>,
        exportable: bool,
    ) -> impl Future<Output = LairResult<SeedInfo>> + 'static + Send {
        let this = self.clone();
        async move {
            // generate a new random seed
            let seed = sodoken::BufWriteSized::new_mem_locked()?;
            sodoken::random::bytes_buf(seed.clone()).await?;

            this.insert_deep_locked_seed(
                seed.to_read_sized(),
                tag,
                ops_limit,
                mem_limit,
                deep_lock_passphrase,
                exportable,
            )
            .await
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

            // generate the random well-known-authority signed certificate.
            let TlsCertGenResult {
                sni,
                priv_key,
                cert,
                digest,
            } = tls_cert_self_signed_new().await?;

            // encrypt the private key with our context secret
            let key = inner.get_bidi_ctx_key();
            let priv_key = SecretData::encrypt(key, priv_key).await?;

            // populate the certificate info
            let cert_info = CertInfo {
                sni,
                digest: digest.into(),
                cert: cert.into(),
            };

            // construct the entry for the keystore
            let entry = LairEntryInner::WkaTlsCert {
                tag,
                cert_info: cert_info.clone(),
                priv_key,
            };

            // write the entry to the store
            inner.write_entry(Arc::new(entry)).await?;

            // return the cert info
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

    /// Get an entry from the lair store by x25519 pub key.
    pub fn get_entry_by_x25519_pub_key(
        &self,
        x25519_pub_key: X25519PubKey,
    ) -> impl Future<Output = LairResult<LairEntry>> + 'static + Send {
        AsLairStore::get_entry_by_x25519_pub_key(&*self.0, x25519_pub_key)
    }
}

/// A factory abstraction allowing connecting to a lair keystore persistance
/// backend with an unlock secret (generally derived from a user passphrase).
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
