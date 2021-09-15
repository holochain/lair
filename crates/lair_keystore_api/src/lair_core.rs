#![allow(clippy::new_without_default)]
#![allow(clippy::boxed_local)]
//! Lair core types

use crate::LairResult2 as LairResult;
use futures::future::BoxFuture;
use sodoken::secretstream::xchacha20poly1305 as sss;
use std::future::Future;
use std::sync::Arc;

/// Helper traits for core types - you probably don't need these unless
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
    }

    /// Defines a factory that produces lair storage mechanism instances.
    pub trait AsLairStoreFactory: 'static + Send + Sync {
        /// Open a store connection with given config / passphrase.
        fn connect_to_store(
            &self,
            unlock_secret: sodoken::BufReadSized<32>,
        ) -> BoxFuture<'static, LairResult<LairStore>>;
    }

    /// Defines a lair serialization object.
    pub trait AsLairCodec:
        'static
        + std::fmt::Debug
        + serde::Serialize
        + for<'de> serde::Deserialize<'de>
        + std::convert::TryFrom<LairApiEnum>
    {
        /// Convert this individual lair serialization object
        /// into a combined API enum instance variant.
        fn into_api_enum(self) -> LairApiEnum;
    }

    /// A "Request" type lair codec instance.
    pub trait AsLairRequest: AsLairCodec {
        /// The "Response" type associated with this request type.
        type Response: AsLairCodec;
    }

    /// A "Response" type lair codec instance.
    pub trait AsLairResponse: AsLairCodec {
        /// The "Request" type associated with this response type.
        type Request: AsLairCodec;
    }

    /// Defines the lair client API.
    pub trait AsLairClient: 'static + Send + Sync {
        /// Return the encryption context key for passphrases, etc.
        fn get_encryption_context_key(&self) -> sodoken::BufReadSized<32>;

        /// Return the decryption context key for passphrases, etc.
        fn get_decryption_context_key(&self) -> sodoken::BufReadSized<32>;

        /// Handle a lair client request
        fn request(
            &self,
            request: LairApiEnum,
        ) -> BoxFuture<'static, LairResult<LairApiEnum>>;
    }
}
use traits::*;

/// Wrapper newtype for serde encoding / decoding binary data
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BinData(pub Arc<[u8]>);

impl std::fmt::Debug for BinData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("BinData").field(&self.len()).finish()
    }
}

impl BinData {
    /// Get a clone of our inner Arc<[u8]>
    pub fn cloned_inner(&self) -> Arc<[u8]> {
        self.0.clone()
    }
}

impl From<Box<[u8]>> for BinData {
    fn from(b: Box<[u8]>) -> Self {
        Self(b.into())
    }
}

impl std::ops::Deref for BinData {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

impl serde::Serialize for BinData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&*self.0)
    }
}

impl<'de> serde::Deserialize<'de> for BinData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let tmp: Box<[u8]> = serde::Deserialize::deserialize(deserializer)?;
        Ok(Self(tmp.into()))
    }
}

/// Wrapper newtype for serde encoding / decoding sized binary data
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BinDataSized<const N: usize>(pub Arc<[u8; N]>);

impl<const N: usize> std::fmt::Debug for BinDataSized<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BinDataSized<{}>", N)
    }
}

impl<const N: usize> BinDataSized<N> {
    /// Get a clone of our inner Arc<[u8; N]>
    pub fn cloned_inner(&self) -> Arc<[u8; N]> {
        self.0.clone()
    }
}

impl<const N: usize> From<[u8; N]> for BinDataSized<N> {
    fn from(b: [u8; N]) -> Self {
        Self(Arc::new(b))
    }
}

impl<const N: usize> std::ops::Deref for BinDataSized<N> {
    type Target = [u8; N];

    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

impl<const N: usize> serde::Serialize for BinDataSized<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&*self.0)
    }
}

impl<'de, const N: usize> serde::Deserialize<'de> for BinDataSized<N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let tmp: &'de [u8] = serde::Deserialize::deserialize(deserializer)?;
        if tmp.len() != N {
            return Err(serde::de::Error::custom("invalid buffer length"));
        }
        let mut out = [0; N];
        out.copy_from_slice(tmp);
        Ok(Self(Arc::new(out)))
    }
}

impl BinDataSized<32> {
    /// Treat this bin data as an ed25519 public key,
    /// and use it to verify a signature over a given message.
    pub async fn verify_detached<Sig, M>(
        &self,
        signature: Sig,
        message: M,
    ) -> LairResult<bool>
    where
        Sig: Into<sodoken::BufReadSized<64>> + 'static + Send,
        M: Into<sodoken::BufRead> + 'static + Send,
    {
        let pub_key = sodoken::BufReadSized::from(self.0.clone());
        sodoken::sign::verify_detached(signature, message, pub_key).await
    }
}

/// Secret data. Encrypted with sodium secretstream.
/// The key used to encrypt / decrypt is context dependent.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SecretData(
    // the secretstream header
    pub BinDataSized<24>,
    // the secretstream cipher data
    pub BinData,
);

impl SecretData {
    /// encrypt some data as a 'SecretData' object with given context key.
    pub async fn encrypt(
        key: sodoken::BufReadSized<32>,
        data: sodoken::BufRead,
    ) -> LairResult<Self> {
        let header =
            <sodoken::BufWriteSized<{ sss::HEADERBYTES }>>::new_no_lock();
        let cipher = sodoken::BufExtend::new_no_lock(data.len() + sss::ABYTES);
        let mut enc = sss::SecretStreamEncrypt::new(key, header.clone())?;
        enc.push_final(data, <Option<sodoken::BufRead>>::None, cipher.clone())
            .await?;

        let header = header.try_unwrap_sized().unwrap();

        let cipher_r = cipher.to_read();
        drop(cipher);
        let cipher_r = cipher_r.try_unwrap().unwrap();

        Ok(Self(header.into(), cipher_r.into()))
    }

    /// decrypt some data as a 'SecretData' object with given context key.
    pub async fn decrypt(
        &self,
        key: sodoken::BufReadSized<32>,
    ) -> LairResult<sodoken::BufRead> {
        let header = sodoken::BufReadSized::from(self.0.cloned_inner());
        let cipher = sodoken::BufRead::from(self.1.cloned_inner());
        let mut dec = sss::SecretStreamDecrypt::new(key, header)?;
        let out =
            sodoken::BufWrite::new_mem_locked(cipher.len() - sss::ABYTES)?;
        dec.pull(cipher, <Option<sodoken::BufRead>>::None, out.clone())
            .await?;
        Ok(out.to_read())
    }
}

/// Secret data sized. Encrypted with sodium secretstream.
/// The key used to encrypt / decrypt is context dependent.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SecretDataSized<const M: usize, const C: usize>(
    // the secretstream header
    pub BinDataSized<24>,
    // the secretstream cipher data
    pub BinDataSized<C>,
);

impl<const M: usize, const C: usize> SecretDataSized<M, C> {
    /// encrypt some data as a 'SecretDataSized' object with given context key.
    pub async fn encrypt(
        key: sodoken::BufReadSized<32>,
        data: sodoken::BufReadSized<M>,
    ) -> LairResult<Self> {
        let header =
            <sodoken::BufWriteSized<{ sss::HEADERBYTES }>>::new_no_lock();
        let cipher = sodoken::BufWriteSized::new_no_lock();
        let mut enc = sss::SecretStreamEncrypt::new(key, header.clone())?;
        enc.push_final(data, <Option<sodoken::BufRead>>::None, cipher.clone())
            .await?;

        let header = header.try_unwrap_sized().unwrap();
        let cipher = cipher.try_unwrap_sized().unwrap();

        Ok(Self(header.into(), cipher.into()))
    }

    /// decrypt some data as a 'SecretDataSized' object with given context key.
    pub async fn decrypt(
        &self,
        key: sodoken::BufReadSized<32>,
    ) -> LairResult<sodoken::BufReadSized<M>> {
        let header = sodoken::BufReadSized::from(self.0.cloned_inner());
        let cipher = sodoken::BufReadSized::from(self.1.cloned_inner());
        let mut dec = sss::SecretStreamDecrypt::new(key, header)?;
        let out = sodoken::BufWriteSized::new_mem_locked()?;
        dec.pull(cipher, <Option<sodoken::BufRead>>::None, out.clone())
            .await?;
        Ok(out.to_read_sized())
    }
}

/// ed25519 signature public key derived from this seed.
pub type Ed25519PubKey = BinDataSized<32>;

/// ed25519 signature bytes.
pub type Ed25519Signature = BinDataSized<64>;

/// x25519 encryption public key derived from this seed.
pub type X25519PubKey = BinDataSized<32>;

/// Public information associated with a given seed
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct SeedInfo {
    /// The ed25519 signature public key derived from this seed.
    pub ed25519_pub_key: Ed25519PubKey,

    /// The x25519 encryption public key derived from this seed.
    pub x25519_pub_key: X25519PubKey,
}

/// The 32 byte blake2b digest of the der encoded tls certificate.
pub type CertDigest = BinDataSized<32>;

/// Public information associated with a given tls certificate.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
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
    TlsCert {
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
    TlsCert {
        /// user-supplied tag for this tls certificate
        tag: Arc<str>,
        /// the certificate info
        cert_info: CertInfo,
        /// the certificate private key, encrypted with context key
        priv_key: SecretData,
    },
}

/// The LairEntry enum.
pub type LairEntry = Arc<LairEntryInner>;

fn new_msg_id() -> Arc<str> {
    nanoid::nanoid!().into()
}

/// An error response from the remote instance.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LairApiResError {
    /// msg id to relate request / response.
    pub msg_id: Arc<str>,

    /// The error returned.
    pub error: one_err::OneErr,
}

impl std::convert::TryFrom<LairApiEnum> for LairApiResError {
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::ResError(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {:?}", e).into())
        }
    }
}

impl AsLairCodec for LairApiResError {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::ResError(self)
    }
}

/// Initiate communication with the target lair instance.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LairApiReqHello {
    /// msg id to relate request / response.
    pub msg_id: Arc<str>,

    /// random data for server identity verification.
    pub nonce: BinData,
}

impl LairApiReqHello {
    /// Make a new server info request
    pub fn new(nonce: BinData) -> Self {
        Self {
            msg_id: new_msg_id(),
            nonce,
        }
    }
}

impl std::convert::TryFrom<LairApiEnum> for LairApiReqHello {
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::ReqHello(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {:?}", e).into())
        }
    }
}

impl AsLairCodec for LairApiReqHello {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::ReqHello(self)
    }
}

/// The hello response from the target lair instance.
/// This data allows us to verify we are speaking to our expected target.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LairApiResHello {
    /// msg id to relate request / response.
    pub msg_id: Arc<str>,

    /// The server name / identifier.
    pub name: Arc<str>,

    /// The server semantic version.
    pub version: Arc<str>,

    /// The public key this hello sig was signed with.
    pub server_pub_key: BinDataSized<32>,

    /// The hello signature of the random bytes sent with the hello request.
    pub hello_sig: BinDataSized<64>,
}

impl std::convert::TryFrom<LairApiEnum> for LairApiResHello {
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::ResHello(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {:?}", e).into())
        }
    }
}

impl AsLairCodec for LairApiResHello {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::ResHello(self)
    }
}

impl AsLairRequest for LairApiReqHello {
    type Response = LairApiResHello;
}

impl AsLairResponse for LairApiResHello {
    type Request = LairApiReqHello;
}

/// Unlock the keystore -- this verifies the client to the keystore.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LairApiReqUnlock {
    /// msg id to relate request / response.
    pub msg_id: Arc<str>,

    /// passphrase to unlock the keystore.
    pub passphrase: SecretData,
}

impl LairApiReqUnlock {
    /// Make a new server info request
    pub fn new(passphrase: SecretData) -> Self {
        Self {
            msg_id: new_msg_id(),
            passphrase,
        }
    }
}

impl std::convert::TryFrom<LairApiEnum> for LairApiReqUnlock {
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::ReqUnlock(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {:?}", e).into())
        }
    }
}

impl AsLairCodec for LairApiReqUnlock {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::ReqUnlock(self)
    }
}

/// Sucess / Failure of the unlock request.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LairApiResUnlock {
    /// msg id to relate request / response.
    pub msg_id: Arc<str>,
}

impl std::convert::TryFrom<LairApiEnum> for LairApiResUnlock {
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::ResUnlock(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {:?}", e).into())
        }
    }
}

impl AsLairCodec for LairApiResUnlock {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::ResUnlock(self)
    }
}

impl AsLairRequest for LairApiReqUnlock {
    type Response = LairApiResUnlock;
}

impl AsLairResponse for LairApiResUnlock {
    type Request = LairApiReqUnlock;
}

/// Request a list of entries from lair.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LairApiReqListEntries {
    /// msg id to relate request / response.
    pub msg_id: Arc<str>,
}

impl LairApiReqListEntries {
    /// Make a new list entries request
    pub fn new() -> Self {
        Self {
            msg_id: new_msg_id(),
        }
    }
}

impl std::convert::TryFrom<LairApiEnum> for LairApiReqListEntries {
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::ReqListEntries(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {:?}", e).into())
        }
    }
}

impl AsLairCodec for LairApiReqListEntries {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::ReqListEntries(self)
    }
}

/// Respond to a list entries request.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LairApiResListEntries {
    /// msg id to relate request / response.
    pub msg_id: Arc<str>,
    /// list of lair entry list items.
    pub entry_list: Vec<LairEntryInfo>,
}

impl std::convert::TryFrom<LairApiEnum> for LairApiResListEntries {
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::ResListEntries(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {:?}", e).into())
        }
    }
}

impl AsLairCodec for LairApiResListEntries {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::ResListEntries(self)
    }
}

impl AsLairRequest for LairApiReqListEntries {
    type Response = LairApiResListEntries;
}

impl AsLairResponse for LairApiResListEntries {
    type Request = LairApiReqListEntries;
}

/// Instruct lair to generate a new seed from cryptographically secure
/// random data with given tag.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LairApiReqNewSeed {
    /// msg id to relate request / response.
    pub msg_id: Arc<str>,
    /// user-defined tag to associate with the new seed.
    pub tag: Arc<str>,
    /// if this new seed is to be deep_locked, the passphrase for that.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub deep_lock_passphrase: Option<SecretData>,
}

impl LairApiReqNewSeed {
    /// Make a new_seed request
    pub fn new(
        tag: Arc<str>,
        deep_lock_passphrase: Option<SecretData>,
    ) -> Self {
        Self {
            msg_id: new_msg_id(),
            tag,
            deep_lock_passphrase,
        }
    }
}

impl std::convert::TryFrom<LairApiEnum> for LairApiReqNewSeed {
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::ReqNewSeed(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {:?}", e).into())
        }
    }
}

impl AsLairCodec for LairApiReqNewSeed {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::ReqNewSeed(self)
    }
}

/// On new seed generation, lair will respond with info about
/// that seed.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct LairApiResNewSeed {
    /// msg id to relate request / response.
    pub msg_id: Arc<str>,
    /// user-defined tag associated with the generated seed.
    pub tag: Arc<str>,
    /// the seed info associated with this seed
    pub seed_info: SeedInfo,
}

impl std::convert::TryFrom<LairApiEnum> for LairApiResNewSeed {
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::ResNewSeed(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {:?}", e).into())
        }
    }
}

impl AsLairCodec for LairApiResNewSeed {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::ResNewSeed(self)
    }
}

impl AsLairRequest for LairApiReqNewSeed {
    type Response = LairApiResNewSeed;
}

impl AsLairResponse for LairApiResNewSeed {
    type Request = LairApiReqNewSeed;
}

/// Lair Api enum
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
#[non_exhaustive]
pub enum LairApiEnum {
    /// An error response from the remote instance.
    ResError(LairApiResError),

    /// Initiate communication with the target lair instance.
    ReqHello(LairApiReqHello),

    /// The hello response from the target lair instance.
    /// This data allows us to verify we are speaking to our expected target.
    ResHello(LairApiResHello),

    /// Unlock the keystore -- this verifies the client to the keystore.
    ReqUnlock(LairApiReqUnlock),

    /// Sucess / Failure of the unlock request.
    ResUnlock(LairApiResUnlock),

    /// Request a list of entries from lair.
    ReqListEntries(LairApiReqListEntries),

    /// Respond to a list entries request.
    ResListEntries(LairApiResListEntries),

    /// Instruct lair to generate a new seed from cryptographically secure
    /// random data with given tag.
    ReqNewSeed(LairApiReqNewSeed),

    /// On new seed generation, lair will respond with info about
    /// that seed.
    ResNewSeed(LairApiResNewSeed),
}

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
            sodoken::sign::keypair(ed_pk.clone(), ed_sk).await?;

            let x_pk = sodoken::BufWriteSized::new_no_lock();
            let x_sk = sodoken::BufWriteSized::new_mem_locked()?;
            sodoken::sealed_box::curve25519xchacha20poly1305::keypair(
                x_pk.clone(),
                x_sk,
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

/// Concrete lair client struct.
#[derive(Clone)]
pub struct LairClient(pub Arc<dyn AsLairClient>);

fn priv_lair_api_request<R: AsLairRequest>(
    client: &dyn AsLairClient,
    request: R,
) -> impl Future<Output = LairResult<R::Response>> + 'static + Send
where
    one_err::OneErr: std::convert::From<
        <<R as AsLairRequest>::Response as std::convert::TryFrom<
            LairApiEnum,
        >>::Error,
    >,
{
    let request = request.into_api_enum();
    let fut = AsLairClient::request(client, request);
    async move {
        let res = fut.await?;
        match res {
            LairApiEnum::ResError(err) => Err(err.error),
            res => {
                let res: R::Response = std::convert::TryFrom::try_from(res)?;
                Ok(res)
            }
        }
    }
}

impl LairClient {
    /// Return the encryption context key for passphrases, etc.
    pub fn get_encryption_context_key(&self) -> sodoken::BufReadSized<32> {
        AsLairClient::get_encryption_context_key(&*self.0)
    }

    /// Return the decryption context key for passphrases, etc.
    pub fn get_decryption_context_key(&self) -> sodoken::BufReadSized<32> {
        AsLairClient::get_decryption_context_key(&*self.0)
    }

    /// Handle a generic lair client request.
    pub fn request<R: AsLairRequest>(
        &self,
        request: R,
    ) -> impl Future<Output = LairResult<R::Response>> + 'static + Send
    where
        one_err::OneErr: std::convert::From<
            <<R as AsLairRequest>::Response as std::convert::TryFrom<
                LairApiEnum,
            >>::Error,
        >,
    {
        priv_lair_api_request(&*self.0, request)
    }

    /// Send the hello message to establish server authenticity.
    /// Check with your implementation before invoking this...
    /// it likely handles this for you in its constructor.
    pub fn hello(
        &self,
        nonce: BinData,
    ) -> impl Future<Output = LairResult<LairApiResHello>> + 'static + Send
    {
        let inner = self.0.clone();
        async move {
            let req = LairApiReqHello::new(nonce);
            let res = priv_lair_api_request(&*inner, req).await?;
            Ok(res)
        }
    }

    /// Send the unlock request to unlock / communicate with the server.
    /// (this verifies client authenticity)
    /// Check with your implementation before invoking this...
    /// it likely handles this for you in its constructor.
    pub fn unlock(
        &self,
        passphrase: sodoken::BufRead,
    ) -> impl Future<Output = LairResult<()>> + 'static + Send {
        let inner = self.0.clone();
        async move {
            let key = inner.get_encryption_context_key();
            let passphrase = SecretData::encrypt(key, passphrase).await?;
            let req = LairApiReqUnlock::new(passphrase);
            let _res = priv_lair_api_request(&*inner, req).await?;
            Ok(())
        }
    }

    /// Request a list of entries from lair.
    pub fn list_entries(
        &self,
    ) -> impl Future<Output = LairResult<Vec<LairEntryInfo>>> + 'static + Send
    {
        let r_fut =
            priv_lair_api_request(&*self.0, LairApiReqListEntries::new());
        async move {
            let r = r_fut.await?;
            Ok(r.entry_list)
        }
    }

    /// Return the EntryInfo for a given tag, or error if no such tag.
    pub fn get_entry(
        &self,
        _tag: Arc<str>,
    ) -> impl Future<Output = LairResult<LairEntryInfo>> + 'static + Send {
        async move { unimplemented!() }
    }

    /// Instruct lair to generate a new seed from cryptographically secure
    /// random data with given tag. If the seed should be deeply locked,
    /// supply the deep_lock_passphrase as well.
    pub fn new_seed(
        &self,
        tag: Arc<str>,
        deep_lock_passphrase: Option<sodoken::BufRead>,
    ) -> impl Future<Output = LairResult<SeedInfo>> + 'static + Send {
        let inner = self.0.clone();
        async move {
            let secret = match deep_lock_passphrase {
                None => None,
                Some(pass) => {
                    let key = inner.get_encryption_context_key();
                    Some(SecretData::encrypt(key, pass).await?)
                }
            };
            let req = LairApiReqNewSeed::new(tag, secret);
            let res = priv_lair_api_request(&*inner, req).await?;
            Ok(res.seed_info)
        }
    }

    /// Derive a pre-existing key identified by given src_tag, with given
    /// derivation path, storing the final resulting sub-seed with
    /// the given dst_tag.
    pub fn derive_seed(
        &self,
        _src_tag: Arc<str>,
        _src_deep_lock_passphrase: Option<sodoken::BufRead>,
        _dst_tag: Arc<str>,
        _dst_deep_lock_passphrase: Option<sodoken::BufRead>,
        _derivation: Box<[u32]>,
    ) -> impl Future<Output = LairResult<SeedInfo>> + 'static + Send {
        async move { unimplemented!() }
    }

    /// Generate a signature for given data, with the ed25519 keypair
    /// derived from seed identified by the given ed25519 pubkey.
    pub fn sign_by_pub_key(
        &self,
        _pub_key: Ed25519PubKey,
        _deep_lock_passphrase: Option<sodoken::BufRead>,
        _data: Arc<[u8]>,
    ) -> impl Future<Output = LairResult<Ed25519Signature>> + 'static + Send
    {
        async move { unimplemented!() }
    }

    /// Instruct lair to generate a new well-known-authority signed TLS cert.
    /// This is a lot like a self-signed certificate, but slightly easier to
    /// work with in that it allows registering a single well-known-authority
    /// as a certificate authority which will respect multiple certs.
    pub fn new_wka_tls_cert(
        &self,
        _tag: Arc<str>,
    ) -> impl Future<Output = LairResult<CertInfo>> + 'static + Send {
        async move { unimplemented!() }
    }

    /// Fetch the private key associated with a wka_tls_cert entry.
    /// Will error if the entry specified by 'tag' is not a wka_tls_cert.
    pub fn get_wka_tls_cert_priv_key(
        &self,
        _tag: Arc<str>,
    ) -> impl Future<Output = LairResult<sodoken::BufRead>> + 'static + Send
    {
        async move { unimplemented!() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::future::FutureExt;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_lair_api() {
        let key = sodoken::BufReadSized::from([0xdb; 32]);
        let data = sodoken::BufRead::from(b"test-data".to_vec());
        let secret = SecretData::encrypt(key.clone(), data).await.unwrap();
        let data = secret.decrypt(key).await.unwrap();
        println!(
            "GOT DEC SECRET: {}",
            String::from_utf8_lossy(&*data.read_lock())
        );

        let key = sodoken::BufReadSized::from([0xdb; 32]);
        let data = sodoken::BufReadSized::from(*b"test-data");
        let secret = <SecretDataSized<9, 26>>::encrypt(key.clone(), data)
            .await
            .unwrap();
        let data = secret.decrypt(key).await.unwrap();
        println!(
            "GOT DEC SECRET SIZED: {}",
            String::from_utf8_lossy(&*data.read_lock_sized())
        );

        struct X {
            srv_pub_key: BinDataSized<32>,
            srv_sec_key: sodoken::BufReadSized<64>,
        }

        impl AsLairClient for X {
            fn get_encryption_context_key(&self) -> sodoken::BufReadSized<32> {
                sodoken::BufReadSized::from([0xff; 32])
            }

            fn get_decryption_context_key(&self) -> sodoken::BufReadSized<32> {
                sodoken::BufReadSized::from([0xff; 32])
            }

            fn request(
                &self,
                request: LairApiEnum,
            ) -> BoxFuture<'static, LairResult<LairApiEnum>> {
                println!("got: {}", serde_json::to_string(&request).unwrap());
                let pub_key = self.srv_pub_key.clone();
                let sec_key = self.srv_sec_key.clone();
                async move {
                    match request {
                        LairApiEnum::ReqHello(e) => {
                            let sig = sodoken::BufWriteSized::new_no_lock();
                            sodoken::sign::detached(
                                sig.clone(),
                                e.nonce.cloned_inner(),
                                sec_key,
                            )
                            .await?;
                            let sig = sig.try_unwrap_sized().unwrap();
                            Ok(LairApiEnum::ResHello(LairApiResHello {
                                msg_id: e.msg_id,
                                name: "test-server".into(),
                                version: "0.0.0".into(),
                                server_pub_key: pub_key,
                                hello_sig: sig.into(),
                            }))
                        }
                        LairApiEnum::ReqUnlock(e) => {
                            Ok(LairApiEnum::ResUnlock(LairApiResUnlock {
                                msg_id: e.msg_id,
                            }))
                        }
                        LairApiEnum::ReqListEntries(e) => {
                            Ok(LairApiEnum::ResListEntries(
                                LairApiResListEntries {
                                    msg_id: e.msg_id,
                                    entry_list: Vec::new(),
                                },
                            ))
                        }
                        LairApiEnum::ReqNewSeed(e) => {
                            Ok(LairApiEnum::ResNewSeed(LairApiResNewSeed {
                                msg_id: e.msg_id,
                                tag: e.tag,
                                seed_info: SeedInfo {
                                    ed25519_pub_key: [0x01; 32].into(),
                                    x25519_pub_key: [0x02; 32].into(),
                                },
                            }))
                        }
                        _ => {
                            return Err(format!("bad req: {:?}", request).into())
                        }
                    }
                }
                .boxed()
            }
        }

        let srv_pub_key = sodoken::BufWriteSized::new_no_lock();
        let srv_sec_key = sodoken::BufWriteSized::new_mem_locked().unwrap();
        sodoken::sign::keypair(srv_pub_key.clone(), srv_sec_key.clone())
            .await
            .unwrap();

        let lair_client = LairClient(Arc::new(X {
            srv_pub_key: srv_pub_key.try_unwrap_sized().unwrap().into(),
            srv_sec_key: srv_sec_key.to_read_sized(),
        }));

        let nonce = sodoken::BufWrite::new_no_lock(24);
        sodoken::random::bytes_buf(nonce.clone()).await.unwrap();
        let nonce = nonce.try_unwrap().unwrap();

        let hello_res = lair_client.hello(nonce.clone().into()).await.unwrap();
        println!("hello: {:?}", hello_res);
        println!(
            "verify_sig: {:?}",
            hello_res
                .server_pub_key
                .verify_detached(hello_res.hello_sig.cloned_inner(), nonce)
                .await
        );

        let passphrase = sodoken::BufRead::from(&b"passphrase"[..]);
        println!("unlock: {:?}", lair_client.unlock(passphrase).await);

        println!("list: {:?}", lair_client.list_entries().await);
        println!(
            "seed: {:?}",
            lair_client.new_seed("test-tag".into(), None).await
        );
        println!(
            "seed: {:?}",
            lair_client
                .new_seed(
                    "test-tag-deep".into(),
                    Some(sodoken::BufRead::from(b"passphrase".to_vec()))
                )
                .await
        );
    }
}
