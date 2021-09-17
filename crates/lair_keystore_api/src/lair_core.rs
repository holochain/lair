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
}
use traits::*;

/// Wrapper newtype for serde encoding / decoding binary data
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BinData(pub Arc<[u8]>);

impl std::fmt::Debug for BinData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = base64::encode_config(&*self.0, base64::URL_SAFE_NO_PAD);
        f.debug_tuple("BinData").field(&s).finish()
    }
}

impl std::fmt::Display for BinData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = base64::encode_config(&*self.0, base64::URL_SAFE_NO_PAD);
        f.write_str(&s)
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
        let s = base64::encode_config(&*self.0, base64::URL_SAFE_NO_PAD);
        serializer.serialize_str(&s)
    }
}

impl<'de> serde::Deserialize<'de> for BinData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let tmp: String = serde::Deserialize::deserialize(deserializer)?;
        base64::decode_config(&tmp, base64::URL_SAFE_NO_PAD)
            .map_err(serde::de::Error::custom)
            .map(|b| Self(b.into()))
    }
}

/// Wrapper newtype for serde encoding / decoding sized binary data
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BinDataSized<const N: usize>(pub Arc<[u8; N]>);

impl<const N: usize> std::fmt::Debug for BinDataSized<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = base64::encode_config(&*self.0, base64::URL_SAFE_NO_PAD);
        write!(f, "BinDataSized<{}>({})", N, s)
    }
}

impl<const N: usize> std::fmt::Display for BinDataSized<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = base64::encode_config(&*self.0, base64::URL_SAFE_NO_PAD);
        f.write_str(&s)
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
        let s = base64::encode_config(&*self.0, base64::URL_SAFE_NO_PAD);
        serializer.serialize_str(&s)
    }
}

impl<'de, const N: usize> serde::Deserialize<'de> for BinDataSized<N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let tmp: String = serde::Deserialize::deserialize(deserializer)?;
        let tmp = base64::decode_config(&tmp, base64::URL_SAFE_NO_PAD)
            .map_err(serde::de::Error::custom)?;
        if tmp.len() != N {
            return Err(serde::de::Error::custom("invalid buffer length"));
        }
        let mut out = [0; N];
        out.copy_from_slice(&tmp);
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

/// Config used by lair servers.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct LairServerConfigInner {
    /// The connection url for communications between server / client.
    /// - `unix:///path/to/unix/socket?k=Yada`
    /// - `named_pipe:\\.\pipe\my_pipe_name?k=Yada`
    /// - `tcp://127.0.0.1:12345?k=Yada`
    pub connection_url: url::Url,

    /// The pid file for managing a running lair-keystore process
    pub pid_file: std::path::PathBuf,

    /// The sqlcipher store file for persisting secrets
    pub store_file: std::path::PathBuf,

    /// salt for decrypting runtime data
    pub runtime_secrets_salt: BinDataSized<16>,

    /// argon2id mem_limit for decrypting runtime data
    pub runtime_secrets_mem_limit: u32,

    /// argon2id ops_limit for decrypting runtime data
    pub runtime_secrets_ops_limit: u32,

    /// the runtime context key secret
    pub runtime_secrets_context_key: SecretDataSized<32, 49>,

    /// the server identity signature keypair seed
    pub runtime_secrets_sign_seed: SecretDataSized<32, 49>,
}

impl std::fmt::Display for LairServerConfigInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_yaml::to_string(&self).map_err(|_| std::fmt::Error)?;
        f.write_str(&s)
    }
}

impl LairServerConfigInner {
    /// Construct a new default lair server config instance.
    /// Respects hc_seed_bundle::PwHashLimits.
    pub fn new<P>(
        root_path: P,
        passphrase: sodoken::BufRead,
    ) -> impl Future<Output = LairResult<Self>> + 'static + Send
    where
        P: AsRef<std::path::Path>,
    {
        let root_path = root_path.as_ref().to_owned();
        let limits = hc_seed_bundle::PwHashLimits::current();
        async move {
            let mut pid_file = root_path.clone();
            pid_file.push("pid_file");

            let mut store_file = root_path.clone();
            store_file.push("store_file");

            let salt = <sodoken::BufWriteSized<16>>::new_no_lock();
            sodoken::random::bytes_buf(salt.clone()).await?;

            let ops_limit = limits.as_ops_limit();
            let mem_limit = limits.as_mem_limit();

            let pre_secret = <sodoken::BufWriteSized<32>>::new_mem_locked()?;
            sodoken::hash::argon2id::hash(
                pre_secret.clone(),
                passphrase,
                salt.clone(),
                ops_limit,
                mem_limit,
            )
            .await?;

            let ctx_secret = <sodoken::BufWriteSized<32>>::new_mem_locked()?;
            sodoken::kdf::derive_from_key(
                ctx_secret.clone(),
                42,
                *b"CtxSecKy",
                pre_secret.clone(),
            )?;

            let sig_secret = <sodoken::BufWriteSized<32>>::new_mem_locked()?;
            sodoken::kdf::derive_from_key(
                sig_secret.clone(),
                142,
                *b"SigSecKy",
                pre_secret,
            )?;

            let context_key = <sodoken::BufWriteSized<32>>::new_mem_locked()?;
            sodoken::random::bytes_buf(context_key.clone()).await?;

            let sign_seed = <sodoken::BufWriteSized<32>>::new_mem_locked()?;
            sodoken::random::bytes_buf(sign_seed.clone()).await?;

            let sign_pk = <sodoken::BufWriteSized<32>>::new_no_lock();
            let sign_sk = <sodoken::BufWriteSized<64>>::new_mem_locked()?;
            sodoken::sign::seed_keypair(
                sign_pk.clone(),
                sign_sk,
                sign_seed.clone(),
            )
            .await?;

            let context_key = SecretDataSized::encrypt(
                ctx_secret.to_read_sized(),
                context_key.to_read_sized(),
            )
            .await?;
            let sign_seed = SecretDataSized::encrypt(
                sig_secret.to_read_sized(),
                sign_seed.to_read_sized(),
            )
            .await?;

            let sign_pk: BinDataSized<32> =
                sign_pk.try_unwrap_sized().unwrap().into();

            #[cfg(windows)]
            let connection_url = {
                let id = nanoid::nanoid!();
                url::Url::parse(&format!(
                    "named-pipe:\\\\.\\pipe\\{}?k={}",
                    id, sign_pk
                ))
                .unwrap()
            };
            // for named pipe: println!("URL PART: {}", connection_url.path());

            #[cfg(not(windows))]
            let connection_url = {
                let mut con_path = root_path.clone();
                con_path.push("socket");
                url::Url::parse(&format!(
                    "unix://{}?k={}",
                    con_path.to_str().unwrap(),
                    sign_pk
                ))
                .unwrap()
            };

            let config = LairServerConfigInner {
                connection_url,
                pid_file,
                store_file,
                runtime_secrets_salt: salt.try_unwrap_sized().unwrap().into(),
                runtime_secrets_mem_limit: mem_limit,
                runtime_secrets_ops_limit: ops_limit,
                runtime_secrets_context_key: context_key,
                runtime_secrets_sign_seed: sign_seed,
            };

            Ok(config)
        }
    }

    /// Get the server pub key BinDataSized<32> bytes from the connectionUrl
    pub fn get_server_pub_key(&self) -> LairResult<BinDataSized<32>> {
        for (k, v) in self.connection_url.query_pairs() {
            if k == "k" {
                let tmp = base64::decode_config(
                    v.as_bytes(),
                    base64::URL_SAFE_NO_PAD,
                )
                .map_err(one_err::OneErr::new)?;
                if tmp.len() != 32 {
                    return Err(format!(
                        "invalid server_pub_key len, expected 32, got {}",
                        tmp.len()
                    )
                    .into());
                }
                let mut out = [0; 32];
                out.copy_from_slice(&tmp);
                return Ok(out.into());
            }
        }
        Err("no server_pub_key on connection_url".into())
    }
}

/// Additional config used by lair servers.
pub type LairServerConfig = Arc<LairServerConfigInner>;

/// Public information associated with a given seed
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
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
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
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

impl LairApiEnum {
    /// Get the msg_id associated with this msg variant.
    pub fn msg_id(&self) -> Arc<str> {
        match self {
            Self::ResError(LairApiResError { msg_id, .. }) => msg_id.clone(),
            Self::ReqHello(LairApiReqHello { msg_id, .. }) => msg_id.clone(),
            Self::ResHello(LairApiResHello { msg_id, .. }) => msg_id.clone(),
            Self::ReqUnlock(LairApiReqUnlock { msg_id, .. }) => msg_id.clone(),
            Self::ResUnlock(LairApiResUnlock { msg_id, .. }) => msg_id.clone(),
            Self::ReqListEntries(LairApiReqListEntries { msg_id, .. }) => {
                msg_id.clone()
            }
            Self::ResListEntries(LairApiResListEntries { msg_id, .. }) => {
                msg_id.clone()
            }
            Self::ReqNewSeed(LairApiReqNewSeed { msg_id, .. }) => {
                msg_id.clone()
            }
            Self::ResNewSeed(LairApiResNewSeed { msg_id, .. }) => {
                msg_id.clone()
            }
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_config_yaml() {
        let passphrase = sodoken::BufRead::from(&b"passphrase"[..]);
        let srv = LairServerConfigInner::new("/tmp/my/path", passphrase)
            .await
            .unwrap();
        println!("-- server config start --");
        println!("{}", serde_yaml::to_string(&srv).unwrap());
        println!("-- server config end --");
    }
}
