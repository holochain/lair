#![allow(clippy::new_without_default)]
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
        /// Handle a lair client request
        fn request(
            &self,
            request: LairApiEnum,
        ) -> BoxFuture<'static, LairResult<LairApiEnum>>;
    }
}
use traits::*;

/// Lair Configuration Inner Struct
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct LairConfigInner {}

/// Lair Configuration Type
pub type LairConfig = Arc<LairConfigInner>;

/// Secret data. Encrypted with sodium secretstream.
/// The key used to encrypt / decrypt is context dependent.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SecretData(
    // the secretstream header
    pub Arc<[u8; 24]>,

    // the secretstream cipher data
    pub Arc<[u8]>,
);

impl SecretData {
    pub async fn encrypt(
        key: sodoken::BufReadSized<32>,
        data: sodoken::BufRead,
    ) -> LairResult<Self> {
        use sodoken::secretstream::xchacha20poly1305::*;
        let header = <sodoken::BufWriteSized<{ HEADERBYTES }>>::new_no_lock();
        let cipher = sodoken::BufExtend::new_no_lock(data.len() + ABYTES);
        let mut enc = SecretStreamEncrypt::new(key, header.clone())?;
        enc.push_final(data, <Option<sodoken::BufRead>>::None, cipher.clone()).await?;

        let header = header.try_unwrap_sized().unwrap();

        let cipher_r = cipher.to_read();
        drop(cipher);
        let cipher_r = cipher_r.try_unwrap().unwrap();

        Ok(Self(header.into(), cipher_r.into()))
    }

    pub async fn decrypt(&self, key: sodoken::BufReadSized<32>) -> LairResult<sodoken::BufRead> {
        use sodoken::secretstream::xchacha20poly1305::*;
        let header = sodoken::BufReadSized::from(self.0.clone());
        let cipher = sodoken::BufRead::from(self.1.clone());
        let mut dec = SecretStreamDecrypt::new(key, header)?;
        let out = sodoken::BufWrite::new_mem_locked(cipher.len() - ABYTES)?;
        dec.pull(cipher, <Option<sodoken::BufRead>>::None, out.clone()).await?;
        Ok(out.to_read())
    }
}

/// ed25519 signature public key derived from this seed.
pub type Ed25519PubKey = Arc<[u8; 32]>;

/// ed25519 signature bytes.
pub type Ed25519Signature = Arc<[u8; 64]>;

/// x25519 encryption public key derived from this seed.
pub type X25519PubKey = Arc<[u8; 32]>;

/// Public information associated with a given seed
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct SeedInfo {
    /// The ed25519 signature public key derived from this seed.
    pub ed25519_pub_key: Ed25519PubKey,

    /// The x25519 encryption public key derived from this seed.
    pub x25519_pub_key: X25519PubKey,
}

/// The 32 byte blake2b digest of the der encoded tls certificate.
pub type CertDigest = Arc<[u8; 32]>;

/// Public information associated with a given tls certificate.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct CertInfo {
    /// The random sni that was generated for this certificate.
    pub sni: Arc<str>,

    /// The 32 byte blake2b digest of the der encoded tls certificate.
    pub digest: CertDigest,

    /// The der-encoded tls certificate bytes.
    pub cert: Arc<[u8]>,
}

/// The Type and Tag of this lair entry.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
#[non_exhaustive]
pub enum LairEntryListItem {
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
        /// the secretstream header for this seed encryption
        seed_header: Arc<[u8; 24]>,
        /// the secretstream cipher seed content bytes
        seed_cipher: Arc<[u8; 49]>,
    },

    /// As 'Seed' but requires an additional access-time passphrase to use
    DeepLockedSeed {
        /// user-supplied tag for this seed
        tag: Arc<str>,
        /// the seed info associated with this seed
        seed_info: SeedInfo,
        /// salt for argon2id encrypted seed
        salt: Arc<[u8; 16]>,
        /// argon2id ops limit used when encrypting this seed
        ops_limit: u32,
        /// argon2id mem limit used when encrypting this seed
        mem_limit: u32,
        /// the secretstream header for this seed encryption
        seed_header: Arc<[u8; 24]>,
        /// the secretstream cipher seed content bytes
        seed_cipher: Arc<[u8; 49]>,
    },

    /// This tls cert and private key can be used to establish tls cryptography
    /// The secretstream priv_key uses the base passphrase-derived secret
    /// for decryption.
    TlsCert {
        /// user-supplied tag for this tls certificate
        tag: Arc<str>,
        /// the certificate info
        cert_info: CertInfo,
        /// the secretstream header for this priv_key encryption
        priv_key_header: Arc<[u8; 24]>,
        /// the secretstream cipher priv_key content bytes
        priv_key_cipher: Arc<[u8]>,
    },
}

/// The LairEntry enum.
pub type LairEntry = Arc<LairEntryInner>;

fn new_msg_id() -> Arc<str> {
    nanoid::nanoid!().into()
}

/// The LairServerInfo from the remote end of this connection.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct LairServerInfo {
    /// The server name / identifier.
    pub name: Arc<str>,

    /// The server semantic version.
    pub version: Arc<str>,
}

/// Request LairServerInfo from the remote end of this connection.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LairApiReqServerInfo {
    /// msg id to relate request / response.
    pub msg_id: Arc<str>,
}

impl LairApiReqServerInfo {
    /// Make a new server info request
    pub fn new() -> Self {
        Self {
            msg_id: new_msg_id(),
        }
    }
}

impl std::convert::TryFrom<LairApiEnum> for LairApiReqServerInfo {
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::LairApiReqServerInfo(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {:?}", e).into())
        }
    }
}

impl AsLairCodec for LairApiReqServerInfo {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::LairApiReqServerInfo(self)
    }
}

/// Respond to a list entries request.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LairApiResServerInfo {
    /// msg id to relate request / response.
    pub msg_id: Arc<str>,
    /// the returned lair server info.
    pub server_info: LairServerInfo,
}

impl std::convert::TryFrom<LairApiEnum> for LairApiResServerInfo {
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::LairApiResServerInfo(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {:?}", e).into())
        }
    }
}

impl AsLairCodec for LairApiResServerInfo {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::LairApiResServerInfo(self)
    }
}

impl AsLairRequest for LairApiReqServerInfo {
    type Response = LairApiResServerInfo;
}

impl AsLairResponse for LairApiResServerInfo {
    type Request = LairApiReqServerInfo;
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
        if let LairApiEnum::LairApiReqListEntries(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {:?}", e).into())
        }
    }
}

impl AsLairCodec for LairApiReqListEntries {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::LairApiReqListEntries(self)
    }
}

/// Respond to a list entries request.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LairApiResListEntries {
    /// msg id to relate request / response.
    pub msg_id: Arc<str>,
    /// list of lair entry list items.
    pub entry_list: Vec<LairEntryListItem>,
}

impl std::convert::TryFrom<LairApiEnum> for LairApiResListEntries {
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::LairApiResListEntries(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {:?}", e).into())
        }
    }
}

impl AsLairCodec for LairApiResListEntries {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::LairApiResListEntries(self)
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
}

impl LairApiReqNewSeed {
    /// Make a new list entries request
    pub fn new(tag: Arc<str>) -> Self {
        Self {
            msg_id: new_msg_id(),
            tag,
        }
    }
}

impl std::convert::TryFrom<LairApiEnum> for LairApiReqNewSeed {
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::LairApiReqNewSeed(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {:?}", e).into())
        }
    }
}

impl AsLairCodec for LairApiReqNewSeed {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::LairApiReqNewSeed(self)
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
        if let LairApiEnum::LairApiResNewSeed(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {:?}", e).into())
        }
    }
}

impl AsLairCodec for LairApiResNewSeed {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::LairApiResNewSeed(self)
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
    /// Request server info from lair.
    LairApiReqServerInfo(LairApiReqServerInfo),

    /// Respond to a server info request.
    LairApiResServerInfo(LairApiResServerInfo),

    /// Request a list of entries from lair.
    LairApiReqListEntries(LairApiReqListEntries),

    /// Respond to a list entries request.
    LairApiResListEntries(LairApiResListEntries),

    /// Instruct lair to generate a new seed from cryptographically secure
    /// random data with given tag.
    LairApiReqNewSeed(LairApiReqNewSeed),

    /// On new seed generation, lair will respond with info about
    /// that seed.
    LairApiResNewSeed(LairApiResNewSeed),
}

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

/// Concrete lair client struct.
#[derive(Clone)]
pub struct LairClient(pub Arc<dyn AsLairClient>);

impl LairClient {
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
        let request = request.into_api_enum();
        let fut = AsLairClient::request(&*self.0, request);
        async move {
            let res = fut.await?;
            let res: R::Response = std::convert::TryFrom::try_from(res)?;
            Ok(res)
        }
    }

    /// Request server info from lair.
    pub fn server_info(
        &self,
    ) -> impl Future<Output = LairResult<LairServerInfo>> + 'static + Send {
        let r_fut = self.request(LairApiReqServerInfo::new());
        async move {
            let r = r_fut.await?;
            Ok(r.server_info)
        }
    }

    /// Request a list of entries from lair.
    pub fn list_entries(
        &self,
    ) -> impl Future<Output = LairResult<Vec<LairEntryListItem>>> + 'static + Send
    {
        let r_fut = self.request(LairApiReqListEntries::new());
        async move {
            let r = r_fut.await?;
            Ok(r.entry_list)
        }
    }

    /// Instruct lair to generate a new seed from cryptographically secure
    /// random data with given tag. If the seed should be deeply locked,
    /// supply the deep_lock_passphrase as well.
    pub fn new_seed(
        &self,
        tag: Arc<str>,
        //deep_lock_passphrase: Option<sodoken::BufRead>,
    ) -> impl Future<Output = LairResult<SeedInfo>> + 'static + Send {
        let r_fut = self.request(LairApiReqNewSeed::new(tag));
        async move {
            let r = r_fut.await?;
            Ok(r.seed_info)
        }
    }

    /// Derive a pre-existing key identified by given src_tag, with given
    /// derivation path, storing the final resulting sub-seed with
    /// the given dst_tag.
    pub fn derive_seed(
        &self,
        _src_tag: Arc<str>,
        _dst_tag: Arc<str>,
        _derivation: Box<[u32]>,
    ) -> impl Future<Output = LairResult<SeedInfo>> + 'static + Send {
        async move { unimplemented!() }
    }

    /// Generate a signature for given data, with the ed25519 keypair
    /// derived from seed identified by the given ed25519 pubkey.
    pub fn sign_by_pub_key(
        &self,
        _pub_key: Ed25519PubKey,
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
        println!("GOT DEC SECRET: {}", String::from_utf8_lossy(&*data.read_lock()));

        struct X;

        impl AsLairClient for X {
            fn request(
                &self,
                request: LairApiEnum,
            ) -> BoxFuture<'static, LairResult<LairApiEnum>> {
                println!("got: {}", serde_json::to_string(&request).unwrap());
                async move {
                    match request {
                        LairApiEnum::LairApiReqServerInfo(e) => {
                            Ok(LairApiEnum::LairApiResServerInfo(
                                LairApiResServerInfo {
                                    msg_id: e.msg_id,
                                    server_info: LairServerInfo {
                                        name: "test-server".into(),
                                        version: "0.0.0".into(),
                                    },
                                },
                            ))
                        }
                        LairApiEnum::LairApiReqListEntries(e) => {
                            Ok(LairApiEnum::LairApiResListEntries(
                                LairApiResListEntries {
                                    msg_id: e.msg_id,
                                    entry_list: Vec::new(),
                                },
                            ))
                        }
                        LairApiEnum::LairApiReqNewSeed(e) => Ok(
                            LairApiEnum::LairApiResNewSeed(LairApiResNewSeed {
                                msg_id: e.msg_id,
                                tag: e.tag,
                                seed_info: SeedInfo {
                                    ed25519_pub_key: Arc::new([0x01; 32]),
                                    x25519_pub_key: Arc::new([0x02; 32]),
                                },
                            }),
                        ),
                        _ => {
                            return Err(format!("bad req: {:?}", request).into())
                        }
                    }
                }
                .boxed()
            }
        }

        let lair_client = LairClient(Arc::new(X));

        println!("info: {:?}", lair_client.server_info().await);
        println!("list: {:?}", lair_client.list_entries().await);
        println!("seed: {:?}", lair_client.new_seed("test-tag".into()).await);
    }
}
