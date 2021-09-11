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

fn new_msg_id() -> Arc<str> {
    nanoid::nanoid!().into()
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
    pub fn new(tag: String) -> Self {
        Self {
            msg_id: new_msg_id(),
            tag: tag.into(),
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
    /// ed25519 signature public key derived from this seed.
    pub ed25519_pub_key: Arc<[u8; 32]>,
    /// x25519 encryption public key derived from this seed.
    pub x25519_pub_key: Arc<[u8; 32]>,
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
    /// Handle a lair client request
    pub fn request<R: AsLairRequest>(
        &self,
        request: R,
    ) -> impl Future<Output = LairResult<R::Response>>
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::future::FutureExt;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_lair_api() {
        struct X;

        impl AsLairClient for X {
            fn request(
                &self,
                request: LairApiEnum,
            ) -> BoxFuture<'static, LairResult<LairApiEnum>> {
                println!("got: {}", serde_json::to_string(&request).unwrap());
                async move {
                    match request {
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
                                ed25519_pub_key: Arc::new([0x01; 32]),
                                x25519_pub_key: Arc::new([0x02; 32]),
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

        println!(
            "list: {:?}",
            lair_client.request(LairApiReqListEntries::new()).await
        );
        println!(
            "seed: {:?}",
            lair_client
                .request(LairApiReqNewSeed::new("test-tag".into()))
                .await
        );
    }
}
