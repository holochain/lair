//! Lair api serialization types

use crate::prelude::*;
use std::sync::Arc;

/// Helper traits for core types - you probably don't need these unless
/// you are implementing new lair core instance logic.
pub mod traits {
    use super::*;

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

/// ed25519 signature public key derived from this seed.
pub type Ed25519PubKey = BinDataSized<32>;

/// ed25519 signature bytes.
pub type Ed25519Signature = BinDataSized<64>;

/// x25519 encryption public key derived from this seed.
pub type X25519PubKey = BinDataSized<32>;

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

/// Instructions for how to argon2id pwhash a passphrase
/// for use in deep locking a seed.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeepLockPassphrase {
    /// argon2id ops_limit for decrypting runtime data
    pub ops_limit: u32,
    /// argon2id mem_limit for decrypting runtime data
    pub mem_limit: u32,
    /// if this new seed is to be deep_locked, the passphrase for that.
    pub passphrase: SecretData,
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
    pub deep_lock_passphrase: Option<DeepLockPassphrase>,
}

impl LairApiReqNewSeed {
    /// Make a new_seed request
    pub fn new(
        tag: Arc<str>,
        deep_lock_passphrase: Option<DeepLockPassphrase>,
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
