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

/// Get entry_info for an entry by tag from lair.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LairApiReqGetEntry {
    /// msg id to relate request / response.
    pub msg_id: Arc<str>,
    /// user-defined tag associated entry being requested.
    pub tag: Arc<str>,
}

impl LairApiReqGetEntry {
    /// Make a new list entries request
    pub fn new(tag: Arc<str>) -> Self {
        Self {
            msg_id: new_msg_id(),
            tag,
        }
    }
}

impl std::convert::TryFrom<LairApiEnum> for LairApiReqGetEntry {
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::ReqGetEntry(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {:?}", e).into())
        }
    }
}

impl AsLairCodec for LairApiReqGetEntry {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::ReqGetEntry(self)
    }
}

/// Response to a GetEntry request.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LairApiResGetEntry {
    /// msg id to relate request / response.
    pub msg_id: Arc<str>,
    /// entry info for the item requested.
    pub entry_info: LairEntryInfo,
}

impl std::convert::TryFrom<LairApiEnum> for LairApiResGetEntry {
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::ResGetEntry(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {:?}", e).into())
        }
    }
}

impl AsLairCodec for LairApiResGetEntry {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::ResGetEntry(self)
    }
}

impl AsLairRequest for LairApiReqGetEntry {
    type Response = LairApiResGetEntry;
}

impl AsLairResponse for LairApiResGetEntry {
    type Request = LairApiReqGetEntry;
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

/// Request a signature.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LairApiReqSignByPubKey {
    /// msg id to relate request / response.
    pub msg_id: Arc<str>,
    /// the pub key side of the private key to sign the data with.
    pub pub_key: Ed25519PubKey,
    /// if this new seed is to be deep_locked, the passphrase for that.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub deep_lock_passphrase: Option<DeepLockPassphrase>,
    /// the data to sign
    pub data: Arc<[u8]>,
}

impl LairApiReqSignByPubKey {
    /// Make a new_seed request
    pub fn new(
        pub_key: Ed25519PubKey,
        deep_lock_passphrase: Option<DeepLockPassphrase>,
        data: Arc<[u8]>,
    ) -> Self {
        Self {
            msg_id: new_msg_id(),
            pub_key,
            deep_lock_passphrase,
            data,
        }
    }
}

impl std::convert::TryFrom<LairApiEnum> for LairApiReqSignByPubKey {
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::ReqSignByPubKey(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {:?}", e).into())
        }
    }
}

impl AsLairCodec for LairApiReqSignByPubKey {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::ReqSignByPubKey(self)
    }
}

/// A signature response.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct LairApiResSignByPubKey {
    /// msg id to relate request / response.
    pub msg_id: Arc<str>,
    /// the signature bytes
    pub signature: Ed25519Signature,
}

impl std::convert::TryFrom<LairApiEnum> for LairApiResSignByPubKey {
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::ResSignByPubKey(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {:?}", e).into())
        }
    }
}

impl AsLairCodec for LairApiResSignByPubKey {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::ResSignByPubKey(self)
    }
}

impl AsLairRequest for LairApiReqSignByPubKey {
    type Response = LairApiResSignByPubKey;
}

impl AsLairResponse for LairApiResSignByPubKey {
    type Request = LairApiReqSignByPubKey;
}

/// Instruct lair to generate a new wka tls certificate
/// from cryptographically secure random data with given tag.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LairApiReqNewWkaTlsCert {
    /// msg id to relate request / response.
    pub msg_id: Arc<str>,
    /// user-defined tag to associate with the new seed.
    pub tag: Arc<str>,
}

impl LairApiReqNewWkaTlsCert {
    /// Make a new_seed request
    pub fn new(tag: Arc<str>) -> Self {
        Self {
            msg_id: new_msg_id(),
            tag,
        }
    }
}

impl std::convert::TryFrom<LairApiEnum> for LairApiReqNewWkaTlsCert {
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::ReqNewWkaTlsCert(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {:?}", e).into())
        }
    }
}

impl AsLairCodec for LairApiReqNewWkaTlsCert {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::ReqNewWkaTlsCert(self)
    }
}

/// On new cert generation, lair will respond with info about
/// that cert.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct LairApiResNewWkaTlsCert {
    /// msg id to relate request / response.
    pub msg_id: Arc<str>,
    /// user-defined tag associated with the generated seed.
    pub tag: Arc<str>,
    /// the associated cert info
    pub cert_info: CertInfo,
}

impl std::convert::TryFrom<LairApiEnum> for LairApiResNewWkaTlsCert {
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::ResNewWkaTlsCert(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {:?}", e).into())
        }
    }
}

impl AsLairCodec for LairApiResNewWkaTlsCert {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::ResNewWkaTlsCert(self)
    }
}

impl AsLairRequest for LairApiReqNewWkaTlsCert {
    type Response = LairApiResNewWkaTlsCert;
}

impl AsLairResponse for LairApiResNewWkaTlsCert {
    type Request = LairApiReqNewWkaTlsCert;
}

/// Request the private key associated with a tagged wka tls cert.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LairApiReqGetWkaTlsCertPrivKey {
    /// msg id to relate request / response.
    pub msg_id: Arc<str>,
    /// user-defined tag to associate with the new seed.
    pub tag: Arc<str>,
}

impl LairApiReqGetWkaTlsCertPrivKey {
    /// Make a new_seed request
    pub fn new(tag: Arc<str>) -> Self {
        Self {
            msg_id: new_msg_id(),
            tag,
        }
    }
}

impl std::convert::TryFrom<LairApiEnum> for LairApiReqGetWkaTlsCertPrivKey {
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::ReqGetWkaTlsCertPrivKey(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {:?}", e).into())
        }
    }
}

impl AsLairCodec for LairApiReqGetWkaTlsCertPrivKey {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::ReqGetWkaTlsCertPrivKey(self)
    }
}

/// Returns the private key associated with a tagged wka tls cert.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct LairApiResGetWkaTlsCertPrivKey {
    /// msg id to relate request / response.
    pub msg_id: Arc<str>,
    /// the certificate private key.
    pub priv_key: SecretData,
}

impl std::convert::TryFrom<LairApiEnum> for LairApiResGetWkaTlsCertPrivKey {
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::ResGetWkaTlsCertPrivKey(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {:?}", e).into())
        }
    }
}

impl AsLairCodec for LairApiResGetWkaTlsCertPrivKey {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::ResGetWkaTlsCertPrivKey(self)
    }
}

impl AsLairRequest for LairApiReqGetWkaTlsCertPrivKey {
    type Response = LairApiResGetWkaTlsCertPrivKey;
}

impl AsLairResponse for LairApiResGetWkaTlsCertPrivKey {
    type Request = LairApiReqGetWkaTlsCertPrivKey;
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

    /// Get entry_info for an entry by tag from lair.
    ReqGetEntry(LairApiReqGetEntry),

    /// Response to a GetEntry request.
    ResGetEntry(LairApiResGetEntry),

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

    /// Request a signature.
    ReqSignByPubKey(LairApiReqSignByPubKey),

    /// A signature response.
    ResSignByPubKey(LairApiResSignByPubKey),

    /// Instruct lair to generate a new wka tls certificate
    /// from cryptographically secure random data with given tag.
    ReqNewWkaTlsCert(LairApiReqNewWkaTlsCert),

    /// On new cert generation, lair will respond with info about
    /// that cert.
    ResNewWkaTlsCert(LairApiResNewWkaTlsCert),

    /// Request the private key associated with a tagged wka tls cert.
    ReqGetWkaTlsCertPrivKey(LairApiReqGetWkaTlsCertPrivKey),

    /// Returns the private key associated with a tagged wka tls cert.
    ResGetWkaTlsCertPrivKey(LairApiResGetWkaTlsCertPrivKey),
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
            Self::ReqGetEntry(LairApiReqGetEntry { msg_id, .. }) => {
                msg_id.clone()
            }
            Self::ResGetEntry(LairApiResGetEntry { msg_id, .. }) => {
                msg_id.clone()
            }
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
            Self::ReqSignByPubKey(LairApiReqSignByPubKey {
                msg_id, ..
            }) => msg_id.clone(),
            Self::ResSignByPubKey(LairApiResSignByPubKey {
                msg_id, ..
            }) => msg_id.clone(),
            Self::ReqNewWkaTlsCert(LairApiReqNewWkaTlsCert {
                msg_id, ..
            }) => msg_id.clone(),
            Self::ResNewWkaTlsCert(LairApiResNewWkaTlsCert {
                msg_id, ..
            }) => msg_id.clone(),
            Self::ReqGetWkaTlsCertPrivKey(LairApiReqGetWkaTlsCertPrivKey {
                msg_id,
                ..
            }) => msg_id.clone(),
            Self::ResGetWkaTlsCertPrivKey(LairApiResGetWkaTlsCertPrivKey {
                msg_id,
                ..
            }) => msg_id.clone(),
        }
    }
}
