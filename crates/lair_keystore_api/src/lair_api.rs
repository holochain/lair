//! Lair api serialization types.

use crate::*;
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
    pub passphrase: SecretDataSized<64, 81>,
}

fn new_msg_id() -> Arc<str> {
    nanoid::nanoid!().into()
}

mod error;
pub use error::*;

mod hello;
pub use hello::*;

mod unlock;
pub use unlock::*;

mod get_entry;
pub use get_entry::*;

mod list_entries;
pub use list_entries::*;

mod new_seed;
pub use new_seed::*;

mod sign_by_pub_key;
pub use sign_by_pub_key::*;

mod crypto_box_xsalsa_by_pub_key;
pub use crypto_box_xsalsa_by_pub_key::*;

mod crypto_box_xsalsa_open_by_pub_key;
pub use crypto_box_xsalsa_open_by_pub_key::*;

mod new_wka_tls_cert;
pub use new_wka_tls_cert::*;

mod get_wka_tls_cert_priv_key;
pub use get_wka_tls_cert_priv_key::*;

/// Lair api enum.
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

    /// Request "crypto_box" encryption.
    ReqCryptoBoxXSalsaByPubKey(LairApiReqCryptoBoxXSalsaByPubKey),

    /// A "crypto_box" encryption response.
    ResCryptoBoxXSalsaByPubKey(LairApiResCryptoBoxXSalsaByPubKey),

    /// Request "crypto_box_open" decryption.
    ReqCryptoBoxXSalsaOpenByPubKey(LairApiReqCryptoBoxXSalsaOpenByPubKey),

    /// A "crypto_box_open" decryption response.
    ResCryptoBoxXSalsaOpenByPubKey(LairApiResCryptoBoxXSalsaOpenByPubKey),

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
            Self::ReqCryptoBoxXSalsaByPubKey(
                LairApiReqCryptoBoxXSalsaByPubKey { msg_id, .. },
            ) => msg_id.clone(),
            Self::ResCryptoBoxXSalsaByPubKey(
                LairApiResCryptoBoxXSalsaByPubKey { msg_id, .. },
            ) => msg_id.clone(),
            Self::ReqCryptoBoxXSalsaOpenByPubKey(
                LairApiReqCryptoBoxXSalsaOpenByPubKey { msg_id, .. },
            ) => msg_id.clone(),
            Self::ResCryptoBoxXSalsaOpenByPubKey(
                LairApiResCryptoBoxXSalsaOpenByPubKey { msg_id, .. },
            ) => msg_id.clone(),
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
