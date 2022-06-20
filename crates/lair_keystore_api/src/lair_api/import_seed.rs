use super::*;

/// Request "crypto_box_open" decryption.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LairApiReqImportSeed {
    /// Msg id to relate request / response.
    pub msg_id: Arc<str>,

    /// The pub key representing the sender.
    pub sender_pub_key: X25519PubKey,

    /// The pub key of the recipient.
    pub recipient_pub_key: X25519PubKey,

    /// If this new seed is to be deep_locked, the passphrase for that.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub deep_lock_passphrase: Option<DeepLockPassphrase>,

    /// The nonce associated with the cipher.
    pub nonce: [u8; 24],

    /// The data to decrypt.
    pub cipher: Arc<[u8]>,

    /// The tag at which to store this new seed.
    pub tag: Arc<str>,

    /// If the seed should be re-exportable after having been imported.
    pub exportable: bool,
}

impl LairApiReqImportSeed {
    /// Make a crypto_box_open request.
    pub fn new(
        sender_pub_key: X25519PubKey,
        recipient_pub_key: X25519PubKey,
        deep_lock_passphrase: Option<DeepLockPassphrase>,
        nonce: [u8; 24],
        cipher: Arc<[u8]>,
        tag: Arc<str>,
        exportable: bool,
    ) -> Self {
        Self {
            msg_id: new_msg_id(),
            sender_pub_key,
            recipient_pub_key,
            deep_lock_passphrase,
            nonce,
            cipher,
            tag,
            exportable,
        }
    }
}

impl std::convert::TryFrom<LairApiEnum> for LairApiReqImportSeed {
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::ReqImportSeed(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {:?}", e).into())
        }
    }
}

impl AsLairCodec for LairApiReqImportSeed {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::ReqImportSeed(self)
    }
}

/// A "crypto_box_open" decryption response.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct LairApiResImportSeed {
    /// Msg id to relate request / response.
    pub msg_id: Arc<str>,

    /// User-defined tag associated with the generated seed.
    pub tag: Arc<str>,

    /// The seed info associated with this seed.
    pub seed_info: SeedInfo,
}

impl std::convert::TryFrom<LairApiEnum> for LairApiResImportSeed {
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::ResImportSeed(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {:?}", e).into())
        }
    }
}

impl AsLairCodec for LairApiResImportSeed {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::ResImportSeed(self)
    }
}

impl AsLairRequest for LairApiReqImportSeed {
    type Response = LairApiResImportSeed;
}

impl AsLairResponse for LairApiResImportSeed {
    type Request = LairApiReqImportSeed;
}
