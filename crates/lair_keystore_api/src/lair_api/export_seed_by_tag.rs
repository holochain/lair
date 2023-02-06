use super::*;

/// Request "crypto_box" encryption.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LairApiReqExportSeedByTag {
    /// Msg id to relate request / response.
    pub msg_id: Arc<str>,

    /// The tag of the seed to export.
    pub tag: Arc<str>,

    /// The pub key representing the sender.
    pub sender_pub_key: X25519PubKey,

    /// The pub key of the recipient.
    pub recipient_pub_key: X25519PubKey,

    /// If this new seed is to be deep_locked, the passphrase for that.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub deep_lock_passphrase: Option<SecretDataSized<64, 81>>,
}

impl LairApiReqExportSeedByTag {
    /// Make a crypto_box request.
    pub fn new(
        tag: Arc<str>,
        sender_pub_key: X25519PubKey,
        recipient_pub_key: X25519PubKey,
        deep_lock_passphrase: Option<SecretDataSized<64, 81>>,
    ) -> Self {
        Self {
            msg_id: new_msg_id(),
            tag,
            sender_pub_key,
            recipient_pub_key,
            deep_lock_passphrase,
        }
    }
}

impl std::convert::TryFrom<LairApiEnum> for LairApiReqExportSeedByTag {
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::ReqExportSeedByTag(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {e:?}").into())
        }
    }
}

impl AsLairCodec for LairApiReqExportSeedByTag {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::ReqExportSeedByTag(self)
    }
}

/// A "crypto_box" encryption response.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct LairApiResExportSeedByTag {
    /// Msg id to relate request / response.
    pub msg_id: Arc<str>,

    /// The generated nonce.
    pub nonce: [u8; 24],

    /// The encrypted bytes.
    pub cipher: Arc<[u8]>,
}

impl std::convert::TryFrom<LairApiEnum> for LairApiResExportSeedByTag {
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::ResExportSeedByTag(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {e:?}").into())
        }
    }
}

impl AsLairCodec for LairApiResExportSeedByTag {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::ResExportSeedByTag(self)
    }
}

impl AsLairRequest for LairApiReqExportSeedByTag {
    type Response = LairApiResExportSeedByTag;
}

impl AsLairResponse for LairApiResExportSeedByTag {
    type Request = LairApiReqExportSeedByTag;
}
