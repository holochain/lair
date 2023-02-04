use super::*;

/// Request "crypto_box" encryption.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LairApiReqCryptoBoxXSalsaByPubKey {
    /// Msg id to relate request / response.
    pub msg_id: Arc<str>,

    /// The pub key representing the sender.
    pub sender_pub_key: X25519PubKey,

    /// The pub key of the recipient.
    pub recipient_pub_key: X25519PubKey,

    /// If this new seed is to be deep_locked, the passphrase for that.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub deep_lock_passphrase: Option<SecretDataSized<64, 81>>,

    /// The data to encrypt
    pub data: Arc<[u8]>,
}

impl LairApiReqCryptoBoxXSalsaByPubKey {
    /// Make a crypto_box request.
    pub fn new(
        sender_pub_key: X25519PubKey,
        recipient_pub_key: X25519PubKey,
        deep_lock_passphrase: Option<SecretDataSized<64, 81>>,
        data: Arc<[u8]>,
    ) -> Self {
        Self {
            msg_id: new_msg_id(),
            sender_pub_key,
            recipient_pub_key,
            deep_lock_passphrase,
            data,
        }
    }
}

impl std::convert::TryFrom<LairApiEnum> for LairApiReqCryptoBoxXSalsaByPubKey {
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::ReqCryptoBoxXSalsaByPubKey(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {e:?}").into())
        }
    }
}

impl AsLairCodec for LairApiReqCryptoBoxXSalsaByPubKey {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::ReqCryptoBoxXSalsaByPubKey(self)
    }
}

/// A "crypto_box" encryption response.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct LairApiResCryptoBoxXSalsaByPubKey {
    /// Msg id to relate request / response.
    pub msg_id: Arc<str>,

    /// The generated nonce.
    pub nonce: [u8; 24],

    /// The encrypted bytes.
    pub cipher: Arc<[u8]>,
}

impl std::convert::TryFrom<LairApiEnum> for LairApiResCryptoBoxXSalsaByPubKey {
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::ResCryptoBoxXSalsaByPubKey(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {e:?}").into())
        }
    }
}

impl AsLairCodec for LairApiResCryptoBoxXSalsaByPubKey {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::ResCryptoBoxXSalsaByPubKey(self)
    }
}

impl AsLairRequest for LairApiReqCryptoBoxXSalsaByPubKey {
    type Response = LairApiResCryptoBoxXSalsaByPubKey;
}

impl AsLairResponse for LairApiResCryptoBoxXSalsaByPubKey {
    type Request = LairApiReqCryptoBoxXSalsaByPubKey;
}
