use super::*;

/// Request "crypto_box_open" decryption.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LairApiReqCryptoBoxXSalsaOpenByPubKey {
    /// Msg id to relate request / response.
    pub msg_id: Arc<str>,

    /// The pub key representing the sender.
    pub sender_pub_key: X25519PubKey,

    /// The pub key of the recipient.
    pub recipient_pub_key: X25519PubKey,

    /// If this new seed is to be deep_locked, the passphrase for that.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub deep_lock_passphrase: Option<SecretDataSized<64, 81>>,

    /// The nonce associated with the cipher.
    pub nonce: [u8; 24],

    /// The data to decrypt.
    pub cipher: Arc<[u8]>,
}

impl LairApiReqCryptoBoxXSalsaOpenByPubKey {
    /// Make a crypto_box_open request.
    pub fn new(
        sender_pub_key: X25519PubKey,
        recipient_pub_key: X25519PubKey,
        deep_lock_passphrase: Option<SecretDataSized<64, 81>>,
        nonce: [u8; 24],
        cipher: Arc<[u8]>,
    ) -> Self {
        Self {
            msg_id: new_msg_id(),
            sender_pub_key,
            recipient_pub_key,
            deep_lock_passphrase,
            nonce,
            cipher,
        }
    }
}

impl std::convert::TryFrom<LairApiEnum>
    for LairApiReqCryptoBoxXSalsaOpenByPubKey
{
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::ReqCryptoBoxXSalsaOpenByPubKey(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {e:?}").into())
        }
    }
}

impl AsLairCodec for LairApiReqCryptoBoxXSalsaOpenByPubKey {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::ReqCryptoBoxXSalsaOpenByPubKey(self)
    }
}

/// A "crypto_box_open" decryption response.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct LairApiResCryptoBoxXSalsaOpenByPubKey {
    /// Msg id to relate request / response.
    pub msg_id: Arc<str>,

    /// The decrypted bytes.
    pub message: Arc<[u8]>,
}

impl std::convert::TryFrom<LairApiEnum>
    for LairApiResCryptoBoxXSalsaOpenByPubKey
{
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::ResCryptoBoxXSalsaOpenByPubKey(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {e:?}").into())
        }
    }
}

impl AsLairCodec for LairApiResCryptoBoxXSalsaOpenByPubKey {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::ResCryptoBoxXSalsaOpenByPubKey(self)
    }
}

impl AsLairRequest for LairApiReqCryptoBoxXSalsaOpenByPubKey {
    type Response = LairApiResCryptoBoxXSalsaOpenByPubKey;
}

impl AsLairResponse for LairApiResCryptoBoxXSalsaOpenByPubKey {
    type Request = LairApiReqCryptoBoxXSalsaOpenByPubKey;
}
