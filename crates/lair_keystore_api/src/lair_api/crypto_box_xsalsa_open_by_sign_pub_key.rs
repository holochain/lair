use super::*;

/// Request "crypto_box_open" decryption.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LairApiReqCryptoBoxXSalsaOpenBySignPubKey {
    /// Msg id to relate request / response.
    pub msg_id: Arc<str>,

    /// The pub key representing the sender.
    pub sender_pub_key: Ed25519PubKey,

    /// The pub key of the recipient.
    pub recipient_pub_key: Ed25519PubKey,

    /// If this new seed is to be deep_locked, the passphrase for that.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub deep_lock_passphrase: Option<SecretDataSized<64, 81>>,

    /// The nonce associated with the cipher.
    pub nonce: [u8; 24],

    /// The data to decrypt.
    pub cipher: Arc<[u8]>,
}

impl LairApiReqCryptoBoxXSalsaOpenBySignPubKey {
    /// Make a crypto_box_open request.
    pub fn new(
        sender_pub_key: Ed25519PubKey,
        recipient_pub_key: Ed25519PubKey,
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
    for LairApiReqCryptoBoxXSalsaOpenBySignPubKey
{
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::ReqCryptoBoxXSalsaOpenBySignPubKey(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {e:?}").into())
        }
    }
}

impl AsLairCodec for LairApiReqCryptoBoxXSalsaOpenBySignPubKey {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::ReqCryptoBoxXSalsaOpenBySignPubKey(self)
    }
}

/// A "crypto_box_open" decryption response.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct LairApiResCryptoBoxXSalsaOpenBySignPubKey {
    /// Msg id to relate request / response.
    pub msg_id: Arc<str>,

    /// The decrypted bytes.
    pub message: Arc<[u8]>,
}

impl std::convert::TryFrom<LairApiEnum>
    for LairApiResCryptoBoxXSalsaOpenBySignPubKey
{
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::ResCryptoBoxXSalsaOpenBySignPubKey(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {e:?}").into())
        }
    }
}

impl AsLairCodec for LairApiResCryptoBoxXSalsaOpenBySignPubKey {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::ResCryptoBoxXSalsaOpenBySignPubKey(self)
    }
}

impl AsLairRequest for LairApiReqCryptoBoxXSalsaOpenBySignPubKey {
    type Response = LairApiResCryptoBoxXSalsaOpenBySignPubKey;
}

impl AsLairResponse for LairApiResCryptoBoxXSalsaOpenBySignPubKey {
    type Request = LairApiReqCryptoBoxXSalsaOpenBySignPubKey;
}
