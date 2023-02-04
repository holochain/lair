use super::*;

/// Request "crypto_box" encryption.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LairApiReqSecretBoxXSalsaOpenByTag {
    /// Msg id to relate request / response.
    pub msg_id: Arc<str>,

    /// The tag identifying the seed to use as a shared secret.
    pub tag: Arc<str>,

    /// Reserved for deep_locked seeds. Must be None right now
    /// as deep_locked shared secrets are not implemented.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub deep_lock_passphrase: Option<SecretDataSized<64, 81>>,

    /// The nonce associated with the cipher.
    pub nonce: [u8; 24],

    /// The data to decrypt.
    pub cipher: Arc<[u8]>,
}

impl LairApiReqSecretBoxXSalsaOpenByTag {
    /// Make a crypto_box request.
    pub fn new(
        tag: Arc<str>,
        deep_lock_passphrase: Option<SecretDataSized<64, 81>>,
        nonce: [u8; 24],
        cipher: Arc<[u8]>,
    ) -> Self {
        Self {
            msg_id: new_msg_id(),
            tag,
            deep_lock_passphrase,
            nonce,
            cipher,
        }
    }
}

impl std::convert::TryFrom<LairApiEnum> for LairApiReqSecretBoxXSalsaOpenByTag {
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::ReqSecretBoxXSalsaOpenByTag(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {e:?}").into())
        }
    }
}

impl AsLairCodec for LairApiReqSecretBoxXSalsaOpenByTag {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::ReqSecretBoxXSalsaOpenByTag(self)
    }
}

/// A "crypto_box" encryption response.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct LairApiResSecretBoxXSalsaOpenByTag {
    /// Msg id to relate request / response.
    pub msg_id: Arc<str>,

    /// The decrypted bytes.
    pub message: Arc<[u8]>,
}

impl std::convert::TryFrom<LairApiEnum> for LairApiResSecretBoxXSalsaOpenByTag {
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::ResSecretBoxXSalsaOpenByTag(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {e:?}").into())
        }
    }
}

impl AsLairCodec for LairApiResSecretBoxXSalsaOpenByTag {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::ResSecretBoxXSalsaOpenByTag(self)
    }
}

impl AsLairRequest for LairApiReqSecretBoxXSalsaOpenByTag {
    type Response = LairApiResSecretBoxXSalsaOpenByTag;
}

impl AsLairResponse for LairApiResSecretBoxXSalsaOpenByTag {
    type Request = LairApiReqSecretBoxXSalsaOpenByTag;
}
