use super::*;

/// Request "crypto_box" encryption.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LairApiReqSecretBoxXSalsaByTag {
    /// Msg id to relate request / response.
    pub msg_id: Arc<str>,

    /// The tag identifying the seed to use as a shared secret.
    pub tag: Arc<str>,

    /// Reserved for deep_locked seeds. Must be None right now
    /// as deep_locked shared secrets are not implemented.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub deep_lock_passphrase: Option<SecretDataSized<64, 81>>,

    /// The data to encrypt
    pub data: Arc<[u8]>,
}

impl LairApiReqSecretBoxXSalsaByTag {
    /// Make a crypto_box request.
    pub fn new(
        tag: Arc<str>,
        deep_lock_passphrase: Option<SecretDataSized<64, 81>>,
        data: Arc<[u8]>,
    ) -> Self {
        Self {
            msg_id: new_msg_id(),
            tag,
            deep_lock_passphrase,
            data,
        }
    }
}

impl std::convert::TryFrom<LairApiEnum> for LairApiReqSecretBoxXSalsaByTag {
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::ReqSecretBoxXSalsaByTag(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {:?}", e).into())
        }
    }
}

impl AsLairCodec for LairApiReqSecretBoxXSalsaByTag {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::ReqSecretBoxXSalsaByTag(self)
    }
}

/// A "crypto_box" encryption response.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct LairApiResSecretBoxXSalsaByTag {
    /// Msg id to relate request / response.
    pub msg_id: Arc<str>,

    /// The generated nonce.
    pub nonce: [u8; 24],

    /// The encrypted bytes.
    pub cipher: Arc<[u8]>,
}

impl std::convert::TryFrom<LairApiEnum> for LairApiResSecretBoxXSalsaByTag {
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::ResSecretBoxXSalsaByTag(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {:?}", e).into())
        }
    }
}

impl AsLairCodec for LairApiResSecretBoxXSalsaByTag {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::ResSecretBoxXSalsaByTag(self)
    }
}

impl AsLairRequest for LairApiReqSecretBoxXSalsaByTag {
    type Response = LairApiResSecretBoxXSalsaByTag;
}

impl AsLairResponse for LairApiResSecretBoxXSalsaByTag {
    type Request = LairApiReqSecretBoxXSalsaByTag;
}
