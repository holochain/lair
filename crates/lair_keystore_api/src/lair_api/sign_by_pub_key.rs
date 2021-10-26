use super::*;

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
    pub deep_lock_passphrase: Option<SecretDataSized<64, 81>>,
    /// the data to sign
    pub data: Arc<[u8]>,
}

impl LairApiReqSignByPubKey {
    /// Make a new_seed request
    pub fn new(
        pub_key: Ed25519PubKey,
        deep_lock_passphrase: Option<SecretDataSized<64, 81>>,
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
