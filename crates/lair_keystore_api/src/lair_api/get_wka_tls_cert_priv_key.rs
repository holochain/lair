use super::*;

/// Request the private key associated with a tagged wka tls cert.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LairApiReqGetWkaTlsCertPrivKey {
    /// Msg id to relate request / response.
    pub msg_id: Arc<str>,

    /// User-defined tag to associate with the new seed.
    pub tag: Arc<str>,
}

impl LairApiReqGetWkaTlsCertPrivKey {
    /// Make a new_seed request.
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
    /// Msg id to relate request / response.
    pub msg_id: Arc<str>,

    /// The certificate private key.
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
