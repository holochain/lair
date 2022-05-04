use super::*;

/// Instruct lair to generate a new wka tls certificate
/// from cryptographically secure random data with given tag.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LairApiReqNewWkaTlsCert {
    /// Msg id to relate request / response.
    pub msg_id: Arc<str>,

    /// User-defined tag to associate with the new seed.
    pub tag: Arc<str>,
}

impl LairApiReqNewWkaTlsCert {
    /// Make a new_seed request.
    pub fn new(tag: Arc<str>) -> Self {
        Self {
            msg_id: new_msg_id(),
            tag,
        }
    }
}

impl std::convert::TryFrom<LairApiEnum> for LairApiReqNewWkaTlsCert {
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::ReqNewWkaTlsCert(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {:?}", e).into())
        }
    }
}

impl AsLairCodec for LairApiReqNewWkaTlsCert {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::ReqNewWkaTlsCert(self)
    }
}

/// On new cert generation, lair will respond with info about
/// that cert.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct LairApiResNewWkaTlsCert {
    /// Msg id to relate request / response.
    pub msg_id: Arc<str>,

    /// User-defined tag associated with the generated seed.
    pub tag: Arc<str>,

    /// The associated cert info.
    pub cert_info: CertInfo,
}

impl std::convert::TryFrom<LairApiEnum> for LairApiResNewWkaTlsCert {
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::ResNewWkaTlsCert(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {:?}", e).into())
        }
    }
}

impl AsLairCodec for LairApiResNewWkaTlsCert {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::ResNewWkaTlsCert(self)
    }
}

impl AsLairRequest for LairApiReqNewWkaTlsCert {
    type Response = LairApiResNewWkaTlsCert;
}

impl AsLairResponse for LairApiResNewWkaTlsCert {
    type Request = LairApiReqNewWkaTlsCert;
}
