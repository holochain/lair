use super::*;

/// An error response from the remote instance.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LairApiResError {
    /// Msg id to relate request / response.
    pub msg_id: Arc<str>,

    /// The error returned.
    pub error: one_err::OneErr,
}

impl std::convert::TryFrom<LairApiEnum> for LairApiResError {
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::ResError(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {e:?}").into())
        }
    }
}

impl AsLairCodec for LairApiResError {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::ResError(self)
    }
}
