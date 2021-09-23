use super::*;

/// Unlock the keystore -- this verifies the client to the keystore.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LairApiReqUnlock {
    /// msg id to relate request / response.
    pub msg_id: Arc<str>,

    /// passphrase to unlock the keystore.
    pub passphrase: SecretData,
}

impl LairApiReqUnlock {
    /// Make a new server info request
    pub fn new(passphrase: SecretData) -> Self {
        Self {
            msg_id: new_msg_id(),
            passphrase,
        }
    }
}

impl std::convert::TryFrom<LairApiEnum> for LairApiReqUnlock {
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::ReqUnlock(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {:?}", e).into())
        }
    }
}

impl AsLairCodec for LairApiReqUnlock {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::ReqUnlock(self)
    }
}

/// Sucess / Failure of the unlock request.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LairApiResUnlock {
    /// msg id to relate request / response.
    pub msg_id: Arc<str>,
}

impl std::convert::TryFrom<LairApiEnum> for LairApiResUnlock {
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::ResUnlock(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {:?}", e).into())
        }
    }
}

impl AsLairCodec for LairApiResUnlock {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::ResUnlock(self)
    }
}

impl AsLairRequest for LairApiReqUnlock {
    type Response = LairApiResUnlock;
}

impl AsLairResponse for LairApiResUnlock {
    type Request = LairApiReqUnlock;
}
