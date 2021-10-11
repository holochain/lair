use super::*;

/// Initiate communication with the target lair instance.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LairApiReqHello {
    /// msg id to relate request / response.
    pub msg_id: Arc<str>,
}

impl LairApiReqHello {
    /// Make a new server info request
    pub fn new() -> Self {
        Self {
            msg_id: new_msg_id(),
        }
    }
}

impl std::convert::TryFrom<LairApiEnum> for LairApiReqHello {
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::ReqHello(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {:?}", e).into())
        }
    }
}

impl AsLairCodec for LairApiReqHello {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::ReqHello(self)
    }
}

/// The hello response from the target lair instance.
/// This data allows us to verify we are speaking to our expected target.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LairApiResHello {
    /// msg id to relate request / response.
    pub msg_id: Arc<str>,

    /// The server name / identifier.
    pub name: Arc<str>,

    /// The server semantic version.
    pub version: Arc<str>,

    /// The public key identifying this server.
    pub server_pub_key: BinDataSized<32>,
}

impl std::convert::TryFrom<LairApiEnum> for LairApiResHello {
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::ResHello(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {:?}", e).into())
        }
    }
}

impl AsLairCodec for LairApiResHello {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::ResHello(self)
    }
}

impl AsLairRequest for LairApiReqHello {
    type Response = LairApiResHello;
}

impl AsLairResponse for LairApiResHello {
    type Request = LairApiReqHello;
}
