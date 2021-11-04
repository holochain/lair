use super::*;

/// Get entry_info for an entry by tag from lair.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LairApiReqGetEntry {
    /// msg id to relate request / response.
    pub msg_id: Arc<str>,
    /// user-defined tag associated entry being requested.
    pub tag: Arc<str>,
}

impl LairApiReqGetEntry {
    /// Make a new list entries request
    pub fn new(tag: Arc<str>) -> Self {
        Self {
            msg_id: new_msg_id(),
            tag,
        }
    }
}

impl std::convert::TryFrom<LairApiEnum> for LairApiReqGetEntry {
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::ReqGetEntry(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {:?}", e).into())
        }
    }
}

impl AsLairCodec for LairApiReqGetEntry {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::ReqGetEntry(self)
    }
}

/// Response to a GetEntry request.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LairApiResGetEntry {
    /// msg id to relate request / response.
    pub msg_id: Arc<str>,
    /// entry info for the item requested.
    pub entry_info: LairEntryInfo,
}

impl std::convert::TryFrom<LairApiEnum> for LairApiResGetEntry {
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::ResGetEntry(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {:?}", e).into())
        }
    }
}

impl AsLairCodec for LairApiResGetEntry {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::ResGetEntry(self)
    }
}

impl AsLairRequest for LairApiReqGetEntry {
    type Response = LairApiResGetEntry;
}

impl AsLairResponse for LairApiResGetEntry {
    type Request = LairApiReqGetEntry;
}
