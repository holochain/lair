use super::*;

/// Get entry_info for an entry by tag from lair.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LairApiReqDeriveSeed {
    /// Msg id to relate request / response.
    pub msg_id: Arc<str>,

    /// Tag of existing seed.
    pub src_tag: Arc<str>,

    /// If source seed is deep-locked, this passphrase will unlock it.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub src_deep_lock_passphrase: Option<DeepLockPassphraseBytes>,

    /// Tag under which to store derived seed.
    pub dst_tag: Arc<str>,

    /// Optional passphrase with which to deep-lock derived seed.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub dst_deep_lock_passphrase: Option<DeepLockPassphraseBytes>,

    /// The hierarchy of nested derivations.
    /// For instance, [0, 2, 1] would specify that the destination seed is the
    /// 2nd derivation of the 3rd derivation of the 1st derivation of the source seed.
    pub derivation_path: Box<[u32]>,
}

impl LairApiReqDeriveSeed {
    /// Make a new list entries request.
    pub fn new(
        src_tag: Arc<str>,
        src_deep_lock_passphrase: Option<DeepLockPassphraseBytes>,
        dst_tag: Arc<str>,
        dst_deep_lock_passphrase: Option<DeepLockPassphraseBytes>,
        derivation_path: Box<[u32]>,
    ) -> Self {
        Self {
            msg_id: new_msg_id(),
            src_tag,
            src_deep_lock_passphrase,
            dst_tag,
            dst_deep_lock_passphrase,
            derivation_path,
        }
    }
}

impl std::convert::TryFrom<LairApiEnum> for LairApiReqDeriveSeed {
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::ReqDeriveSeed(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {e:?}").into())
        }
    }
}

impl AsLairCodec for LairApiReqDeriveSeed {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::ReqDeriveSeed(self)
    }
}

/// Response to a GetEntry request.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LairApiResDeriveSeed {
    /// Msg id to relate request / response.
    pub msg_id: Arc<str>,

    /// The seed info associated with this seed.
    pub seed_info: SeedInfo,
}

impl std::convert::TryFrom<LairApiEnum> for LairApiResDeriveSeed {
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::ResDeriveSeed(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {e:?}").into())
        }
    }
}

impl AsLairCodec for LairApiResDeriveSeed {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::ResDeriveSeed(self)
    }
}

impl AsLairRequest for LairApiReqDeriveSeed {
    type Response = LairApiResDeriveSeed;
}

impl AsLairResponse for LairApiResDeriveSeed {
    type Request = LairApiReqDeriveSeed;
}
