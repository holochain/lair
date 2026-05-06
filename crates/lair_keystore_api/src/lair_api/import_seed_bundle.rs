use super::*;

/// Import a passphrase-locked `hc_seed_bundle` into the keystore.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LairApiReqImportSeedBundle {
    /// Msg id to relate request / response.
    pub msg_id: Arc<str>,

    /// The MSGPACK-encoded locked seed bundle bytes.
    pub bundle_bytes: Arc<[u8]>,

    /// Encrypted bundle passphrase. The server uses this to unlock the
    /// `PwHash` cipher inside the seed bundle.
    pub bundle_passphrase: EncryptedPassphrase,

    /// The tag at which to store the recovered seed.
    pub tag: Arc<str>,

    /// If the seed should be re-exportable after having been imported.
    pub exportable: bool,
}

impl LairApiReqImportSeedBundle {
    /// Make an import-seed-bundle request.
    pub fn new(
        bundle_bytes: Arc<[u8]>,
        bundle_passphrase: EncryptedPassphrase,
        tag: Arc<str>,
        exportable: bool,
    ) -> Self {
        Self {
            msg_id: new_msg_id(),
            bundle_bytes,
            bundle_passphrase,
            tag,
            exportable,
        }
    }
}

impl std::convert::TryFrom<LairApiEnum> for LairApiReqImportSeedBundle {
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::ReqImportSeedBundle(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {e:?}").into())
        }
    }
}

impl AsLairCodec for LairApiReqImportSeedBundle {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::ReqImportSeedBundle(self)
    }
}

/// Response after importing a seed bundle.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct LairApiResImportSeedBundle {
    /// Msg id to relate request / response.
    pub msg_id: Arc<str>,

    /// User-defined tag associated with the imported seed.
    pub tag: Arc<str>,

    /// The seed info associated with this seed.
    pub seed_info: SeedInfo,
}

impl std::convert::TryFrom<LairApiEnum> for LairApiResImportSeedBundle {
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::ResImportSeedBundle(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {e:?}").into())
        }
    }
}

impl AsLairCodec for LairApiResImportSeedBundle {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::ResImportSeedBundle(self)
    }
}

impl AsLairRequest for LairApiReqImportSeedBundle {
    type Response = LairApiResImportSeedBundle;
}

impl AsLairResponse for LairApiResImportSeedBundle {
    type Request = LairApiReqImportSeedBundle;
}
