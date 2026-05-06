use super::*;

/// Request a passphrase-locked `hc_seed_bundle` for the seed at the given tag.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LairApiReqExportSeedBundleByTag {
    /// Msg id to relate request / response.
    pub msg_id: Arc<str>,

    /// The tag of the seed to export.
    pub tag: Arc<str>,

    /// Encrypted bundle passphrase. The server will use this to derive the
    /// argon2id-based cipher key that locks the returned seed bundle.
    pub bundle_passphrase: DeepLockPassphraseBytes,

    /// Argon2id difficulty for the bundle's passphrase cipher.
    pub pw_hash_limits: hc_seed_bundle::PwHashLimits,
}

impl LairApiReqExportSeedBundleByTag {
    /// Make an export-seed-bundle request.
    pub fn new(
        tag: Arc<str>,
        bundle_passphrase: DeepLockPassphraseBytes,
        pw_hash_limits: hc_seed_bundle::PwHashLimits,
    ) -> Self {
        Self {
            msg_id: new_msg_id(),
            tag,
            bundle_passphrase,
            pw_hash_limits,
        }
    }
}

impl std::convert::TryFrom<LairApiEnum> for LairApiReqExportSeedBundleByTag {
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::ReqExportSeedBundleByTag(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {e:?}").into())
        }
    }
}

impl AsLairCodec for LairApiReqExportSeedBundleByTag {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::ReqExportSeedBundleByTag(self)
    }
}

/// A passphrase-locked `hc_seed_bundle` (MSGPACK bytes).
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct LairApiResExportSeedBundleByTag {
    /// Msg id to relate request / response.
    pub msg_id: Arc<str>,

    /// The MSGPACK-encoded locked seed bundle bytes.
    pub bundle_bytes: Arc<[u8]>,
}

impl std::convert::TryFrom<LairApiEnum> for LairApiResExportSeedBundleByTag {
    type Error = one_err::OneErr;

    fn try_from(e: LairApiEnum) -> Result<Self, Self::Error> {
        if let LairApiEnum::ResExportSeedBundleByTag(s) = e {
            Ok(s)
        } else {
            Err(format!("Invalid response type: {e:?}").into())
        }
    }
}

impl AsLairCodec for LairApiResExportSeedBundleByTag {
    fn into_api_enum(self) -> LairApiEnum {
        LairApiEnum::ResExportSeedBundleByTag(self)
    }
}

impl AsLairRequest for LairApiReqExportSeedBundleByTag {
    type Response = LairApiResExportSeedBundleByTag;
}

impl AsLairResponse for LairApiResExportSeedBundleByTag {
    type Request = LairApiReqExportSeedBundleByTag;
}
