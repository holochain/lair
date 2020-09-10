//! Test keystore implementation. DANGER - Not for production!

use crate::actor::*;
use crate::*;
use futures::future::FutureExt;

/// DANGER! These Fixture Keypairs should NEVER be used in production
/// The private keys have not been handled securely!
pub struct FixtureSignEd25519Keypair {
    /// The agent public key.
    pub pub_key: Vec<u8>,

    /// The private secret key DANGER - this is not handled securely!!
    pub sec_key: Vec<u8>,
}

/// DANGER! These Fixture Certs should NEVER be used in production
/// The private keys have not been handled securely!
pub struct FixtureTlsCert {
    /// The certificate private key der.
    pub priv_key_der: Vec<u8>,

    /// The sni encoded in the certificate.
    pub sni: String,

    /// The der encoded certificate.
    pub cert_der: Vec<u8>,

    /// the 32 byte blake2b certificate digest.
    pub cert_digest: Vec<u8>,
}

/// Spawn a test keystore using publicly available private keys.
/// DANGER - Not for production!
pub async fn spawn_client_ipc(
    _fixture_sign_ed25519_keypairs: Vec<FixtureSignEd25519Keypair>,
    _fixture_tls_certs: Vec<FixtureTlsCert>,
) -> LairResult<(
    ghost_actor::GhostSender<LairClientApi>,
    LairClientEventReceiver,
)> {
    let (_evt_send, evt_recv) = futures::channel::mpsc::channel(10);

    let builder = ghost_actor::actor_builder::GhostActorBuilder::new();

    let sender = builder
        .channel_factory()
        .create_channel::<LairClientApi>()
        .await?;

    tokio::task::spawn(builder.spawn(Internal {}));

    Ok((sender, evt_recv))
}

struct Internal {}

impl ghost_actor::GhostControlHandler for Internal {}

impl ghost_actor::GhostHandler<LairClientApi> for Internal {}

impl LairClientApiHandler for Internal {
    fn handle_lair_get_server_info(
        &mut self,
    ) -> LairClientApiHandlerResult<LairServerInfo> {
        let mut out = LairServerInfo::default();
        out.name = "[LAIR-TEST-KEYSTORE]".to_string();
        out.version = crate::LAIR_VER.to_string();

        Ok(async move { Ok(out) }.boxed().into())
    }

    fn handle_lair_get_last_entry_index(
        &mut self,
    ) -> LairClientApiHandlerResult<KeystoreIndex> {
        unimplemented!()
    }

    fn handle_lair_get_entry_type(
        &mut self,
        _keystore_index: KeystoreIndex,
    ) -> LairClientApiHandlerResult<LairEntryType> {
        unimplemented!()
    }

    fn handle_tls_cert_new_self_signed_from_entropy(
        &mut self,
        _options: TlsCertOptions,
    ) -> LairClientApiHandlerResult<(KeystoreIndex, CertSni, CertDigest)> {
        unimplemented!()
    }

    fn handle_tls_cert_get(
        &mut self,
        _keystore_index: KeystoreIndex,
    ) -> LairClientApiHandlerResult<(CertSni, CertDigest)> {
        unimplemented!()
    }

    fn handle_tls_cert_get_cert_by_index(
        &mut self,
        _keystore_index: KeystoreIndex,
    ) -> LairClientApiHandlerResult<Cert> {
        unimplemented!()
    }

    fn handle_tls_cert_get_cert_by_digest(
        &mut self,
        _cert_digest: CertDigest,
    ) -> LairClientApiHandlerResult<Cert> {
        unimplemented!()
    }

    fn handle_tls_cert_get_cert_by_sni(
        &mut self,
        _cert_sni: CertSni,
    ) -> LairClientApiHandlerResult<Cert> {
        unimplemented!()
    }

    fn handle_tls_cert_get_priv_key_by_index(
        &mut self,
        _keystore_index: KeystoreIndex,
    ) -> LairClientApiHandlerResult<CertPrivKey> {
        unimplemented!()
    }

    fn handle_tls_cert_get_priv_key_by_digest(
        &mut self,
        _cert_digest: CertDigest,
    ) -> LairClientApiHandlerResult<CertPrivKey> {
        unimplemented!()
    }

    fn handle_tls_cert_get_priv_key_by_sni(
        &mut self,
        _cert_sni: CertSni,
    ) -> LairClientApiHandlerResult<CertPrivKey> {
        unimplemented!()
    }

    fn handle_sign_ed25519_new_from_entropy(
        &mut self,
    ) -> LairClientApiHandlerResult<(KeystoreIndex, SignEd25519PubKey)> {
        unimplemented!()
    }

    fn handle_sign_ed25519_get(
        &mut self,
        _keystore_index: KeystoreIndex,
    ) -> LairClientApiHandlerResult<SignEd25519PubKey> {
        unimplemented!()
    }

    fn handle_sign_ed25519_sign_by_index(
        &mut self,
        _keystore_index: KeystoreIndex,
        _message: Arc<Vec<u8>>,
    ) -> LairClientApiHandlerResult<SignEd25519Signature> {
        unimplemented!()
    }

    fn handle_sign_ed25519_sign_by_pub_key(
        &mut self,
        _pub_key: SignEd25519PubKey,
        _message: Arc<Vec<u8>>,
    ) -> LairClientApiHandlerResult<SignEd25519Signature> {
        unimplemented!()
    }
}
