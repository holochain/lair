//! Test keystore implementation. DANGER - Not for production!

use crate::actor::*;
use crate::internal::*;
use crate::*;
use futures::future::FutureExt;
use std::collections::HashMap;

static NEXT_KEYSTORE_ID: std::sync::atomic::AtomicU32 =
    std::sync::atomic::AtomicU32::new(0);

fn next_keystore_idx() -> KeystoreIndex {
    NEXT_KEYSTORE_ID
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        .into()
}

/// DANGER! These Fixture Keypairs should NEVER be used in production
/// The private keys have not been handled securely!
pub struct FixtureSignEd25519Keypair {
    /// The agent public key.
    pub pub_key: Vec<u8>,

    /// The private secret key DANGER - this is not handled securely!!
    pub priv_key: Vec<u8>,
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
    fixture_sign_ed25519_keypairs: Vec<FixtureSignEd25519Keypair>,
    fixture_tls_certs: Vec<FixtureTlsCert>,
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

    let i_s = builder
        .channel_factory()
        .create_channel::<InternalApi>()
        .await?;

    tokio::task::spawn(builder.spawn(Internal {
        i_s,
        fixture_sign_ed25519_keypairs,
        fixture_tls_certs,
        by_idx: HashMap::new(),
        cert_by_digest: HashMap::new(),
        cert_by_sni: HashMap::new(),
        sign_by_pub: HashMap::new(),
        last_idx: 0.into(),
    }));

    Ok((sender, evt_recv))
}

struct Internal {
    i_s: ghost_actor::GhostSender<InternalApi>,
    fixture_sign_ed25519_keypairs: Vec<FixtureSignEd25519Keypair>,
    fixture_tls_certs: Vec<FixtureTlsCert>,
    by_idx: HashMap<KeystoreIndex, entry::LairEntry>,
    cert_by_digest: HashMap<CertDigest, entry::EntryTlsCert>,
    cert_by_sni: HashMap<CertSni, entry::EntryTlsCert>,
    sign_by_pub: HashMap<SignEd25519PubKey, entry::EntrySignEd25519>,
    last_idx: KeystoreIndex,
}

impl ghost_actor::GhostControlHandler for Internal {}

ghost_actor::ghost_chan! {
    chan InternalApi<LairError> {
        fn finalize_entry(
            idx: KeystoreIndex,
            entry: entry::LairEntry,
        ) -> ();
    }
}

impl ghost_actor::GhostHandler<InternalApi> for Internal {}

impl InternalApiHandler for Internal {
    fn handle_finalize_entry(
        &mut self,
        idx: KeystoreIndex,
        entry: entry::LairEntry,
    ) -> InternalApiHandlerResult<()> {
        if idx.0 > self.last_idx.0 {
            self.last_idx = idx;
        }
        self.by_idx.insert(idx, entry.clone());
        match entry {
            entry::LairEntry::TlsCert(cert) => {
                self.cert_by_digest
                    .insert(cert.cert_digest.clone(), cert.clone());
                self.cert_by_sni.insert(cert.sni.clone(), cert);
            }
            entry::LairEntry::SignEd25519(keypair) => {
                self.sign_by_pub.insert(keypair.pub_key.clone(), keypair);
            }
        }
        Ok(async move { Ok(()) }.boxed().into())
    }
}

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
        let last_idx = self.last_idx;
        Ok(async move { Ok(last_idx) }.boxed().into())
    }

    fn handle_lair_get_entry_type(
        &mut self,
        keystore_index: KeystoreIndex,
    ) -> LairClientApiHandlerResult<LairEntryType> {
        let entry = match self.by_idx.get(&keystore_index) {
            Some(entry) => entry,
            None => return Err("bad index".into()),
        };
        let t = match entry {
            entry::LairEntry::TlsCert(_) => LairEntryType::TlsCert,
            entry::LairEntry::SignEd25519(_) => LairEntryType::SignEd25519,
        };
        Ok(async move { Ok(t) }.boxed().into())
    }

    fn handle_tls_cert_new_self_signed_from_entropy(
        &mut self,
        options: TlsCertOptions,
    ) -> LairClientApiHandlerResult<(KeystoreIndex, CertSni, CertDigest)> {
        if !self.fixture_tls_certs.is_empty() {
            let cert = self.fixture_tls_certs.remove(0);
            let i_s = self.i_s.clone();
            return Ok(async move {
                let idx = next_keystore_idx();
                let entry = entry::EntryTlsCert {
                    sni: cert.sni.into(),
                    priv_key_der: cert.priv_key_der.into(),
                    cert_der: cert.cert_der.into(),
                    cert_digest: cert.cert_digest.into(),
                };
                let sni = entry.sni.clone();
                let digest = entry.cert_digest.clone();
                let entry = entry::LairEntry::from(entry);
                i_s.finalize_entry(idx, entry).await?;
                Ok((idx, sni, digest))
            }
            .boxed()
            .into());
        }
        let i_s = self.i_s.clone();
        Ok(async move {
            let idx = next_keystore_idx();
            let entry =
                tls::tls_cert_self_signed_new_from_entropy(options).await?;
            let sni = entry.sni.clone();
            let digest = entry.cert_digest.clone();
            let entry = entry::LairEntry::from(entry);
            i_s.finalize_entry(idx, entry).await?;
            Ok((idx, sni, digest))
        }
        .boxed()
        .into())
    }

    fn handle_tls_cert_get(
        &mut self,
        keystore_index: KeystoreIndex,
    ) -> LairClientApiHandlerResult<(CertSni, CertDigest)> {
        let out = match match self.by_idx.get(&keystore_index) {
            Some(entry) => entry,
            None => return Err("bad index".into()),
        } {
            entry::LairEntry::TlsCert(cert) => {
                (cert.sni.clone(), cert.cert_digest.clone())
            }
            _ => return Err("bad type".into()),
        };
        Ok(async move { Ok(out) }.boxed().into())
    }

    fn handle_tls_cert_get_cert_by_index(
        &mut self,
        keystore_index: KeystoreIndex,
    ) -> LairClientApiHandlerResult<Cert> {
        let out = match match self.by_idx.get(&keystore_index) {
            Some(entry) => entry,
            None => return Err("bad index".into()),
        } {
            entry::LairEntry::TlsCert(cert) => cert.cert_der.clone(),
            _ => return Err("bad type".into()),
        };
        Ok(async move { Ok(out) }.boxed().into())
    }

    fn handle_tls_cert_get_cert_by_digest(
        &mut self,
        cert_digest: CertDigest,
    ) -> LairClientApiHandlerResult<Cert> {
        let out = match self.cert_by_digest.get(&cert_digest) {
            Some(cert) => cert.cert_der.clone(),
            None => return Err("bad digest".into()),
        };
        Ok(async move { Ok(out) }.boxed().into())
    }

    fn handle_tls_cert_get_cert_by_sni(
        &mut self,
        cert_sni: CertSni,
    ) -> LairClientApiHandlerResult<Cert> {
        let out = match self.cert_by_sni.get(&cert_sni) {
            Some(cert) => cert.cert_der.clone(),
            None => return Err("bad sni".into()),
        };
        Ok(async move { Ok(out) }.boxed().into())
    }

    fn handle_tls_cert_get_priv_key_by_index(
        &mut self,
        keystore_index: KeystoreIndex,
    ) -> LairClientApiHandlerResult<CertPrivKey> {
        let out = match match self.by_idx.get(&keystore_index) {
            Some(entry) => entry,
            None => return Err("bad index".into()),
        } {
            entry::LairEntry::TlsCert(cert) => cert.priv_key_der.clone(),
            _ => return Err("bad type".into()),
        };
        Ok(async move { Ok(out) }.boxed().into())
    }

    fn handle_tls_cert_get_priv_key_by_digest(
        &mut self,
        cert_digest: CertDigest,
    ) -> LairClientApiHandlerResult<CertPrivKey> {
        let out = match self.cert_by_digest.get(&cert_digest) {
            Some(cert) => cert.priv_key_der.clone(),
            None => return Err("bad digest".into()),
        };
        Ok(async move { Ok(out) }.boxed().into())
    }

    fn handle_tls_cert_get_priv_key_by_sni(
        &mut self,
        cert_sni: CertSni,
    ) -> LairClientApiHandlerResult<CertPrivKey> {
        let out = match self.cert_by_sni.get(&cert_sni) {
            Some(cert) => cert.priv_key_der.clone(),
            None => return Err("bad sni".into()),
        };
        Ok(async move { Ok(out) }.boxed().into())
    }

    fn handle_sign_ed25519_new_from_entropy(
        &mut self,
    ) -> LairClientApiHandlerResult<(KeystoreIndex, SignEd25519PubKey)> {
        if !self.fixture_sign_ed25519_keypairs.is_empty() {
            let keypair = self.fixture_sign_ed25519_keypairs.remove(0);
            let i_s = self.i_s.clone();
            return Ok(async move {
                let idx = next_keystore_idx();
                let entry = entry::EntrySignEd25519 {
                    priv_key: keypair.priv_key.into(),
                    pub_key: keypair.pub_key.into(),
                };
                let pk = entry.pub_key.clone();
                let entry = entry::LairEntry::from(entry);
                i_s.finalize_entry(idx, entry).await?;
                Ok((idx, pk))
            }
            .boxed()
            .into());
        }
        let i_s = self.i_s.clone();
        Ok(async move {
            let idx = next_keystore_idx();
            let entry =
                sign_ed25519::sign_ed25519_keypair_new_from_entropy().await?;
            let pk = entry.pub_key.clone();
            let entry = entry::LairEntry::from(entry);
            i_s.finalize_entry(idx, entry).await?;
            Ok((idx, pk))
        }
        .boxed()
        .into())
    }

    fn handle_sign_ed25519_get(
        &mut self,
        keystore_index: KeystoreIndex,
    ) -> LairClientApiHandlerResult<SignEd25519PubKey> {
        let out = match match self.by_idx.get(&keystore_index) {
            Some(entry) => entry,
            None => return Err("bad index".into()),
        } {
            entry::LairEntry::SignEd25519(keypair) => keypair.pub_key.clone(),
            _ => return Err("bad type".into()),
        };
        Ok(async move { Ok(out) }.boxed().into())
    }

    fn handle_sign_ed25519_sign_by_index(
        &mut self,
        keystore_index: KeystoreIndex,
        message: Arc<Vec<u8>>,
    ) -> LairClientApiHandlerResult<SignEd25519Signature> {
        let priv_key = match match self.by_idx.get(&keystore_index) {
            Some(entry) => entry,
            None => return Err("bad index".into()),
        } {
            entry::LairEntry::SignEd25519(keypair) => keypair.priv_key.clone(),
            _ => return Err("bad type".into()),
        };
        Ok(
            async move { sign_ed25519::sign_ed25519(priv_key, message).await }
                .boxed()
                .into(),
        )
    }

    fn handle_sign_ed25519_sign_by_pub_key(
        &mut self,
        pub_key: SignEd25519PubKey,
        message: Arc<Vec<u8>>,
    ) -> LairClientApiHandlerResult<SignEd25519Signature> {
        let priv_key = match self.sign_by_pub.get(&pub_key) {
            Some(keypair) => keypair.priv_key.clone(),
            None => return Err("bad type".into()),
        };
        Ok(
            async move { sign_ed25519::sign_ed25519(priv_key, message).await }
                .boxed()
                .into(),
        )
    }
}
