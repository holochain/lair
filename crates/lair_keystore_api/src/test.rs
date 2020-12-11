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
/// To be clear, the private keys are committed in a public repo on github!
pub struct FixtureSignEd25519Keypair {
    /// The agent public key.
    pub pub_key: Vec<u8>,

    /// The private secret key DANGER - this is not handled securely!!
    pub priv_key: Vec<u8>,
}

/// DANGER! These Fixture Certs should NEVER be used in production
/// The private keys have not been handled securely!
/// To be clear, the private keys are committed in a public repo on github!
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

/// DANGER! These Fixture Keypairs should NEVER be used in production
/// The private keys have not been handled securely!
/// To be clear, the private keys are committed in a public repo on github!
pub struct FixtureX25519Keypair {
    /// Public key fixture.
    pub pub_key: x25519::X25519PubKey,
    /// Private key fixture.
    pub priv_key: x25519::X25519PrivKey,
}

/// Spawn a test keystore using publicly available private keys.
/// DANGER - Not for production!
pub async fn spawn_test_keystore(
    fixture_sign_ed25519_keypairs: Vec<FixtureSignEd25519Keypair>,
    fixture_tls_certs: Vec<FixtureTlsCert>,
    fixture_x25519_keypairs: Vec<FixtureX25519Keypair>,
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
        fixture_x25519_keypairs,
        by_idx: HashMap::new(),
        cert_by_digest: HashMap::new(),
        cert_by_sni: HashMap::new(),
        sign_by_pub: HashMap::new(),
        x25519_by_pub: HashMap::new(),
        last_idx: 0.into(),
    }));

    Ok((sender, evt_recv))
}

struct Internal {
    i_s: ghost_actor::GhostSender<InternalApi>,
    fixture_sign_ed25519_keypairs: Vec<FixtureSignEd25519Keypair>,
    fixture_tls_certs: Vec<FixtureTlsCert>,
    fixture_x25519_keypairs: Vec<FixtureX25519Keypair>,
    by_idx: HashMap<KeystoreIndex, entry::LairEntry>,
    cert_by_digest: HashMap<CertDigest, entry::EntryTlsCert>,
    cert_by_sni: HashMap<CertSni, entry::EntryTlsCert>,
    sign_by_pub: HashMap<sign_ed25519::SignEd25519PubKey, entry::EntrySignEd25519>,
    x25519_by_pub: HashMap<x25519::X25519PubKey, entry::EntryX25519>,
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
            entry::LairEntry::X25519(keypair) => {
                self.x25519_by_pub.insert(keypair.pub_key.clone(), keypair);
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
            entry::LairEntry::X25519(_) => LairEntryType::X25519,
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
    ) -> LairClientApiHandlerResult<(KeystoreIndex, sign_ed25519::SignEd25519PubKey)> {
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
    ) -> LairClientApiHandlerResult<sign_ed25519::SignEd25519PubKey> {
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
    ) -> LairClientApiHandlerResult<sign_ed25519::SignEd25519Signature> {
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
        pub_key: sign_ed25519::SignEd25519PubKey,
        message: Arc<Vec<u8>>,
    ) -> LairClientApiHandlerResult<sign_ed25519::SignEd25519Signature> {
        let priv_key = match self.sign_by_pub.get(&pub_key) {
            Some(keypair) => keypair.priv_key.clone(),
            None => return Err(LairError::PubKeyNotFound),
        };
        Ok(
            async move { sign_ed25519::sign_ed25519(priv_key, message).await }
                .boxed()
                .into(),
        )
    }

    fn handle_x25519_new_from_entropy(&mut self) -> LairClientApiHandlerResult<(KeystoreIndex, x25519::X25519PubKey)> {
        if !self.fixture_x25519_keypairs.is_empty() {
            let keypair = self.fixture_x25519_keypairs.remove(0);
            let i_s = self.i_s.clone();
            return Ok(async move {
                let idx = next_keystore_idx();
                let entry = entry::EntryX25519 {
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
                x25519::x25519_keypair_new_from_entropy().await?;
            let pk = entry.pub_key.clone();
            let entry = entry::LairEntry::from(entry);
            i_s.finalize_entry(idx, entry).await?;
            Ok((idx, pk))
        }
        .boxed()
        .into())
    }

    fn handle_x25519_get(&mut self, keystore_index: KeystoreIndex,
    ) -> LairClientApiHandlerResult<x25519::X25519PubKey> {
        let out = match match self.by_idx.get(&keystore_index) {
            Some(entry) => entry,
            None => return Err("bad index".into()),
        } {
            entry::LairEntry::X25519(keypair) => keypair.pub_key.clone(),
            _ => return Err("bad type".into()),
        };
        Ok(async move { Ok(out) }.boxed().into())
    }

    fn handle_crypto_box_by_index(&mut self, keystore_index: KeystoreIndex, recipient: x25519::X25519PubKey, data: Arc<crypto_box::CryptoBoxData>)
    -> LairClientApiHandlerResult<crypto_box::CryptoBoxEncryptedData> {
        let priv_key = match match self.by_idx.get(&keystore_index) {
            Some(entry) => entry,
            None => return Err("bad index".into()),
        } {
            entry::LairEntry::X25519(keypair) => keypair.priv_key.clone(),
            _ => return Err("bad type".into()),
        };
        Ok(async move { crypto_box::crypto_box(priv_key, recipient, data) }.boxed().into())
    }

    fn handle_crypto_box_by_pub_key(&mut self, pub_key: x25519::X25519PubKey, recipient: x25519::X25519PubKey, data: Arc<crypto_box::CryptoBoxData>) -> LairClientApiHandlerResult<crypto_box::CryptoBoxEncryptedData> {
        let priv_key = match self.x25519_by_pub.get(&pub_key) {
            Some(keypair) => keypair.priv_key.clone(),
            None => return Err(LairError::PubKeyNotFound),
        };
        Ok(async move { crypto_box::crypto_box(priv_key, recipient, data) }.boxed().into())
    }

    fn handle_crypto_box_open_by_index(&mut self, keystore_index: KeystoreIndex, sender: x25519::X25519PubKey, encrypted_data: Arc<crypto_box::CryptoBoxEncryptedData>) -> LairClientApiHandlerResult<crypto_box::CryptoBoxData> {
        let priv_key = match match self.by_idx.get(&keystore_index) {
            Some(entry) => entry,
            None => return Err("bad index".into()),
        } {
            entry::LairEntry::X25519(keypair) => keypair.priv_key.clone(),
            _ => return Err("bad type".into()),
        };
        Ok(
            async move { crypto_box::crypto_box_open(priv_key, sender, encrypted_data) }
            .boxed()
            .into(),
        )
    }

    fn handle_crypto_box_open_by_pub_key(&mut self, pub_key: x25519::X25519PubKey, sender: x25519::X25519PubKey, encrypted_data: Arc<crypto_box::CryptoBoxEncryptedData>) -> LairClientApiHandlerResult<crypto_box::CryptoBoxData> {
        let priv_key = match self.x25519_by_pub.get(&pub_key) {
            Some(keypair) => keypair.priv_key.clone(),
            None => return Err(LairError::PubKeyNotFound),
        };
        Ok(
            async move { crypto_box::crypto_box_open(priv_key, sender, encrypted_data) }
            .boxed()
            .into(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUB1: &[u8] = &[
        154, 185, 40, 0, 115, 213, 127, 247, 174, 124, 110, 222, 11, 151, 230,
        233, 2, 171, 91, 154, 79, 50, 137, 45, 188, 110, 75, 56, 45, 18, 156,
        158,
    ];
    const SEC1: &[u8] = &[
        207, 84, 35, 155, 191, 10, 211, 240, 254, 92, 222, 153, 125, 241, 80,
        102, 189, 217, 201, 140, 112, 159, 21, 148, 138, 41, 85, 90, 169, 56,
        174, 72,
    ];
    const PUB2: &[u8] = &[
        123, 88, 252, 103, 102, 190, 254, 104, 167, 210, 29, 41, 26, 225, 12,
        113, 137, 104, 253, 93, 101, 214, 107, 125, 58, 208, 110, 203, 2, 166,
        30, 88,
    ];
    const SEC2: &[u8] = &[
        59, 31, 135, 117, 115, 107, 84, 52, 95, 216, 51, 180, 79, 81, 14, 169,
        163, 149, 166, 174, 167, 143, 3, 211, 123, 224, 24, 25, 201, 40, 81,
        188,
    ];

    const CERT_SNI: &str = "ar1J-HVz0EO4CzS9CN8EFta.ad471maBa70w5vn6nNilfUa";
    const CERT_SEC: &[u8] = &[
        48, 83, 2, 1, 1, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32, 135, 101, 23,
        181, 167, 183, 114, 94, 169, 84, 144, 224, 192, 41, 112, 118, 149, 226,
        42, 187, 247, 210, 54, 43, 83, 125, 13, 209, 93, 207, 33, 153, 161, 35,
        3, 33, 0, 83, 74, 255, 70, 132, 118, 51, 92, 85, 250, 176, 123, 49,
        206, 237, 79, 161, 136, 99, 44, 52, 128, 94, 174, 55, 174, 198, 113,
        79, 135, 111, 26,
    ];
    const CERT: &[u8] = &[
        48, 130, 1, 48, 48, 129, 227, 160, 3, 2, 1, 2, 2, 1, 42, 48, 5, 6, 3,
        43, 101, 112, 48, 33, 49, 31, 48, 29, 6, 3, 85, 4, 3, 12, 22, 114, 99,
        103, 101, 110, 32, 115, 101, 108, 102, 32, 115, 105, 103, 110, 101,
        100, 32, 99, 101, 114, 116, 48, 32, 23, 13, 55, 53, 48, 49, 48, 49, 48,
        48, 48, 48, 48, 48, 90, 24, 15, 52, 48, 57, 54, 48, 49, 48, 49, 48, 48,
        48, 48, 48, 48, 90, 48, 33, 49, 31, 48, 29, 6, 3, 85, 4, 3, 12, 22,
        114, 99, 103, 101, 110, 32, 115, 101, 108, 102, 32, 115, 105, 103, 110,
        101, 100, 32, 99, 101, 114, 116, 48, 42, 48, 5, 6, 3, 43, 101, 112, 3,
        33, 0, 83, 74, 255, 70, 132, 118, 51, 92, 85, 250, 176, 123, 49, 206,
        237, 79, 161, 136, 99, 44, 52, 128, 94, 174, 55, 174, 198, 113, 79,
        135, 111, 26, 163, 62, 48, 60, 48, 58, 6, 3, 85, 29, 17, 4, 51, 48, 49,
        130, 47, 97, 114, 49, 74, 45, 72, 86, 122, 48, 69, 79, 52, 67, 122, 83,
        57, 67, 78, 56, 69, 70, 116, 97, 46, 97, 100, 52, 55, 49, 109, 97, 66,
        97, 55, 48, 119, 53, 118, 110, 54, 110, 78, 105, 108, 102, 85, 97, 48,
        5, 6, 3, 43, 101, 112, 3, 65, 0, 211, 114, 220, 25, 145, 60, 41, 144,
        219, 0, 170, 31, 206, 39, 134, 136, 147, 103, 63, 215, 239, 108, 28,
        136, 102, 40, 213, 247, 233, 32, 190, 66, 155, 175, 6, 206, 193, 223,
        93, 244, 11, 54, 81, 66, 31, 79, 20, 161, 138, 83, 58, 13, 4, 214, 204,
        189, 12, 66, 180, 147, 202, 208, 242, 3,
    ];
    const CERT_DIGEST: &[u8] = &[
        112, 155, 175, 48, 124, 184, 87, 220, 71, 56, 229, 88, 125, 146, 177,
        13, 218, 216, 23, 59, 225, 6, 23, 207, 126, 223, 169, 142, 92, 242,
        240, 239,
    ];

    const X25519_SEC: [u8; 32] = [
        253, 12, 117, 61, 12, 47, 207, 107, 110, 116, 6, 194, 214, 88, 61, 161, 220, 6, 53, 190,
        225, 254, 230, 143, 130, 70, 25, 160, 15, 168, 42, 37
    ];
    const X25519_PUB: [u8; 32] = [
        65, 17, 71, 31, 48, 10, 48, 208, 3, 220, 71, 246, 83, 246, 74, 221, 3, 123, 54, 48, 160,
        192, 179, 207, 115, 6, 19, 53, 233, 231, 167, 75
    ];

    async fn setup() -> LairResult<ghost_actor::GhostSender<LairClientApi>> {
        let (api, _evt) = spawn_test_keystore(
            vec![
                FixtureSignEd25519Keypair {
                    pub_key: PUB1.to_vec(),
                    priv_key: SEC1.to_vec(),
                },
                FixtureSignEd25519Keypair {
                    pub_key: PUB2.to_vec(),
                    priv_key: SEC2.to_vec(),
                },
            ],
            vec![FixtureTlsCert {
                priv_key_der: CERT_SEC.to_vec(),
                sni: CERT_SNI.to_string(),
                cert_der: CERT.to_vec(),
                cert_digest: CERT_DIGEST.to_vec(),
            }],
            vec![
                FixtureX25519Keypair {
                    pub_key: X25519_PUB.into(),
                    priv_key: X25519_SEC.into(),
                }
            ],
        )
        .await?;
        Ok(api)
    }

    #[tokio::test(threaded_scheduler)]
    async fn test_test_keystore_signing() -> LairResult<()> {
        let api = setup().await?;
        let api2 = api.clone();

        let sys_info = api.lair_get_server_info().await?;
        assert_eq!(crate::LAIR_VER, sys_info.version);
        let sys_info = api2.lair_get_server_info().await?;
        assert_eq!(crate::LAIR_VER, sys_info.version);

        let (idx1, pk1) = api.sign_ed25519_new_from_entropy().await?;
        assert_eq!(pk1.0.as_slice(), PUB1);
        assert_eq!(pk1, api.sign_ed25519_get(idx1).await?);
        let (idx2, pk2) = api2.sign_ed25519_new_from_entropy().await?;
        assert_eq!(pk2.0.as_slice(), PUB2);
        assert_eq!(pk2, api2.sign_ed25519_get(idx2).await?);
        let (idx3, pk3) = api.sign_ed25519_new_from_entropy().await?;
        assert_eq!(pk3, api.sign_ed25519_get(idx3).await?);
        assert_ne!(pk3.0.as_slice(), PUB1);
        assert_ne!(pk3.0.as_slice(), PUB2);

        assert_eq!(idx3, api.lair_get_last_entry_index().await?);

        let data = std::sync::Arc::new(b"test-data".to_vec());

        let sig1 = api.sign_ed25519_sign_by_index(idx1, data.clone()).await?;
        let sig2 = api
            .sign_ed25519_sign_by_pub_key(pk1.clone(), data.clone())
            .await?;
        assert_eq!(sig1, sig2);
        assert!(pk1.verify(data.clone(), sig1).await?);

        let sig1 = api2.sign_ed25519_sign_by_index(idx2, data.clone()).await?;
        let sig2 = api2
            .sign_ed25519_sign_by_pub_key(pk2.clone(), data.clone())
            .await?;
        assert_eq!(sig1, sig2);
        assert!(pk2.verify(data.clone(), sig1).await?);

        let sig1 = api.sign_ed25519_sign_by_index(idx3, data.clone()).await?;
        let sig2 = api
            .sign_ed25519_sign_by_pub_key(pk3.clone(), data.clone())
            .await?;
        assert_eq!(sig1, sig2);
        assert!(pk3.verify(data.clone(), sig1).await?);

        Ok(())
    }

    #[tokio::test(threaded_scheduler)]
    async fn test_test_keystore_tls() -> LairResult<()> {
        let api = setup().await?;

        let (idx1, sni1, digest1) = api
            .tls_cert_new_self_signed_from_entropy(TlsCertOptions::default())
            .await?;
        assert_eq!(CERT_SNI, sni1.as_str());
        assert_eq!(CERT_DIGEST, digest1.as_slice());

        let (sni1, digest1) = api.tls_cert_get(idx1).await?;
        assert_eq!(CERT_SNI, sni1.as_str());
        assert_eq!(CERT_DIGEST, digest1.as_slice());

        let cert1 = api.tls_cert_get_cert_by_index(idx1).await?;
        let cert2 = api.tls_cert_get_cert_by_sni(sni1.clone()).await?;
        let cert3 = api.tls_cert_get_cert_by_digest(digest1.clone()).await?;
        assert_eq!(cert1, cert2);
        assert_eq!(cert2, cert3);

        let priv1 = api.tls_cert_get_priv_key_by_index(idx1).await?;
        let priv2 = api.tls_cert_get_priv_key_by_sni(sni1).await?;
        let priv3 = api.tls_cert_get_priv_key_by_digest(digest1).await?;
        assert_eq!(priv1, priv2);
        assert_eq!(priv2, priv3);

        let (_idx2, sni2, digest2) = api
            .tls_cert_new_self_signed_from_entropy(TlsCertOptions::default())
            .await?;
        assert_ne!(CERT_SNI, sni2.as_str());
        assert_ne!(CERT_DIGEST, digest2.as_slice());

        Ok(())
    }
}
