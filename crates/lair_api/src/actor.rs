//! Types associated with Lair client actor.

use crate::*;

ghost_actor::ghost_chan! {
    /// "Event" types emitted by Lair Client Actor Api.
    pub chan LairClientEvent<LairError> {
        /// The keystore is currently locked - the user
        /// must supply a passphrase in order to unlock.
        fn request_unlock_passphrase() -> String;
    }
}

/// Tls keypair algorithm to use.
#[repr(u32)]
#[derive(Clone, Copy)]
pub enum TlsCertAlg {
    /// Ed25519 Curve.
    PkcsEd25519 = 0x00000200,
}

impl TlsCertAlg {
    /// parse a u32 into a LairEntryType enum variant.
    pub fn parse(d: u32) -> LairResult<Self> {
        use TlsCertAlg::*;
        Ok(match d {
            x if x == PkcsEd25519 as u32 => PkcsEd25519,
            _ => return Err("invalide tls cert alg".into()),
        })
    }
}

/// Configuration for Tls Certificate Generation.
pub struct TlsCertOptions {
    /// Tls keypair algorithm to use.
    pub alg: TlsCertAlg,
}

impl Default for TlsCertOptions {
    fn default() -> Self {
        Self {
            alg: TlsCertAlg::PkcsEd25519,
        }
    }
}

/// Keystore index type.
pub type KeystoreIndex = u32;

/// Der encoded Tls Certificate bytes.
pub type Cert = Arc<Vec<u8>>;

/// Der encoded pkcs #8 Tls Certificate private key bytes.
pub type CertPrivKey = Arc<Vec<u8>>;

/// Sni encoded in given Tls Certificate.
pub type CertSni = Arc<String>;

/// The 32 byte blake2b digest of given Tls Certificate.
pub type CertDigest = Arc<Vec<u8>>;

/// The 32 byte signature ed25519 public key.
pub type SignEd25519PubKey = Arc<Vec<u8>>;

/// The 64 byte detached ed25519 signature data.
pub type SignEd25519Signature = Arc<Vec<u8>>;

/// The entry type for a given entry.
#[repr(u32)]
#[derive(Clone, Copy)]
pub enum LairEntryType {
    /// This entry index was deleted or corrupted.
    Invalid = 0x00000000,

    /// Tls Certificate & private key.
    TlsCert = 0x00000100,

    /// Ed25519 algorithm signature keypair.
    SignEd25519 = 0x00000200,
}

impl LairEntryType {
    /// parse a u32 into a LairEntryType enum variant.
    pub fn parse(d: u32) -> LairResult<Self> {
        use LairEntryType::*;
        Ok(match d {
            x if x == Invalid as u32 => Invalid,
            x if x == TlsCert as u32 => TlsCert,
            x if x == SignEd25519 as u32 => SignEd25519,
            _ => return Err("invalide lair entry type".into()),
        })
    }
}

ghost_actor::ghost_chan! {
    /// Lair Client Actor Api.
    pub chan LairClientApi<LairError> {
        /// Get the highest entry index.
        /// Note, some entries my be stubs / erased values.
        fn lair_get_last_entry_index() -> KeystoreIndex;

        /// Get the entry type for a given index.
        fn lair_get_entry_type(
            keystore_index: KeystoreIndex,
        ) -> LairEntryType;

        /// Create a new self-signed tls certificate.
        fn tls_cert_new_self_signed_from_entropy(
            options: TlsCertOptions,
        ) -> (KeystoreIndex, CertSni, CertDigest);

        /// Get tls cert info by keystore index.
        fn tls_cert_get(
            keystore_index: KeystoreIndex,
        ) -> (CertSni, CertDigest);

        /// Fetch the certificate by entry index.
        fn tls_cert_get_cert_by_index(
            keystore_index: KeystoreIndex,
        ) -> Cert;

        /// Fetch the certificate by digest.
        fn tls_cert_get_cert_by_digest(
            cert_digest: CertDigest,
        ) -> Cert;

        /// Fetch the certificate by sni.
        fn tls_cert_get_cert_by_sni(
            sni: CertSni,
        ) -> Cert;

        /// Fetch the certificate private key by entry index.
        fn tls_cert_get_priv_key_by_index(
            keystore_index: KeystoreIndex,
        ) -> CertPrivKey;

        /// Fetch the certificate private key by digest.
        fn tls_cert_get_priv_key_by_digest(
            cert_digest: CertDigest,
        ) -> CertPrivKey;

        /// Fetch the certificate private key by sni.
        fn tls_cert_get_priv_key_by_sni(
            sni: CertSni,
        ) -> CertPrivKey;

        /// Create a new signature ed25519 keypair from entropy.
        fn sign_ed25519_new_from_entropy(
        ) -> (KeystoreIndex, SignEd25519PubKey);

        /// Get ed25519 keypair info by keystore index.
        fn sign_ed25519_get(
            keystore_index: KeystoreIndex,
        ) -> SignEd25519PubKey;

        /// Generate a signature for message by keystore index.
        fn sign_ed25519_sign_by_index(
            keystore_index: KeystoreIndex,
            message: Arc<Vec<u8>>,
        ) -> SignEd25519Signature;

        /// Generate a signature for message by signature pub key.
        fn sign_ed25519_sign_by_pub_key(
            pub_key: SignEd25519PubKey,
            message: Arc<Vec<u8>>,
        ) -> SignEd25519Signature;
    }
}
