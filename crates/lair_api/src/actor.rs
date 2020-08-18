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
pub enum TlsCertAlg {
    /// Ed25519 Curve.
    PkcsEd25519,
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

ghost_actor::ghost_chan! {
    /// Lair Client Actor Api.
    pub chan LairClientApi<LairError> {
        /// Create a new self-signed tls certificate.
        fn tls_cert_new_self_signed_from_entropy(
            options: TlsCertOptions,
        ) -> (KeystoreIndex, CertSni, CertDigest);

        /// List tls cert keystore indexes / digests.
        fn tls_cert_list() -> Vec<(KeystoreIndex, CertSni, CertDigest)>;

        /// Fetch the certificate by entry index.
        fn tls_cert_get_by_index(
            keystore_index: KeystoreIndex,
        ) -> Cert;

        /// Fetch the certificate by digest.
        fn tls_cert_get_by_digest(
            cert_digest: CertDigest,
        ) -> Cert;

        /// Fetch the certificate by sni.
        fn tls_cert_get_by_sni(
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
        fn sign_ed25519_new_from_entropy() -> (KeystoreIndex, SignEd25519PubKey);

        /// List sign ed25519 keystore indexes / pubkeys.
        fn sign_ed25519_list() -> Vec<(KeystoreIndex, SignEd25519PubKey)>;

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
