//! Types associated with Lair client actor.

use crate::*;
use derive_more::*;
use internal::crypto_box;
use internal::sign_ed25519;
use internal::x25519;

ghost_actor::ghost_chan! {
    /// "Event" types emitted by Lair Client Actor Api.
    pub chan LairClientEvent<LairError> {
        /// The keystore is currently locked - the user
        /// must supply a passphrase in order to unlock.
        fn request_unlock_passphrase() -> String;
    }
}

/// Lair Client Event Sender Type.
pub type LairClientEventSenderType =
    futures::channel::mpsc::Sender<LairClientEvent>;

/// Lair Client Event Receiver Type.
pub type LairClientEventReceiver =
    futures::channel::mpsc::Receiver<LairClientEvent>;

/// Tls keypair algorithm to use.
#[non_exhaustive]
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TlsCertAlg {
    /// Ed25519 Curve.
    PkcsEd25519 = 0x00000200,
    /// Ecdsa Curve 256.
    PkcsEcdsaP256Sha256 = 0x00000201,
    /// Ecdsa Curve 384.
    PkcsEcdsaP384Sha384 = 0x00000202,
}

impl Default for TlsCertAlg {
    fn default() -> Self {
        Self::PkcsEd25519
    }
}

impl TlsCertAlg {
    /// parse a u32 into a LairEntryType enum variant.
    pub fn parse(d: u32) -> LairResult<Self> {
        use TlsCertAlg::*;
        Ok(match d {
            x if x == PkcsEd25519 as u32 => PkcsEd25519,
            x if x == PkcsEcdsaP256Sha256 as u32 => PkcsEcdsaP256Sha256,
            x if x == PkcsEcdsaP384Sha384 as u32 => PkcsEcdsaP384Sha384,
            _ => return Err("invalid tls cert alg".into()),
        })
    }
}

/// Configuration for Tls Certificate Generation.
#[non_exhaustive]
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
#[derive(
    Clone,
    Copy,
    Debug,
    Display,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Deref,
    From,
    Into,
)]
pub struct KeystoreIndex(pub u32);

/// Der encoded Tls Certificate bytes.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Deref, From, Into,
)]
#[allow(clippy::rc_buffer)]
pub struct Cert(pub Arc<Vec<u8>>);

impl From<Vec<u8>> for Cert {
    fn from(d: Vec<u8>) -> Self {
        Self(Arc::new(d))
    }
}

/// Der encoded pkcs #8 Tls Certificate private key bytes.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Deref, From, Into,
)]
#[allow(clippy::rc_buffer)]
pub struct CertPrivKey(pub Arc<Vec<u8>>);

impl From<Vec<u8>> for CertPrivKey {
    fn from(d: Vec<u8>) -> Self {
        Self(Arc::new(d))
    }
}

/// Sni encoded in given Tls Certificate.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Deref, From, Into,
)]
#[allow(clippy::rc_buffer)]
pub struct CertSni(pub Arc<String>);

impl From<String> for CertSni {
    fn from(s: String) -> Self {
        Self(Arc::new(s))
    }
}

/// The 32 byte blake2b digest of given Tls Certificate.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Deref, From, Into,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[allow(clippy::rc_buffer)]
pub struct CertDigest(pub Arc<Vec<u8>>);

impl From<Vec<u8>> for CertDigest {
    fn from(d: Vec<u8>) -> Self {
        Self(Arc::new(d))
    }
}

/// The entry type for a given entry.
#[non_exhaustive]
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum LairEntryType {
    /// This entry index was deleted or corrupted.
    Invalid = 0x00000000,

    /// Tls Certificate & private key.
    TlsCert = 0x00000100,

    /// Ed25519 algorithm signature keypair.
    SignEd25519 = 0x00000200,

    /// X25519 ECDH keypair.
    X25519 = 0x00000300,
}

impl Default for LairEntryType {
    fn default() -> Self {
        Self::Invalid
    }
}

impl LairEntryType {
    /// parse a u32 into a LairEntryType enum variant.
    pub fn parse(d: u32) -> LairResult<Self> {
        use LairEntryType::*;
        Ok(match d {
            x if x == Invalid as u32 => Invalid,
            x if x == TlsCert as u32 => TlsCert,
            x if x == SignEd25519 as u32 => SignEd25519,
            x if x == X25519 as u32 => X25519,
            _ => return Err("invalide lair entry type".into()),
        })
    }
}

/// Get information about the server we are connected to.
#[non_exhaustive]
#[derive(Debug, Default, Clone, PartialEq)]
pub struct LairServerInfo {
    /// Server name / identifier.
    pub name: String,

    /// Server version.
    pub version: String,
}

ghost_actor::ghost_chan! {
    /// Lair Client Actor Api.
    pub chan LairClientApi<LairError> {
        /// Get lair server info.
        fn lair_get_server_info() -> LairServerInfo;

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
            cert_sni: CertSni,
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
            cert_sni: CertSni,
        ) -> CertPrivKey;

        /// Create a new signature ed25519 keypair from entropy.
        fn sign_ed25519_new_from_entropy(
        ) -> (KeystoreIndex, sign_ed25519::SignEd25519PubKey);

        /// Get ed25519 keypair info by keystore index.
        fn sign_ed25519_get(
            keystore_index: KeystoreIndex,
        ) -> sign_ed25519::SignEd25519PubKey;

        /// Generate a signature for message by keystore index.
        fn sign_ed25519_sign_by_index(
            keystore_index: KeystoreIndex,
            message: Arc<Vec<u8>>,
        ) -> sign_ed25519::SignEd25519Signature;

        /// Generate a signature for message by signature pub key.
        fn sign_ed25519_sign_by_pub_key(
            pub_key: sign_ed25519::SignEd25519PubKey,
            message: Arc<Vec<u8>>,
        ) -> sign_ed25519::SignEd25519Signature;

        /// Generate new x25519 keypair from entropy.
        fn x25519_new_from_entropy() -> (KeystoreIndex, x25519::X25519PubKey);

        /// Get x25519 keypair by keystore index.
        fn x25519_get(
            keystore_index: KeystoreIndex,
        ) -> x25519::X25519PubKey;

        /// Generate encrypted crypto box data by sender keystore index for recipient pubkey.
        fn crypto_box_by_index(
            keystore_index: KeystoreIndex,
            recipient: x25519::X25519PubKey,
            data: Arc<crypto_box::CryptoBoxData>,
        ) -> crypto_box::CryptoBoxEncryptedData;

        /// Generate encrypted crypto box data by sender pubkey for recipient pubkey.
        fn crypto_box_by_pub_key(
            pub_key: x25519::X25519PubKey,
            recipient: x25519::X25519PubKey,
            data: Arc<crypto_box::CryptoBoxData>,
        ) -> crypto_box::CryptoBoxEncryptedData;

        /// Open crypto box previously generated by recipient keystore index from sender pubkey.
        fn crypto_box_open_by_index(
            keystore_index: KeystoreIndex,
            sender: x25519::X25519PubKey,
            encrypted_data: Arc<crypto_box::CryptoBoxEncryptedData>,
        ) -> Option<crypto_box::CryptoBoxData>;

        /// Open crypto box previously generated by recipient pubkey from sender pubkey.
        fn crypto_box_open_by_pub_key(
            pub_key: x25519::X25519PubKey,
            sender: x25519::X25519PubKey,
            encrypted_data: Arc<crypto_box::CryptoBoxEncryptedData>
        ) -> Option<crypto_box::CryptoBoxData>;
    }
}

/// Lair Client Sender Type.
pub type LairClientSender = futures::channel::mpsc::Sender<LairClientApi>;
