//! X25519 ECDH utilities
//! NOTE - underlying lib subject to change in the future, although the algorithm should be stable.

use crate::*;
use derive_more::*;
use crypto_box as lib_crypto_box;

/// Length of an x25519 private key in bytes.
pub const PRIV_KEY_BYTES: usize = lib_crypto_box::KEY_SIZE;

/// Length of an x25519 public key in bytes.
pub const PUB_KEY_BYTES: usize = lib_crypto_box::KEY_SIZE;

/// Newtype for the private key.
// Almost all these derives seem dangerous to me...
// @todo Do we really need to be cloning and debugging secrets?
#[derive(Debug, Clone, Deref, From, Into)]
pub struct X25519PrivKey(lib_crypto_box::SecretKey);

/// @todo Do we really need to be comparing secrets?
impl PartialEq for X25519PrivKey {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.to_bytes().ct_eq(&other.to_bytes()).into()
    }
}

impl Eq for X25519PrivKey { }

impl From<[u8; PRIV_KEY_BYTES]> for X25519PrivKey {
    fn from(bytes: [u8; PRIV_KEY_BYTES]) -> Self {
        Self(bytes.into())
    }
}

impl AsRef<lib_crypto_box::SecretKey> for X25519PrivKey {
    fn as_ref(&self) -> &lib_crypto_box::SecretKey {
        &self.0
    }
}

impl X25519PrivKey {
    /// Wrapper around internal to_bytes() from upstream.
    pub fn to_bytes(&self) -> [u8; PRIV_KEY_BYTES] {
        self.0.to_bytes()
    }
}

impl core::convert::TryFrom<&[u8]> for X25519PrivKey {
    type Error = crate::error::LairError;
    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        if slice.len() == PRIV_KEY_BYTES {
            let mut inner = [0; PRIV_KEY_BYTES];
            inner.copy_from_slice(slice);
            Ok(Self::from(inner))
        }
        else {
            Err(crate::error::LairError::X25519PrivKeyLength)
        }
    }
}

/// @todo Do we really need to be ordering secrets?
impl PartialOrd for X25519PrivKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        // @todo i assume there is a timing attack here?
        self.to_bytes().partial_cmp(&other.to_bytes())
    }
}

/// @todo Do we really need to be ordering secrets?
impl Ord for X25519PrivKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // @todo i assume there is a timing attack here?
        self.to_bytes().cmp(&other.to_bytes())
    }
}

/// @todo Is hashing secrets a problem?
impl core::hash::Hash for X25519PrivKey {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state)
    }
}

/// Newtype for the public key.
#[derive(
    Clone, Debug, Deref, From, Into
)]
pub struct X25519PubKey(lib_crypto_box::PublicKey);

impl From<[u8; PUB_KEY_BYTES]> for X25519PubKey {
    fn from(bytes: [u8; PUB_KEY_BYTES]) -> Self {
        Self(bytes.into())
    }
}

impl core::convert::TryFrom<&[u8]> for X25519PubKey {
    type Error = crate::error::LairError;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() == PUB_KEY_BYTES {
            let mut inner = [0; PUB_KEY_BYTES];
            inner.copy_from_slice(bytes);
            Ok(inner.into())
        }
        else {
            Err(crate::error::LairError::X25519PubKeyLength)
        }
    }
}

impl AsRef<lib_crypto_box::PublicKey> for X25519PubKey {
    fn as_ref(&self) -> &lib_crypto_box::PublicKey {
        &self.0
    }
}

impl AsRef<[u8; PUB_KEY_BYTES]> for X25519PubKey {
    fn as_ref(&self) -> &[u8; PUB_KEY_BYTES] {
        &self.0.as_bytes()
    }
}

impl AsRef<[u8]> for X25519PubKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl PartialEq for X25519PubKey {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl Eq for X25519PubKey { }

impl PartialOrd for X25519PubKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.to_bytes().partial_cmp(&other.to_bytes())
    }
}

impl Ord for X25519PubKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.to_bytes().cmp(&other.to_bytes())
    }
}

impl core::hash::Hash for X25519PubKey {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state)
    }
}

/// Generate a new random x25519 keypair.
pub async fn x25519_keypair_new_from_entropy() -> LairResult<entry::EntryX25519> {
    rayon_exec(move || {
        // This is fine _for use with the `crypto_box` crate_ because they specify the `CryptoRng`
        // trait on the `generate()` method below.
        // @see https://docs.rs/crypto_box/0.5.0/crypto_box/struct.SecretKey.html
        let mut rng = rand::thread_rng();

        // @todo this could be dangerous as it's exposed as a general purpose authenticated
        // encryption mechanism (or will be) via. crypto_box from libsodium.
        // The main thing is that if a secret/nonce combination is _ever_ used more than once it
        // completely breaks encryption.
        //
        // Example ways a nonce could accidentally be reused:
        // - If two DNAs are the same or similar (e.g. cloned DNAs) then they will have the same
        //   nonce generation logic, so may create collisions when run in parallel.
        // - Collision of initialization vectors in a key exchange/crypto session.
        // - Use of a counter based nonce in a way that isn't 100% reliably incrementing.
        //
        // Example ways a secret could accidentally be reused:
        // - If two agents both commit their pubkeys then share them with each other, then the same
        //   shared key will be 'negotiated' by x25519 ECDH every time it is called.
        // - If a pubkey is used across two different DNAs the secrets will collide at the lair
        //   and the DNAs won't have a way to co-ordinate or detect this.
        //
        // ring is very wary of secret key re-use e.g. it mandates the use-case where an
        // ephemeral (single use) key is generated to establish an ephemeral (single use) shared
        // key. Our use-case is the libsodium `crypto_box` function that uses an x25519 keypair to
        // perform authenticated encryption, so it makes more sense for us to be storing our
        // private keys for later use BUT see above for the dangers of key re-use that the app dev
        // really needs to be wary of.
        //
        // e.g. ring enforces pairwise agreements.
        // > An ephemeral private key for use (only) with agree_ephemeral. The signature of
        // > agree_ephemeral ensures that an EphemeralPrivateKey can be used for at most one key
        // > agreement.
        //
        // @see https://eprint.iacr.org/2019/519.pdf for 'context separable interfaces'
        // @see https://briansmith.org/rustdoc/ring/agreement/index.html#example
        let priv_key = crypto_box::SecretKey::generate(&mut rng);

        Ok(entry::EntryX25519 {
            pub_key: priv_key.public_key().into(),
            priv_key: priv_key.into(),
        })
    })
    .await
}
