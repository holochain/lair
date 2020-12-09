//! X25519 ECDH utilities
//! NOTE - underlying lib subject to change in the future, although the algorithm should be stable.

use crate::*;
use std::sync::Arc;
use derive_more::*;

/// Length of an x25519 private key in bytes.
pub const PRIV_KEY_BYTES: usize = 32;

/// Length of an x25519 public key in bytes.
pub const PUB_KEY_BYTES: usize = 32;

/// Newtype for the private key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deref, From, Into)]
pub struct X25519PrivKey(pub Arc<Vec<u8>>);

impl From<Vec<u8>> for X25519PrivKey {
    fn from(d: Vec<u8>) -> Self {
        Self(Arc::new(d))
    }
}

/// Newtype for the public key.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Deref, From, Into
)]
pub struct X25519PubKey(pub Arc<Vec<u8>>);

impl From<Vec<u8>> for X25519PubKey {
    fn from(d: Vec<u8>) -> Self {
        Self(Arc::new(d))
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
            priv_key: priv_key.to_bytes().to_vec().into(),
            pub_key: priv_key.public_key().as_bytes().to_vec().into(),
        })
    })
    .await
}
