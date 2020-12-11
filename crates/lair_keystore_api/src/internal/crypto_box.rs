use std::sync::Arc;
use crypto_box as lib_crypto_box;
use crate::internal::x25519;
use block_padding::Padding;

/// Length of the crypto box aead nonce.
/// Ideally this would be exposed from upstream but I didn't see a good way to get at it directly.
pub const NONCE_BYTES: usize = 24;

/// The size of blocks to pad encrypted data to.
/// We have no idea how big incoming data is, but probably it is generally smallish.
/// Devs can always do their own padding on top of this, but we want some safety for unpadded data.
/// Libsodium optionally supports ISO 7816-4 padding algorithm.
/// @see https://doc.libsodium.org/padding#algorithm
pub const BLOCK_PADDING_SIZE: usize = 32;

/// Newtype for the nonce for safety.
#[derive(Debug, PartialEq)]
pub struct CryptoBoxNonce([u8; NONCE_BYTES]);

impl CryptoBoxNonce {
    fn new_random() -> Self {
        let mut rng = rand::thread_rng();
        let mut bytes = [0; NONCE_BYTES];
        // We rely on the lib_crypto_box nonce length being the same as what we expect.
        // Should be a reasonably safe bet as 24 bytes is dictated by the crypto_box algorithm.
        bytes.copy_from_slice(
            lib_crypto_box::generate_nonce(&mut rng).as_slice()
        );
        Self(bytes)
    }
}

impl AsRef<[u8; NONCE_BYTES]> for CryptoBoxNonce {
    fn as_ref(&self) -> &[u8; NONCE_BYTES] {
        &self.0
    }
}

impl AsRef<[u8]> for CryptoBoxNonce {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; NONCE_BYTES]> for CryptoBoxNonce {
    fn from(array: [u8; NONCE_BYTES]) -> Self {
        Self(array)
    }
}

impl std::convert::TryFrom<&[u8]> for CryptoBoxNonce {
    type Error = crate::error::LairError;
    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        if slice.len() == NONCE_BYTES {
            let mut inner = [0; NONCE_BYTES];
            inner.copy_from_slice(slice);
            Ok(Self(inner))
        }
        else {
            Err(crate::error::LairError::CryptoBoxNonceLength)
        }
    }
}

impl CryptoBoxNonce {
    /// Always NONCE_BYTES.
    pub fn len(&self) -> usize {
        NONCE_BYTES
    }
}

/// "Additional associated data" as per the aead rust crate Payload.
/// May be empty. Must be valid if present.
pub struct CryptoBoxAad(Vec<u8>);

/// The nonce and encrypted data together.
/// @todo include additional associated data?
#[derive(Debug, PartialEq)]
pub struct CryptoBoxEncryptedData {
    /// The nonce generated during encryption.
    /// We never allow nonce to be set externally so we need to return it.
    pub nonce: CryptoBoxNonce,
    /// The encrypted version of our input data.
    pub encrypted_data: Arc<Vec<u8>>,
}

/// Data to be encrypted.
/// Not associated with a nonce because we enforce random nonces.
#[derive(Debug, PartialEq, Clone)]
pub struct CryptoBoxData {
    /// Data to be encrypted.
    pub data: Arc<Vec<u8>>,
}

impl AsRef<[u8]> for CryptoBoxData {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl CryptoBoxData {
    /// Length of newtype is length of inner.
    pub fn len(&self) -> usize {
        AsRef::<[u8]>::as_ref(self).len()
    }
}

impl From<Vec<u8>> for CryptoBoxData {
    fn from(v: Vec<u8>) -> Self {
        Self {
            data: Arc::new(v)
        }
    }
}

/// Wrapper around crypto_box from whatever lib we use.
/// No BYO nonces. Nonces always random and returned as part of `CryptoBoxEncryptedData`.
/// No BYO algorithms (cipher agility). Algorithm always X25519XSalsa20Poly1305.
/// Currently no additional associated data but DNA space may be included in the future.
/// The sender's private key encrypts _for_ the recipient's pubkey.
///
/// FYI allowing nonces could be dangerous as it's exposed as a general purpose authenticated
/// encryption mechanism (or will be) via. crypto_box from libsodium.
/// The main thing is that if a secret/nonce combination is _ever_ used more than once it
/// completely breaks encryption.
//
/// Example ways a nonce could accidentally be reused:
/// - If two DNAs are the same or similar (e.g. cloned DNAs) then they will have the same
///   nonce generation logic, so may create collisions when run in parallel.
/// - Collision of initialization vectors in a key exchange/crypto session.
/// - Use of a counter based nonce in a way that isn't 100% reliably incrementing.
///
/// Example ways a secret could accidentally be reused:
/// - If two agents both commit their pubkeys then share them with each other, then the same
///   shared key will be 'negotiated' by x25519 ECDH every time it is called.
/// - If a pubkey is used across two different DNAs the secrets will collide at the lair
///   and the DNAs won't have a way to co-ordinate or detect this.
///
/// E.g. Ring is very wary of secret key re-use e.g. it makes explicit the use-case where an
/// ephemeral (single use) key is generated to establish an ephemeral (single use) shared
/// key. Our use-case is the libsodium `crypto_box` function that uses an x25519 keypair to
/// perform authenticated encryption, so it makes more sense for us to be storing our
/// private keys for later use BUT see above for the dangers of key re-use that the app dev
/// really needs to be wary of.
///
/// @see https://eprint.iacr.org/2019/519.pdf for 'context separable interfaces'
pub fn crypto_box(sender: x25519::X25519PrivKey, recipient: x25519::X25519PubKey, data: Arc<CryptoBoxData>) -> crate::error::LairResult<CryptoBoxEncryptedData> {
    use lib_crypto_box::aead::Aead;
    let sender_box = lib_crypto_box::SalsaBox::new(recipient.as_ref(), sender.as_ref());
    let nonce = CryptoBoxNonce::new_random();

    let mut padded_data = data.data.to_vec();
    block_padding::Iso7816::pad_block(&mut padded_data, BLOCK_PADDING_SIZE)?;

    let encrypted_data = Arc::new(sender_box.encrypt(AsRef::<[u8; NONCE_BYTES]>::as_ref(&nonce).into(), padded_data.as_slice())?);

    // @todo do we want associated data to enforce the originating DHT space?
    // https://eprint.iacr.org/2019/519.pdf for 'context separable interfaces'
    Ok(CryptoBoxEncryptedData {
        encrypted_data,
        nonce,
    })
}

/// Wrapper around crypto_box_open from whatever lib we use.
/// Exact inverse of `crypto_box_open` so nonce must be provided in `CryptoBoxEncryptedData`.
/// The recipient's private key encrypts _from_ the sender's pubkey.
pub fn crypto_box_open(recipient: x25519::X25519PrivKey, sender: x25519::X25519PubKey, encrypted_data: Arc<CryptoBoxEncryptedData>) -> crate::error::LairResult<CryptoBoxData> {
    use lib_crypto_box::aead::Aead;
    let recipient_box = lib_crypto_box::SalsaBox::new(sender.as_ref(), recipient.as_ref());
    let decrypted_data = recipient_box.decrypt(AsRef::<[u8; NONCE_BYTES]>::as_ref(&encrypted_data.nonce).into(), encrypted_data.encrypted_data.as_slice())?;
    let data = Arc::new(block_padding::Iso7816::unpad(&decrypted_data)?.to_vec());

    // @todo do we want associated data to enforce the originating DHT space?
    Ok(CryptoBoxData {
        data,
    })
}
