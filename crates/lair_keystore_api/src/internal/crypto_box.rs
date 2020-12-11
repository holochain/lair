use std::sync::Arc;
use crypto_box as lib_crypto_box;
use crate::internal::x25519;

/// Length of the crypto box aead nonce.
/// Ideally this would be exposed from upstream but I didn't see a good way to get at it directly.
pub const NONCE_BYTES: usize = 24;

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
#[derive(Debug, PartialEq)]
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
pub fn crypto_box(sender: x25519::X25519PrivKey, recipient: x25519::X25519PubKey, data: Arc<CryptoBoxData>) -> crate::error::LairResult<CryptoBoxEncryptedData> {
    use lib_crypto_box::aead::Aead;
    let sender_box = lib_crypto_box::SalsaBox::new(recipient.as_ref(), sender.as_ref());
    let nonce = CryptoBoxNonce::new_random();

    // @todo do we want associated data to enforce the originating DHT space?
    Ok(CryptoBoxEncryptedData {
        encrypted_data: Arc::new(sender_box.encrypt(AsRef::<[u8; NONCE_BYTES]>::as_ref(&nonce).into(), (*data).as_ref())?),
        nonce,
    })
}

/// Wrapper around crypto_box_open from whatever lib we use.
/// Exact inverse of `crypto_box_open` so nonce must be provided in `CryptoBoxEncryptedData`.
/// The recipient's private key encrypts _from_ the sender's pubkey.
pub fn crypto_box_open(recipient: x25519::X25519PrivKey, sender: x25519::X25519PubKey, encrypted_data: Arc<CryptoBoxEncryptedData>) -> crate::error::LairResult<CryptoBoxData> {
    use lib_crypto_box::aead::Aead;
    let recipient_box = lib_crypto_box::SalsaBox::new(sender.as_ref(), recipient.as_ref());

    // @todo do we want associated data to enforce the originating DHT space?
    Ok(CryptoBoxData {
        data: Arc::new(
            recipient_box.decrypt(AsRef::<[u8; NONCE_BYTES]>::as_ref(&encrypted_data.nonce).into(), encrypted_data.encrypted_data.as_slice())?
        ),
    })
}
