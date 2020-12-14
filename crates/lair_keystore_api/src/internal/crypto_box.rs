use crate::internal::rayon::rayon_exec;
use crate::internal::x25519;
use block_padding::Padding;
use crypto_box as lib_crypto_box;
use std::sync::Arc;

/// Length of the crypto box aead nonce.
/// Ideally this would be exposed from upstream but I didn't see a good way to get at it directly.
pub const NONCE_BYTES: usize = 24;

/// The size of blocks to pad encrypted data to.
/// We have no idea how big incoming data is, but probably it is generally smallish.
/// Devs can always do their own padding on top of this, but we want some safety for unpadded data.
/// Libsodium optionally supports ISO 7816-4 padding algorithm.
/// @see https://doc.libsodium.org/padding#algorithm
pub const BLOCK_PADDING_SIZE: usize = 32;
/// The delimiter for padding as per ISO 7816-4.
pub const BLOCK_PADDING_DELIMITER: u8 = 0x80;

/// Newtype for the nonce for safety.
#[derive(Debug, PartialEq, Clone)]
pub struct CryptoBoxNonce([u8; NONCE_BYTES]);

impl CryptoBoxNonce {
    async fn new_random() -> Self {
        rayon_exec(move || {
            let mut rng = rand::thread_rng();
            let mut bytes = [0; NONCE_BYTES];
            // We rely on the lib_crypto_box nonce length being the same as what we expect.
            // Should be a reasonably safe bet as 24 bytes is dictated by the crypto_box algorithm.
            bytes.copy_from_slice(
                lib_crypto_box::generate_nonce(&mut rng).as_slice(),
            );
            Self(bytes)
        })
        .await
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
        } else {
            Err(crate::error::LairError::CryptoBoxNonceLength)
        }
    }
}

impl CryptoBoxNonce {
    /// Always NONCE_BYTES.
    pub fn len(&self) -> usize {
        NONCE_BYTES
    }

    /// For clippy.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// "Additional associated data" as per the aead rust crate Payload.
/// May be empty. Must be valid if present.
pub struct CryptoBoxAad(Vec<u8>);

/// The nonce and encrypted data together.
/// @todo include additional associated data?
#[derive(Debug, PartialEq, Clone)]
pub struct CryptoBoxEncryptedData {
    /// The nonce generated during encryption.
    /// We never allow nonce to be set externally so we need to return it.
    pub nonce: CryptoBoxNonce,
    /// The encrypted version of our input data.
    #[allow(clippy::rc_buffer)]
    pub encrypted_data: Arc<Vec<u8>>,
}

/// Data to be encrypted.
/// Not associated with a nonce because we enforce random nonces.
#[derive(Debug, PartialEq, Clone)]
pub struct CryptoBoxData {
    /// Data to be encrypted.
    #[allow(clippy::rc_buffer)]
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

    /// For clippy.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl From<Vec<u8>> for CryptoBoxData {
    fn from(v: Vec<u8>) -> Self {
        Self { data: Arc::new(v) }
    }
}

/// @todo all of this can be opened up to be more flexible over time.
/// Eventually all possible input such as nonces and associated data should be settable by the
/// external interface.
/// In the short term everyone is getting their heads around the 80/20 usage patterns that are as
/// safe as we can possibly make them to avoid subtleties that lead to nonce or key re-use etc.
///
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
pub async fn crypto_box(
    sender: x25519::X25519PrivKey,
    recipient: x25519::X25519PubKey,
    data: Arc<CryptoBoxData>,
) -> crate::error::LairResult<CryptoBoxEncryptedData> {
    let nonce = CryptoBoxNonce::new_random().await;
    rayon_exec(move || {
        use lib_crypto_box::aead::Aead;
        let sender_box =
            lib_crypto_box::SalsaBox::new(recipient.as_ref(), sender.as_ref());

        // It's actually easier and clearer to directly pad the vector than use the block_padding
        // crate, as that is optimised for blocks.
        let mut to_encrypt = data.data.to_vec();
        let padding_delimiter = vec![BLOCK_PADDING_DELIMITER];
        let padding = vec![0x0; BLOCK_PADDING_SIZE - (data.data.len() + 1) % BLOCK_PADDING_SIZE];
        to_encrypt.extend(padding_delimiter);
        to_encrypt.extend(padding);

        let encrypted_data = Arc::new(sender_box.encrypt(
            AsRef::<[u8; NONCE_BYTES]>::as_ref(&nonce).into(),
            to_encrypt.as_slice(),
        )?);

        // @todo do we want associated data to enforce the originating DHT space?
        // https://eprint.iacr.org/2019/519.pdf for 'context separable interfaces'
        Ok(CryptoBoxEncryptedData {
            encrypted_data,
            nonce,
        })
    })
    .await
}

/// Wrapper around crypto_box_open from whatever lib we use.
/// Exact inverse of `crypto_box_open` so nonce must be provided in `CryptoBoxEncryptedData`.
/// The recipient's private key encrypts _from_ the sender's pubkey.
pub async fn crypto_box_open(
    recipient: x25519::X25519PrivKey,
    sender: x25519::X25519PubKey,
    encrypted_data: Arc<CryptoBoxEncryptedData>,
) -> crate::error::LairResult<CryptoBoxData> {
    rayon_exec(move || {
        use lib_crypto_box::aead::Aead;
        let recipient_box =
            lib_crypto_box::SalsaBox::new(sender.as_ref(), recipient.as_ref());
        dbg!(&sender, &recipient);
        let decrypted_data = recipient_box.decrypt(
            AsRef::<[u8; NONCE_BYTES]>::as_ref(&encrypted_data.nonce).into(),
            encrypted_data.encrypted_data.as_slice(),
        );
        dbg!(&decrypted_data);
        let data =
            Arc::new(block_padding::Iso7816::unpad(&decrypted_data?)?.to_vec());

        // @todo do we want associated data to enforce the originating DHT space?
        Ok(CryptoBoxData { data })
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(threaded_scheduler)]
    async fn it_can_encrypt_and_decrypt() {

        for input in [
         // Empty vec.
         vec![],
         // Small vec.
         vec![0],
         vec![0, 1, 2],
         vec![0, 1, 2, 3],
         // Vec ending in padding delimiter.
         vec![0x80],
         vec![0, 0x80],
         vec![0x80; BLOCK_PADDING_SIZE - 1],
         vec![0x80; BLOCK_PADDING_SIZE],
         vec![0x80; BLOCK_PADDING_SIZE + 1],
         // Larger vec.
         vec![0; BLOCK_PADDING_SIZE - 1],
         vec![0; BLOCK_PADDING_SIZE],
         vec![0; BLOCK_PADDING_SIZE + 1],
         vec![0; BLOCK_PADDING_SIZE * 2 - 1],
         vec![0; BLOCK_PADDING_SIZE * 2],
         vec![0; BLOCK_PADDING_SIZE * 2 + 1],
        ].iter() {
            // Fresh keys.
            let alice = crate::internal::x25519::x25519_keypair_new_from_entropy().await.unwrap();
            let bob = crate::internal::x25519::x25519_keypair_new_from_entropy().await.unwrap();

            let data = CryptoBoxData{ data: Arc::new(input.to_vec()) };

            // from alice to bob.
            let encrypted_data = super::crypto_box(alice.priv_key, bob.pub_key, Arc::new(data.clone())).await.unwrap();

            // The length excluding the 16 byte overhead should always be a multiple of 32 as this
            // is our padding.
            assert_eq!((encrypted_data.encrypted_data.len() - 16) % 32, 0);

            let decrypted_data = super::crypto_box_open(bob.priv_key, alice.pub_key, Arc::new(encrypted_data)).await.unwrap();

            // If we can decrypt we managed to pad and unpad as well as encrypt and decrypt.
            assert_eq!(&decrypted_data, &data);
        }
    }
}
