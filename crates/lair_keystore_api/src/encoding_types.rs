//! Helper types for dealing with serialization.

use crate::*;
use base64::Engine;
use parking_lot::Mutex;
use std::sync::Arc;

fn to_base64_url<B: AsRef<[u8]>>(b: B) -> String {
    base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(b.as_ref())
}

fn from_base64_url<S: AsRef<str>>(s: S) -> LairResult<Arc<[u8]>> {
    base64::prelude::BASE64_URL_SAFE_NO_PAD
        .decode(s.as_ref())
        .map_err(one_err::OneErr::new)
        .map(|b| b.into())
}

/// Wrapper newtype for serde encoding / decoding binary data.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BinData(pub Arc<[u8]>);

impl std::fmt::Debug for BinData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = to_base64_url(&*self.0);
        f.debug_tuple("BinData").field(&s).finish()
    }
}

impl std::fmt::Display for BinData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = to_base64_url(&*self.0);
        f.write_str(&s)
    }
}

impl std::str::FromStr for BinData {
    type Err = one_err::OneErr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        from_base64_url(s).map(Self)
    }
}

impl BinData {
    /// Get a clone of our inner Arc<[u8]>
    pub fn cloned_inner(&self) -> Arc<[u8]> {
        self.0.clone()
    }
}

impl From<Box<[u8]>> for BinData {
    fn from(b: Box<[u8]>) -> Self {
        Self(b.into())
    }
}

impl From<Arc<[u8]>> for BinData {
    fn from(b: Arc<[u8]>) -> Self {
        Self(b)
    }
}

impl std::ops::Deref for BinData {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl serde::Serialize for BinData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = to_base64_url(&*self.0);
        serializer.serialize_str(&s)
    }
}

impl<'de> serde::Deserialize<'de> for BinData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let tmp: String = serde::Deserialize::deserialize(deserializer)?;
        from_base64_url(tmp)
            .map_err(serde::de::Error::custom)
            .map(Self)
    }
}

/// Wrapper newtype for serde encoding / decoding sized binary data.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BinDataSized<const N: usize>(pub Arc<[u8; N]>);

impl<const N: usize> std::fmt::Debug for BinDataSized<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = to_base64_url(*self.0);
        write!(f, "BinDataSized<{N}>({s})")
    }
}

impl<const N: usize> std::fmt::Display for BinDataSized<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = to_base64_url(*self.0);
        f.write_str(&s)
    }
}

impl<const N: usize> std::str::FromStr for BinDataSized<N> {
    type Err = one_err::OneErr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let tmp = from_base64_url(s)?;
        if tmp.len() != N {
            return Err(one_err::OneErr::new("invalid buffer length"));
        }
        let mut out = [0; N];
        out.copy_from_slice(&tmp);
        Ok(Self(Arc::new(out)))
    }
}

impl<const N: usize> BinDataSized<N> {
    /// Get a clone of our inner Arc<[u8; N]>
    pub fn cloned_inner(&self) -> Arc<[u8; N]> {
        self.0.clone()
    }
}

impl<const N: usize> From<[u8; N]> for BinDataSized<N> {
    fn from(b: [u8; N]) -> Self {
        Self(Arc::new(b))
    }
}

impl<const N: usize> From<Arc<[u8; N]>> for BinDataSized<N> {
    fn from(b: Arc<[u8; N]>) -> Self {
        Self(b)
    }
}

impl<const N: usize> std::ops::Deref for BinDataSized<N> {
    type Target = [u8; N];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> serde::Serialize for BinDataSized<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = to_base64_url(*self.0);
        serializer.serialize_str(&s)
    }
}

impl<'de, const N: usize> serde::Deserialize<'de> for BinDataSized<N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let tmp: String = serde::Deserialize::deserialize(deserializer)?;
        let tmp = from_base64_url(tmp).map_err(serde::de::Error::custom)?;
        if tmp.len() != N {
            return Err(serde::de::Error::custom("invalid buffer length"));
        }
        let mut out = [0; N];
        out.copy_from_slice(&tmp);
        Ok(Self(Arc::new(out)))
    }
}

impl BinDataSized<32> {
    /// Treat this bin data as an ed25519 public key,
    /// and use it to verify a signature over a given message.
    pub async fn verify_detached(
        &self,
        signature: BinDataSized<64>,
        message: Arc<[u8]>,
    ) -> LairResult<bool> {
        sodoken::sign::verify_detached(
            &signature.cloned_inner(),
            &message,
            &self.0,
        )
        .await
    }
}

/// Secret data. Encrypted with sodium secretstream.
/// The key used to encrypt / decrypt is context dependent.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SecretData(
    // the secretstream header
    pub BinDataSized<24>,
    // the secretstream cipher data
    pub BinData,
);

impl SecretData {
    /// Encrypt some data as a 'SecretData' object with given context key.
    pub async fn encrypt(
        mut key: Arc<Mutex<sodoken::SizedLockedArray<32>>>,
        data: Arc<[u8]>,
    ) -> LairResult<Self> {
        let mut header = sodoken::SizedLockedArray::<
            { sodoken::secretstream::HEADERBYTES },
        >::new()?;
        let mut cipher = sodoken::LockedArray::new(
            data.len() + sodoken::secretstream::ABYTES,
        )?;

        let mut enc = sodoken::secretstream::State::default();
        sodoken::secretstream::init_push(
            &mut enc,
            &mut header.lock(),
            &key.lock().lock(),
        )?;

        sodoken::secretstream::push(
            &mut enc,
            &mut cipher.lock(),
            &data,
            None,
            sodoken::secretstream::Tag::Final,
        )?;

        Ok(Self(header.lock().into(), cipher.lock().into()))
    }

    /// Decrypt some data as a 'SecretData' object with given context key.
    pub async fn decrypt(
        &self,
        mut key: sodoken::SizedLockedArray<32>,
    ) -> LairResult<sodoken::LockedArray> {
        let mut dec = sodoken::secretstream::State::default();
        sodoken::secretstream::init_pull(&mut dec, &self.0, &key.lock())?;

        let mut out = sodoken::LockedArray::new(
            self.1.len() - sodoken::secretstream::ABYTES,
        )?;
        sodoken::secretstream::pull(&mut dec, &mut out.lock(), &self.1, None)?;

        Ok(out)
    }
}

/// Sized secret data. Encrypted with sodium secretstream.
/// The key used to encrypt / decrypt is context dependent.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SecretDataSized<const M: usize, const C: usize>(
    // the secretstream header
    pub BinDataSized<24>,
    // the secretstream cipher data
    pub BinDataSized<C>,
);

impl<const M: usize, const C: usize> SecretDataSized<M, C> {
    /// Encrypt some data as a 'SecretDataSized' object with given context key.
    pub async fn encrypt(
        mut key: Arc<Mutex<sodoken::SizedLockedArray<32>>>,
        mut data: sodoken::SizedLockedArray<M>,
    ) -> LairResult<Self> {
        let mut header = sodoken::SizedLockedArray::<
            { sodoken::secretstream::HEADERBYTES },
        >::new()?;
        let mut cipher = sodoken::SizedLockedArray::<
            { sodoken::secretstream::KEYBYTES },
        >::new()?;
        let mut enc = sodoken::secretstream::State::default();
        sodoken::secretstream::init_push(
            &mut enc,
            &mut header.lock(),
            &key.lock().lock(),
        )?;

        sodoken::secretstream::push(
            &mut enc,
            &mut cipher.lock(),
            &data.lock(),
            None,
            sodoken::secretstream::Tag::Final,
        )?;

        Ok(Self(header.lock().into(), cipher.into()))
    }

    /// Decrypt some data as a 'SecretDataSized' object with given context key.
    pub async fn decrypt(
        &self,
        mut key: sodoken::SizedLockedArray<32>,
    ) -> LairResult<sodoken::SizedLockedArray<M>> {
        let mut header = sodoken::SizedLockedArray::<24>::new()?;
        header.lock().copy_from_slice(&self.0.cloned_inner());

        let mut cipher = sodoken::SizedLockedArray::<C>::new()?;
        cipher.lock().copy_from_slice(&self.1.cloned_inner());

        let mut state = sodoken::secretstream::State::default();
        sodoken::secretstream::init_pull(
            &mut state,
            &header.lock(),
            &key.lock(),
        )?;

        let mut out = sodoken::SizedLockedArray::<M>::new()?;
        sodoken::secretstream::pull(
            &mut state,
            &mut out.lock(),
            &cipher.lock(),
            None,
        )
        .await?;

        Ok(out)
    }
}

/// Ed25519 signature public key derived from this seed.
pub type Ed25519PubKey = BinDataSized<32>;

/// Ed25519 signature bytes.
pub type Ed25519Signature = BinDataSized<64>;

/// X25519 encryption public key derived from this seed.
pub type X25519PubKey = BinDataSized<32>;
