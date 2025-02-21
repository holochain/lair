//! Helper types for dealing with serialization.

use crate::types::{SharedLockedArray, SharedSizedLockedArray};
use crate::*;
use base64::Engine;
use one_err::OneErr;
use std::convert::TryInto;
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
    ) -> bool {
        sodoken::sign::verify_detached(
            &signature.cloned_inner(),
            &message,
            &self.0,
        )
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
    /// Encrypt some secret data as a 'SecretData' object with given context key.
    pub async fn encrypt(
        key: SharedSizedLockedArray<32>,
        data: SharedLockedArray,
    ) -> LairResult<Self> {
        tokio::task::spawn_blocking(move || {
            let mut data_guard = data.lock();
            let data_lock = data_guard.lock();
            let mut header = [0; sodoken::secretstream::HEADERBYTES];
            let mut cipher =
                vec![0; data_lock.len() + sodoken::secretstream::ABYTES];

            let mut enc = sodoken::secretstream::State::default();
            sodoken::secretstream::init_push(
                &mut enc,
                &mut header,
                &key.lock().lock(),
            )?;

            sodoken::secretstream::push(
                &mut enc,
                &mut cipher,
                &data_lock,
                None,
                sodoken::secretstream::Tag::Final,
            )?;

            Ok(Self(header.into(), cipher.into_boxed_slice().into()))
        })
        .await
        .map_err(OneErr::new)?
    }

    /// Decrypt some data as a 'SecretData' object with given context key.
    pub async fn decrypt(
        &self,
        key: SharedSizedLockedArray<32>,
    ) -> LairResult<sodoken::LockedArray> {
        let header = self.0.clone();
        let data = self.1.clone();

        tokio::task::spawn_blocking(move || {
            let mut dec = sodoken::secretstream::State::default();
            sodoken::secretstream::init_pull(
                &mut dec,
                &header,
                &key.lock().lock(),
            )?;

            let mut out = sodoken::LockedArray::new(
                data.len() - sodoken::secretstream::ABYTES,
            )?;
            sodoken::secretstream::pull(
                &mut dec,
                &mut out.lock(),
                &data,
                None,
            )?;

            Ok(out)
        })
        .await
        .map_err(OneErr::new)?
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
        key: SharedSizedLockedArray<32>,
        data: SharedSizedLockedArray<M>,
    ) -> LairResult<Self> {
        let mut header = [0; sodoken::secretstream::HEADERBYTES];
        let mut cipher =
            vec![0; data.lock().lock().len() + sodoken::secretstream::ABYTES];
        let mut enc = sodoken::secretstream::State::default();
        sodoken::secretstream::init_push(
            &mut enc,
            &mut header,
            &key.lock().lock(),
        )?;

        sodoken::secretstream::push(
            &mut enc,
            cipher.as_mut_slice(),
            &*data.lock().lock(),
            None,
            sodoken::secretstream::Tag::Final,
        )?;

        let cipher: [u8; C] = cipher.try_into().map_err(|_| {
            OneErr::new("cipher data length does not match expected size")
        })?;
        Ok(Self(header.into(), cipher.into()))
    }

    /// Decrypt some data as a 'SecretDataSized' object with given context key.
    pub async fn decrypt(
        &self,
        key: SharedSizedLockedArray<32>,
    ) -> LairResult<sodoken::SizedLockedArray<M>> {
        let header = self.0.clone();
        let cipher = self.1.clone();

        tokio::task::spawn_blocking(move || {
            let mut state = sodoken::secretstream::State::default();
            sodoken::secretstream::init_pull(
                &mut state,
                &header,
                &key.lock().lock(),
            )?;

            let mut out = sodoken::SizedLockedArray::<M>::new()?;
            sodoken::secretstream::pull(
                &mut state,
                &mut *out.lock(),
                cipher.as_slice(),
                None,
            )?;

            Ok(out)
        })
        .await
        .map_err(OneErr::new)?
    }
}

/// Ed25519 signature public key derived from this seed.
pub type Ed25519PubKey = BinDataSized<32>;

/// Ed25519 signature bytes.
pub type Ed25519Signature = BinDataSized<64>;

/// X25519 encryption public key derived from this seed.
pub type X25519PubKey = BinDataSized<32>;
