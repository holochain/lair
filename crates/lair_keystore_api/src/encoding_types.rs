//! Helper types for dealing with serialization.

use crate::*;
use sodoken::secretstream::xchacha20poly1305 as sss;
use std::sync::Arc;

fn to_base64_url<B: AsRef<[u8]>>(b: B) -> String {
    base64::encode_config(b.as_ref(), base64::URL_SAFE_NO_PAD)
}

fn from_base64_url<S: AsRef<str>>(s: S) -> LairResult<Arc<[u8]>> {
    base64::decode_config(s.as_ref(), base64::URL_SAFE_NO_PAD)
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
        &*self.0
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
        from_base64_url(&tmp)
            .map_err(serde::de::Error::custom)
            .map(Self)
    }
}

/// Wrapper newtype for serde encoding / decoding sized binary data.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BinDataSized<const N: usize>(pub Arc<[u8; N]>);

impl<const N: usize> std::fmt::Debug for BinDataSized<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = to_base64_url(&*self.0);
        write!(f, "BinDataSized<{}>({})", N, s)
    }
}

impl<const N: usize> std::fmt::Display for BinDataSized<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = to_base64_url(&*self.0);
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
        &*self.0
    }
}

impl<const N: usize> serde::Serialize for BinDataSized<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = to_base64_url(&*self.0);
        serializer.serialize_str(&s)
    }
}

impl<'de, const N: usize> serde::Deserialize<'de> for BinDataSized<N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let tmp: String = serde::Deserialize::deserialize(deserializer)?;
        let tmp = from_base64_url(&tmp).map_err(serde::de::Error::custom)?;
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
    pub async fn verify_detached<M>(
        &self,
        signature: BinDataSized<64>,
        message: M,
    ) -> LairResult<bool>
    where
        M: Into<sodoken::BufRead> + 'static + Send,
    {
        let pub_key = sodoken::BufReadSized::from(self.0.clone());
        sodoken::sign::verify_detached(
            signature.cloned_inner(),
            message,
            pub_key,
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
        key: sodoken::BufReadSized<32>,
        data: sodoken::BufRead,
    ) -> LairResult<Self> {
        let header =
            <sodoken::BufWriteSized<{ sss::HEADERBYTES }>>::new_no_lock();
        let cipher = sodoken::BufExtend::new_no_lock(data.len() + sss::ABYTES);
        let mut enc = sss::SecretStreamEncrypt::new(key, header.clone())?;
        enc.push_final(data, <Option<sodoken::BufRead>>::None, cipher.clone())
            .await?;

        let header = header.try_unwrap_sized().unwrap();

        let cipher_r = cipher.to_read();
        drop(cipher);
        let cipher_r = cipher_r.try_unwrap().unwrap();

        Ok(Self(header.into(), cipher_r.into()))
    }

    /// Decrypt some data as a 'SecretData' object with given context key.
    pub async fn decrypt(
        &self,
        key: sodoken::BufReadSized<32>,
    ) -> LairResult<sodoken::BufRead> {
        let header = sodoken::BufReadSized::from(self.0.cloned_inner());
        let cipher = sodoken::BufRead::from(self.1.cloned_inner());
        let mut dec = sss::SecretStreamDecrypt::new(key, header)?;
        let out =
            sodoken::BufWrite::new_mem_locked(cipher.len() - sss::ABYTES)?;
        dec.pull(cipher, <Option<sodoken::BufRead>>::None, out.clone())
            .await?;
        Ok(out.to_read())
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
        key: sodoken::BufReadSized<32>,
        data: sodoken::BufReadSized<M>,
    ) -> LairResult<Self> {
        let header =
            <sodoken::BufWriteSized<{ sss::HEADERBYTES }>>::new_no_lock();
        let cipher = sodoken::BufWriteSized::new_no_lock();
        let mut enc = sss::SecretStreamEncrypt::new(key, header.clone())?;
        enc.push_final(data, <Option<sodoken::BufRead>>::None, cipher.clone())
            .await?;

        let header = header.try_unwrap_sized().unwrap();
        let cipher = cipher.try_unwrap_sized().unwrap();

        Ok(Self(header.into(), cipher.into()))
    }

    /// Decrypt some data as a 'SecretDataSized' object with given context key.
    pub async fn decrypt(
        &self,
        key: sodoken::BufReadSized<32>,
    ) -> LairResult<sodoken::BufReadSized<M>> {
        let header = sodoken::BufReadSized::from(self.0.cloned_inner());
        let cipher = sodoken::BufReadSized::from(self.1.cloned_inner());
        let mut dec = sss::SecretStreamDecrypt::new(key, header)?;
        let out = sodoken::BufWriteSized::new_mem_locked()?;
        dec.pull(cipher, <Option<sodoken::BufRead>>::None, out.clone())
            .await?;
        Ok(out.to_read_sized())
    }
}

/// Ed25519 signature public key derived from this seed.
pub type Ed25519PubKey = BinDataSized<32>;

/// Ed25519 signature bytes.
pub type Ed25519Signature = BinDataSized<64>;

/// X25519 encryption public key derived from this seed.
pub type X25519PubKey = BinDataSized<32>;
