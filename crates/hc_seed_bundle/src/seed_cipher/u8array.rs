use crate::SharedSizedLockedArray;
use one_err::OneErr;
use std::convert::TryFrom;
use std::ops::{Deref, DerefMut};

/// A fixed sized byte array with all the translation and serialization
/// support we need for working with SeedBundles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct U8Array<const N: usize>(pub [u8; N]);

impl<const N: usize> TryFrom<U8Array<N>> for sodoken::SizedLockedArray<N> {
    type Error = OneErr;

    fn try_from(o: U8Array<N>) -> Result<Self, Self::Error> {
        let mut out = sodoken::SizedLockedArray::new()?;
        out.lock().copy_from_slice(&o.0);

        Ok(out)
    }
}

impl<const N: usize> From<[u8; N]> for U8Array<N> {
    fn from(o: [u8; N]) -> Self {
        Self(o)
    }
}

impl<const N: usize> From<sodoken::SizedLockedArray<N>> for U8Array<N> {
    fn from(mut o: sodoken::SizedLockedArray<N>) -> Self {
        (*o.lock()).into()
    }
}

impl<const N: usize> From<SharedSizedLockedArray<N>> for U8Array<N> {
    fn from(o: SharedSizedLockedArray<N>) -> Self {
        (*o.lock().lock()).into()
    }
}

impl<const N: usize> From<Box<[u8]>> for U8Array<N> {
    fn from(o: Box<[u8]>) -> Self {
        // we need to runtime panic when loading from unsized sources
        assert_eq!(o.len(), N);
        let mut out = [0; N];
        out.copy_from_slice(&o[0..N]);
        out.into()
    }
}

impl<const N: usize> From<Vec<u8>> for U8Array<N> {
    fn from(o: Vec<u8>) -> Self {
        o.into_boxed_slice().into()
    }
}

impl<const N: usize> Deref for U8Array<N> {
    type Target = [u8; N];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> DerefMut for U8Array<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const N: usize> AsRef<[u8; N]> for U8Array<N> {
    fn as_ref(&self) -> &[u8; N] {
        self.deref()
    }
}

impl<const N: usize> AsMut<[u8; N]> for U8Array<N> {
    fn as_mut(&mut self) -> &mut [u8; N] {
        self.deref_mut()
    }
}

impl<const N: usize> serde::Serialize for U8Array<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // serialize directly as bytes
        serializer.serialize_bytes(self.deref())
    }
}

impl<'de, const N: usize> serde::Deserialize<'de> for U8Array<N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Unfortunately, by default javascript encodes Uint8Arrays as
        // "ext" fields. We could fix this in our library, but if someone
        // else writes one they may run into this problem. Instead, we
        // can be forgiving and accept "ext" entries as binary data.
        let v: rmpv::Value = serde::Deserialize::deserialize(deserializer)?;
        let v = match v {
            rmpv::Value::Binary(b) => b,
            rmpv::Value::Ext(_, b) => b,
            _ => {
                return Err(serde::de::Error::custom(
                    "invalid type, expected bytes",
                ))
            }
        };
        if v.len() != N {
            return Err(serde::de::Error::custom(format!(
                "expected {} bytes, got {} bytes",
                N,
                v.len()
            )));
        }
        let mut out = [0; N];
        out.copy_from_slice(&v[0..N]);
        Ok(Self(out))
    }
}
