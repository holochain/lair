use futures::future::{BoxFuture, FutureExt};
use sodoken::{SodokenError, SodokenResult};
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

/// serde doesn't auto-derive for this byte count
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct U8Array<const N: usize>(pub [u8; N]);

impl<const N: usize> From<U8Array<N>> for sodoken::BufReadSized<N> {
    fn from(o: U8Array<N>) -> Self {
        o.0.into()
    }
}

impl<const N: usize> From<[u8; N]> for U8Array<N> {
    fn from(o: [u8; N]) -> Self {
        Self(o)
    }
}

impl<const N: usize> From<sodoken::BufWriteSized<N>> for U8Array<N> {
    fn from(o: sodoken::BufWriteSized<N>) -> Self {
        (*o.read_lock_sized()).into()
    }
}

impl<const N: usize> From<Box<[u8]>> for U8Array<N> {
    fn from(o: Box<[u8]>) -> Self {
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
        serializer.serialize_bytes(self.deref())
    }
}

impl<'de, const N: usize> serde::Deserialize<'de> for U8Array<N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v: Box<[u8]> = serde::Deserialize::deserialize(deserializer)?;
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

/// Encrypted ("locked") SeedCipher encoding.
/// This has to be struct type so we can at least name unhandled variants.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
struct SeedCipher {
    /// the cipher type name, required
    r#type: Box<str>,

    /// pure entropy salt
    salt: Option<U8Array<16>>,

    /// secretstream header for encrypted seed
    seed_cipher_header: Option<U8Array<24>>,

    /// secretstream "final" tagged msg for encrypted seed
    seed_cipher: Option<U8Array<49>>,
}

/// Encrypted ("locked") SeedBundle encoding.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct SeedBundle {
    /// bundle version (fixed literal '0')
    hc_seed_bundle_ver: u8,

    /// 1+ methods for decrypting the same secret seed
    seed_cipher_list: Box<[SeedCipher]>,

    /// additional msg-pack encoded context included with bundle
    #[serde(with = "serde_bytes")]
    app_data: Box<[u8]>,
}

type PrivCalcCipher = Box<
    dyn FnOnce(
            sodoken::BufReadSized<32>,
        ) -> BoxFuture<'static, SodokenResult<SeedCipher>>
        + 'static
        + Send,
>;

/// Enum to specify limits for argon pwhashing algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Argon2idLimit {
    /// low cpu/mem limits
    Interactive,

    /// middle cpu/mem limits
    Moderate,

    /// high cpu/mem limits
    Sensitive,
}

impl Default for Argon2idLimit {
    fn default() -> Self {
        Self::Moderate
    }
}

impl Argon2idLimit {
    /// translate into mem limit
    fn as_mem_limit(&self) -> usize {
        match self {
            Self::Interactive => sodoken::argon2id::MEMLIMIT_INTERACTIVE,
            Self::Moderate => sodoken::argon2id::MEMLIMIT_MODERATE,
            Self::Sensitive => sodoken::argon2id::MEMLIMIT_SENSITIVE,
        }
    }

    /// translate into cpu limit
    fn as_ops_limit(&self) -> u64 {
        match self {
            Self::Interactive => sodoken::argon2id::OPSLIMIT_INTERACTIVE,
            Self::Moderate => sodoken::argon2id::OPSLIMIT_MODERATE,
            Self::Sensitive => sodoken::argon2id::OPSLIMIT_SENSITIVE,
        }
    }
}

/// To lock a SeedBundle, we need a list of ciphers and their secrets.
/// This builder allows specifying those, then generating the locked bytes.
pub struct SeedCipherBuilder {
    seed: sodoken::BufReadSized<32>,
    app_data: Arc<[u8]>,
    cipher_list: Vec<PrivCalcCipher>,
}

impl SeedCipherBuilder {
    pub(crate) fn new<S>(seed: S, app_data: Arc<[u8]>) -> Self
    where
        S: Into<sodoken::BufReadSized<32>> + 'static + Send,
    {
        Self {
            seed: seed.into(),
            app_data,
            cipher_list: Vec::new(),
        }
    }

    /// Add a simple pwhash passphrase cipher to the cipher list.
    pub fn add_pwhash_cipher<P>(
        mut self,
        passphrase: P,
        limits: Argon2idLimit,
    ) -> Self
    where
        P: Into<sodoken::BufRead> + 'static + Send,
    {
        let passphrase = passphrase.into();
        let gen_cipher: PrivCalcCipher = Box::new(move |seed| {
            async move {
                let salt = sodoken::BufWriteSized::new_no_lock();
                sodoken::random::randombytes_buf(salt.clone()).await?;

                let opslimit = limits.as_ops_limit();
                let memlimit = limits.as_mem_limit();
                let secret = sodoken::BufWriteSized::new_mem_locked()?;
                sodoken::argon2id::hash(
                    secret.clone(),
                    passphrase,
                    salt.clone(),
                    opslimit,
                    memlimit,
                )
                .await?;

                use sodoken::secretstream_xchacha20poly1305::*;
                let header = sodoken::BufWriteSized::new_no_lock();
                let mut enc = SecretStreamEncrypt::new(secret, header.clone())?;

                let cipher = sodoken::BufWriteSized::new_no_lock();
                enc.push_final(
                    seed,
                    <Option<sodoken::BufRead>>::None,
                    cipher.clone(),
                )
                .await?;

                Ok(SeedCipher {
                    r#type: "pwHash".into(),
                    salt: Some(salt.into()),
                    seed_cipher_header: Some(header.into()),
                    seed_cipher: Some(cipher.into()),
                })
            }
            .boxed()
        });
        self.cipher_list.push(gen_cipher);
        self
    }

    /// Process the seed ciphers and generate the locked bytes of this bundle.
    pub async fn lock(self) -> SodokenResult<Box<[u8]>> {
        let Self {
            seed,
            app_data,
            cipher_list,
        } = self;

        let seed_cipher_list = cipher_list
            .into_iter()
            .map(|c| c(seed.clone()))
            .collect::<Vec<_>>();

        let seed_cipher_list = futures::future::try_join_all(seed_cipher_list)
            .await?
            .into_boxed_slice();

        let bundle = SeedBundle {
            hc_seed_bundle_ver: 0,
            seed_cipher_list,
            app_data: app_data.to_vec().into_boxed_slice(),
        };

        use serde::Serialize;
        let mut se = rmp_serde::encode::Serializer::new(Vec::new())
            .with_struct_map()
            .with_string_variants();
        bundle.serialize(&mut se).map_err(SodokenError::other)?;

        Ok(se.into_inner().into_boxed_slice())
    }
}

/// This locked cipher is a simple pwHash type.
pub struct LockedSeedCipherPwHash {
    salt: sodoken::BufReadSized<16>,
    seed_cipher_header: sodoken::BufReadSized<24>,
    seed_cipher: sodoken::BufReadSized<49>,
    app_data: Arc<[u8]>,
}

impl LockedSeedCipherPwHash {
    /// Decrypt this Cipher into an UnlockedSeedBundle struct.
    pub async fn unlock<P>(
        self,
        passphrase: P,
        limits: Argon2idLimit,
    ) -> SodokenResult<crate::UnlockedSeedBundle>
    where
        P: Into<sodoken::BufRead> + 'static + Send,
    {
        let LockedSeedCipherPwHash {
            salt,
            seed_cipher_header,
            seed_cipher,
            app_data,
        } = self;
        let passphrase = passphrase.into();

        let opslimit = limits.as_ops_limit();
        let memlimit = limits.as_mem_limit();
        let secret = sodoken::BufWriteSized::new_mem_locked()?;
        sodoken::argon2id::hash(
            secret.clone(),
            passphrase,
            salt,
            opslimit,
            memlimit,
        )
        .await?;

        use sodoken::secretstream_xchacha20poly1305::*;
        let mut dec = SecretStreamDecrypt::new(secret, seed_cipher_header)?;
        let seed = sodoken::BufWriteSized::new_mem_locked()?;
        dec.pull(seed_cipher, <Option<sodoken::BufRead>>::None, seed.clone())
            .await?;

        let mut bundle =
            crate::UnlockedSeedBundle::priv_from_seed(seed.to_read_sized())
                .await?;
        bundle.set_app_data_bytes(app_data);

        Ok(bundle)
    }
}

/// Enum of Locked SeedCipher types handled by this library.
#[non_exhaustive]
pub enum LockedSeedCipher {
    /// This locked cipher is a simple pwHash type.
    PwHash(LockedSeedCipherPwHash),

    /// The type-name of a cipher not yet supported by this library.
    UnsupportedCipher(Box<str>),
}

impl LockedSeedCipher {
    pub(crate) fn from_locked(bytes: &[u8]) -> SodokenResult<Vec<Self>> {
        let bundle: SeedBundle =
            rmp_serde::from_read_ref(bytes).map_err(SodokenError::other)?;

        let SeedBundle {
            hc_seed_bundle_ver,
            seed_cipher_list,
            app_data,
            ..
        } = bundle;

        if hc_seed_bundle_ver != 0 {
            return Err(format!(
                "expected hcSeedBundleVer = 0, got: {}",
                hc_seed_bundle_ver
            )
            .into());
        }

        let app_data: Arc<[u8]> = app_data.into();

        let mut out = Vec::new();

        for seed_cipher in seed_cipher_list.into_vec().into_iter() {
            let SeedCipher {
                r#type,
                salt,
                seed_cipher_header,
                seed_cipher,
            } = seed_cipher;

            match &*r#type {
                "pwHash" => {
                    let salt = salt
                        .ok_or_else(|| SodokenError::from("salt required"))?;
                    let seed_cipher_header =
                        seed_cipher_header.ok_or_else(|| {
                            SodokenError::from("seed_cipher_header required")
                        })?;
                    let seed_cipher = seed_cipher.ok_or_else(|| {
                        SodokenError::from("seed_cipher required")
                    })?;
                    out.push(LockedSeedCipher::PwHash(
                        LockedSeedCipherPwHash {
                            salt: salt.into(),
                            seed_cipher_header: seed_cipher_header.into(),
                            seed_cipher: seed_cipher.into(),
                            app_data: app_data.clone(),
                        },
                    ));
                }
                unsupported => {
                    out.push(LockedSeedCipher::UnsupportedCipher(
                        unsupported.into(),
                    ));
                }
            }
        }

        Ok(out)
    }
}
