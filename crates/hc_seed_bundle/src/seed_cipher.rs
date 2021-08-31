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

impl<const N: usize> From<sodoken::BufReadSized<N>> for U8Array<N> {
    fn from(o: sodoken::BufReadSized<N>) -> Self {
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

/// Encrypted ("locked") SeedCipher encoding.
/// This has to be struct type so we can at least name unhandled variants.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
struct SeedCipher {
    /// the cipher type name, required
    r#type: Box<str>,

    /// argon salt
    salt: Option<U8Array<16>>,

    /// argon mem limit
    mem_limit: Option<u32>,

    /// argon ops limit
    ops_limit: Option<u32>,

    /// security questions
    question_list: Option<(String, String, String)>,

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

/// Enum to specify limits (difficulty) for argon2id pwhashing algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PwHashLimits {
    /// low cpu/mem limits
    Interactive,

    /// middle cpu/mem limits (default)
    Moderate,

    /// high cpu/mem limits
    Sensitive,
}

thread_local! {
    static PWHASH_LIMITS: std::cell::RefCell<PwHashLimits> = std::cell::RefCell::new(PwHashLimits::Moderate);
}

impl PwHashLimits {
    /// Get the current set limits
    /// or the default "Moderate" limits if none are set by `with_exec()`.
    pub fn current() -> Self {
        PWHASH_LIMITS.with(|s| *s.borrow())
    }

    /// Execute a closure with these pwhash limits set.
    pub fn with_exec<R, F>(self, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        PWHASH_LIMITS.with(move |s| {
            *s.borrow_mut() = self;
            let res = f();
            *s.borrow_mut() = PwHashLimits::Moderate;
            res
        })
    }

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

/// lcase -> trim -> concat security question answers
fn process_security_answers<A1, A2, A3>(
    a1: A1,
    a2: A2,
    a3: A3,
) -> SodokenResult<sodoken::BufRead>
where
    A1: Into<sodoken::BufRead> + 'static + Send,
    A2: Into<sodoken::BufRead> + 'static + Send,
    A3: Into<sodoken::BufRead> + 'static + Send,
{
    let a1 = a1.into();
    let a1 = a1.read_lock();
    let a2 = a2.into();
    let a2 = a2.read_lock();
    let a3 = a3.into();
    let a3 = a3.read_lock();

    // careful not to move any bytes out of protected memory
    let a1 = std::str::from_utf8(&*a1).map_err(SodokenError::other)?;
    let a2 = std::str::from_utf8(&*a2).map_err(SodokenError::other)?;
    let a3 = std::str::from_utf8(&*a3).map_err(SodokenError::other)?;
    let a1 = a1.trim();
    let a2 = a2.trim();
    let a3 = a3.trim();
    let a1 = a1.as_bytes();
    let a2 = a2.as_bytes();
    let a3 = a3.as_bytes();

    let out =
        sodoken::BufWrite::new_mem_locked(a1.len() + a2.len() + a3.len())?;
    {
        let mut out = out.write_lock();
        out[0..a1.len()].copy_from_slice(a1);
        out[a1.len()..a1.len() + a2.len()].copy_from_slice(a2);
        out[a1.len() + a2.len()..a1.len() + a2.len() + a3.len()]
            .copy_from_slice(a3);
        // we forced utf8 above, so safe to unwrap here
        let out = std::str::from_utf8_mut(&mut *out).unwrap();

        // this needs a mutable buffer, so we have to do this in out memory
        out.make_ascii_lowercase();
    }
    Ok(out.to_read())
}

async fn pw_enc(
    seed: sodoken::BufReadSized<32>,
    passphrase: sodoken::BufRead,
    limits: PwHashLimits,
) -> SodokenResult<(
    sodoken::BufReadSized<{ sodoken::argon2id::SALTBYTES }>,
    sodoken::BufReadSized<24>,
    sodoken::BufReadSized<49>,
)> {
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
    enc.push_final(seed, <Option<sodoken::BufRead>>::None, cipher.clone())
        .await?;

    Ok((
        salt.to_read_sized(),
        header.to_read_sized(),
        cipher.to_read_sized(),
    ))
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
    pub fn add_pwhash_cipher<P>(mut self, passphrase: P) -> Self
    where
        P: Into<sodoken::BufRead> + 'static + Send,
    {
        let limits = PwHashLimits::current();
        let passphrase = passphrase.into();
        let gen_cipher: PrivCalcCipher = Box::new(move |seed| {
            async move {
                let (salt, header, cipher) =
                    pw_enc(seed, passphrase, limits).await?;

                Ok(SeedCipher {
                    r#type: "pwHash".into(),
                    salt: Some(salt.into()),
                    mem_limit: Some(limits.as_mem_limit() as u32),
                    ops_limit: Some(limits.as_ops_limit() as u32),
                    question_list: None,
                    seed_cipher_header: Some(header.into()),
                    seed_cipher: Some(cipher.into()),
                })
            }
            .boxed()
        });
        self.cipher_list.push(gen_cipher);
        self
    }

    /// Add a security question based cipher to the cipher list.
    pub fn add_security_question_cipher<A>(
        mut self,
        question_list: (String, String, String),
        answer_list: (A, A, A),
    ) -> Self
    where
        A: Into<sodoken::BufRead> + 'static + Send,
    {
        let limits = PwHashLimits::current();
        let gen_cipher: PrivCalcCipher = Box::new(move |seed| {
            async move {
                let (a1, a2, a3) = answer_list;
                let passphrase = process_security_answers(a1, a2, a3)?;
                let (salt, header, cipher) =
                    pw_enc(seed, passphrase, limits).await?;

                Ok(SeedCipher {
                    r#type: "securityQuestions".into(),
                    salt: Some(salt.into()),
                    mem_limit: Some(limits.as_mem_limit() as u32),
                    ops_limit: Some(limits.as_ops_limit() as u32),
                    question_list: Some(question_list),
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
    mem_limit: usize,
    ops_limit: u64,
    seed_cipher_header: sodoken::BufReadSized<24>,
    seed_cipher: sodoken::BufReadSized<49>,
    app_data: Arc<[u8]>,
}

impl std::fmt::Debug for LockedSeedCipherPwHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LockedSeedCipherPwHash").finish()
    }
}

async fn pw_dec(
    passphrase: sodoken::BufRead,
    salt: sodoken::BufReadSized<{ sodoken::argon2id::SALTBYTES }>,
    mem_limit: usize,
    ops_limit: u64,
    header: sodoken::BufReadSized<24>,
    cipher: sodoken::BufReadSized<49>,
) -> SodokenResult<sodoken::BufReadSized<32>> {
    let secret = sodoken::BufWriteSized::new_mem_locked()?;
    sodoken::argon2id::hash(
        secret.clone(),
        passphrase,
        salt,
        ops_limit,
        mem_limit,
    )
    .await?;

    use sodoken::secretstream_xchacha20poly1305::*;
    let mut dec = SecretStreamDecrypt::new(secret, header)?;
    let seed = sodoken::BufWriteSized::new_mem_locked()?;
    dec.pull(cipher, <Option<sodoken::BufRead>>::None, seed.clone())
        .await?;

    Ok(seed.to_read_sized())
}

impl LockedSeedCipherPwHash {
    /// Decrypt this Cipher into an UnlockedSeedBundle struct.
    pub async fn unlock<P>(
        self,
        passphrase: P,
    ) -> SodokenResult<crate::UnlockedSeedBundle>
    where
        P: Into<sodoken::BufRead> + 'static + Send,
    {
        let LockedSeedCipherPwHash {
            salt,
            mem_limit,
            ops_limit,
            seed_cipher_header,
            seed_cipher,
            app_data,
        } = self;
        let passphrase = passphrase.into();

        let seed = pw_dec(
            passphrase,
            salt,
            mem_limit,
            ops_limit,
            seed_cipher_header,
            seed_cipher,
        )
        .await?;

        let mut bundle =
            crate::UnlockedSeedBundle::priv_from_seed(seed).await?;
        bundle.set_app_data_bytes(app_data);

        Ok(bundle)
    }
}

/// This locked cipher is based on security questions.
pub struct LockedSeedCipherSecurityQuestions {
    salt: sodoken::BufReadSized<16>,
    mem_limit: usize,
    ops_limit: u64,
    question_list: (String, String, String),
    seed_cipher_header: sodoken::BufReadSized<24>,
    seed_cipher: sodoken::BufReadSized<49>,
    app_data: Arc<[u8]>,
}

impl std::fmt::Debug for LockedSeedCipherSecurityQuestions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LockedSeedCipherSecurityQuestions")
            .field("question_list", &self.question_list)
            .finish()
    }
}

impl LockedSeedCipherSecurityQuestions {
    /// List the questions
    pub fn get_question_list(&self) -> &(String, String, String) {
        &self.question_list
    }

    /// Decrypt this Cipher into an UnlockedSeedBundle struct.
    pub async fn unlock<A>(
        self,
        answer_list: (A, A, A),
    ) -> SodokenResult<crate::UnlockedSeedBundle>
    where
        A: Into<sodoken::BufRead> + 'static + Send,
    {
        let LockedSeedCipherSecurityQuestions {
            salt,
            mem_limit,
            ops_limit,
            seed_cipher_header,
            seed_cipher,
            app_data,
            ..
        } = self;
        let (a1, a2, a3) = answer_list;
        let passphrase = process_security_answers(a1, a2, a3)?;

        let seed = pw_dec(
            passphrase,
            salt,
            mem_limit,
            ops_limit,
            seed_cipher_header,
            seed_cipher,
        )
        .await?;

        let mut bundle =
            crate::UnlockedSeedBundle::priv_from_seed(seed).await?;
        bundle.set_app_data_bytes(app_data);

        Ok(bundle)
    }
}

/// Enum of Locked SeedCipher types handled by this library.
#[non_exhaustive]
#[derive(Debug)]
pub enum LockedSeedCipher {
    /// This locked cipher is a simple pwHash type.
    PwHash(LockedSeedCipherPwHash),

    /// This locked cipher is based on security question answers.
    SecurityQuestions(LockedSeedCipherSecurityQuestions),

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
                mem_limit,
                ops_limit,
                question_list,
                seed_cipher_header,
                seed_cipher,
            } = seed_cipher;

            match &*r#type {
                "pwHash" => {
                    let salt = salt
                        .ok_or_else(|| SodokenError::from("salt required"))?;
                    let mem_limit = mem_limit.ok_or_else(|| {
                        SodokenError::from("mem_limit required")
                    })?;
                    let ops_limit = ops_limit.ok_or_else(|| {
                        SodokenError::from("ops_limit required")
                    })?;
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
                            mem_limit: mem_limit as usize,
                            ops_limit: ops_limit as u64,
                            seed_cipher_header: seed_cipher_header.into(),
                            seed_cipher: seed_cipher.into(),
                            app_data: app_data.clone(),
                        },
                    ));
                }
                "securityQuestions" => {
                    let salt = salt
                        .ok_or_else(|| SodokenError::from("salt required"))?;
                    let mem_limit = mem_limit.ok_or_else(|| {
                        SodokenError::from("mem_limit required")
                    })?;
                    let ops_limit = ops_limit.ok_or_else(|| {
                        SodokenError::from("ops_limit required")
                    })?;
                    let question_list = question_list.ok_or_else(|| {
                        SodokenError::from("question_list required")
                    })?;
                    let seed_cipher_header =
                        seed_cipher_header.ok_or_else(|| {
                            SodokenError::from("seed_cipher_header required")
                        })?;
                    let seed_cipher = seed_cipher.ok_or_else(|| {
                        SodokenError::from("seed_cipher required")
                    })?;
                    out.push(LockedSeedCipher::SecurityQuestions(
                        LockedSeedCipherSecurityQuestions {
                            salt: salt.into(),
                            mem_limit: mem_limit as usize,
                            ops_limit: ops_limit as u64,
                            question_list,
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
