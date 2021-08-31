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

#[derive(Debug)]
struct SeedBundle {
    cipher_list: Box<[SeedCipher]>,
    app_data: Box<[u8]>,
}

impl serde::Serialize for SeedBundle {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        ("hcsb0", &self.cipher_list, &self.app_data).serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for SeedBundle {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let dec: (&'de str, Box<[SeedCipher]>, Box<[u8]>) =
            serde::Deserialize::deserialize(deserializer)?;
        if dec.0 != "hcsb0" {
            return Err(serde::de::Error::custom(format!(
                "unsupported bundle version: {}",
                dec.0
            )));
        }
        Ok(SeedBundle {
            cipher_list: dec.1,
            app_data: dec.2,
        })
    }
}

#[derive(Debug)]
enum SeedCipher {
    PwHash {
        salt: U8Array<16>,
        mem_limit: u32,
        ops_limit: u32,
        header: U8Array<24>,
        cipher: U8Array<49>,
    },
    SecurityQuestions {
        salt: U8Array<16>,
        mem_limit: u32,
        ops_limit: u32,
        question_list: (String, String, String),
        header: U8Array<24>,
        cipher: U8Array<49>,
    },
}

impl serde::Serialize for SeedCipher {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::PwHash {
                salt,
                mem_limit,
                ops_limit,
                header,
                cipher,
            } => ("pw", salt, mem_limit, ops_limit, header, cipher)
                .serialize(serializer),
            Self::SecurityQuestions {
                salt,
                mem_limit,
                ops_limit,
                question_list,
                header,
                cipher,
            } => (
                "qa",
                salt,
                mem_limit,
                ops_limit,
                &question_list.0,
                &question_list.1,
                &question_list.2,
                header,
                cipher,
            )
                .serialize(serializer),
        }
    }
}

impl<'de> serde::Deserialize<'de> for SeedCipher {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = SeedCipher;

            fn expecting(
                &self,
                f: &mut std::fmt::Formatter<'_>,
            ) -> std::fmt::Result {
                write!(f, "SeedCipher array")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                macro_rules! next_elem {
                    ($t:ty, $s:ident, $e:literal) => {{
                        let out: $t = match $s.next_element() {
                            Ok(Some(t)) => t,
                            _ => return Err(serde::de::Error::custom($e)),
                        };
                        out
                    }};
                }
                let type_name =
                    next_elem!(&'de str, seq, "expected cipher type_name");
                match type_name {
                    "pw" => {
                        let salt =
                            next_elem!(U8Array<16>, seq, "expected salt");
                        let mem_limit =
                            next_elem!(u32, seq, "expected mem_limit");
                        let ops_limit =
                            next_elem!(u32, seq, "expected ops_limit");
                        let header =
                            next_elem!(U8Array<24>, seq, "expected header");
                        let cipher =
                            next_elem!(U8Array<49>, seq, "expected cipher");
                        Ok(SeedCipher::PwHash {
                            salt,
                            mem_limit,
                            ops_limit,
                            header,
                            cipher,
                        })
                    }
                    "qa" => {
                        let salt =
                            next_elem!(U8Array<16>, seq, "expected salt");
                        let mem_limit =
                            next_elem!(u32, seq, "expected mem_limit");
                        let ops_limit =
                            next_elem!(u32, seq, "expected ops_limit");
                        let q1 = next_elem!(String, seq, "expected question 1");
                        let q2 = next_elem!(String, seq, "expected question 2");
                        let q3 = next_elem!(String, seq, "expected question 3");
                        let header =
                            next_elem!(U8Array<24>, seq, "expected header");
                        let cipher =
                            next_elem!(U8Array<49>, seq, "expected cipher");
                        Ok(SeedCipher::SecurityQuestions {
                            salt,
                            mem_limit,
                            ops_limit,
                            question_list: (q1, q2, q3),
                            header,
                            cipher,
                        })
                    }
                    oth => {
                        return Err(serde::de::Error::custom(format!(
                            "unsupported cipher type: {}",
                            oth
                        )))
                    }
                }
            }
        }

        deserializer.deserialize_seq(V)
    }
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

                Ok(SeedCipher::PwHash {
                    salt: salt.into(),
                    mem_limit: limits.as_mem_limit() as u32,
                    ops_limit: limits.as_ops_limit() as u32,
                    header: header.into(),
                    cipher: cipher.into(),
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

                Ok(SeedCipher::SecurityQuestions {
                    salt: salt.into(),
                    mem_limit: limits.as_mem_limit() as u32,
                    ops_limit: limits.as_ops_limit() as u32,
                    question_list,
                    header: header.into(),
                    cipher: cipher.into(),
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

        let cipher_list = cipher_list
            .into_iter()
            .map(|c| c(seed.clone()))
            .collect::<Vec<_>>();

        let cipher_list = futures::future::try_join_all(cipher_list)
            .await?
            .into_boxed_slice();

        let bundle = SeedBundle {
            cipher_list,
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
            cipher_list,
            app_data,
        } = bundle;

        let app_data: Arc<[u8]> = app_data.into();

        let mut out = Vec::new();

        for cipher in cipher_list.into_vec().into_iter() {
            match cipher {
                SeedCipher::PwHash {
                    salt,
                    mem_limit,
                    ops_limit,
                    header,
                    cipher,
                } => {
                    out.push(LockedSeedCipher::PwHash(
                        LockedSeedCipherPwHash {
                            salt: salt.into(),
                            mem_limit: mem_limit as usize,
                            ops_limit: ops_limit as u64,
                            seed_cipher_header: header.into(),
                            seed_cipher: cipher.into(),
                            app_data: app_data.clone(),
                        },
                    ));
                }
                SeedCipher::SecurityQuestions {
                    salt,
                    mem_limit,
                    ops_limit,
                    question_list,
                    header,
                    cipher,
                } => {
                    out.push(LockedSeedCipher::SecurityQuestions(
                        LockedSeedCipherSecurityQuestions {
                            salt: salt.into(),
                            mem_limit: mem_limit as usize,
                            ops_limit: ops_limit as u64,
                            question_list,
                            seed_cipher_header: header.into(),
                            seed_cipher: cipher.into(),
                            app_data: app_data.clone(),
                        },
                    ));
                }
            }
        }

        Ok(out)
    }
}
