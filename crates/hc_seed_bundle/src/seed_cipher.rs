//! A module for seed bundle cipher related items

use futures::future::{BoxFuture, FutureExt};
use one_err::*;
use sodoken::SodokenResult;
use std::sync::Arc;

mod u8array;
use u8array::*;

mod seed_bundle;
use seed_bundle::*;

mod pw_utils;
use pw_utils::*;

mod pw_hash_limits;
pub use pw_hash_limits::*;

type PrivCalcCipher = Box<
    dyn FnOnce(
            sodoken::BufReadSized<32>,
        ) -> BoxFuture<'static, SodokenResult<SeedCipher>>
        + 'static
        + Send,
>;

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
                // encrypt the passphrase
                let (salt, header, cipher) =
                    pw_enc(seed, passphrase, limits).await?;

                // return the encrypted seed cipher struct
                Ok(SeedCipher::PwHash {
                    salt: salt.into(),
                    mem_limit: limits.as_mem_limit(),
                    ops_limit: limits.as_ops_limit(),
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
                // generate a deterministic passphrase from the answers
                let (a1, a2, a3) = answer_list;
                let passphrase = process_security_answers(a1, a2, a3)?;

                // encrypt the passphrase
                let (salt, header, cipher) =
                    pw_enc(seed, passphrase, limits).await?;

                // return the encrypted seed cipher struct
                Ok(SeedCipher::SecurityQuestions {
                    salt: salt.into(),
                    mem_limit: limits.as_mem_limit(),
                    ops_limit: limits.as_ops_limit(),
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

        // aggregate the cipher generation futures
        let cipher_list = cipher_list
            .into_iter()
            .map(|c| c(seed.clone()))
            .collect::<Vec<_>>();

        // process the cipher generation futures in parallel
        let cipher_list = futures::future::try_join_all(cipher_list)
            .await?
            .into_boxed_slice();

        // collect the ciphers and app data into a serialization struct
        let bundle = SeedBundle {
            cipher_list,
            app_data: app_data.to_vec().into_boxed_slice(),
        };

        // serialize the bundle
        use serde::Serialize;
        let mut se =
            rmp_serde::encode::Serializer::new(Vec::new()).with_struct_map();
        bundle.serialize(&mut se).map_err(OneErr::new)?;

        // return the serialized bundle
        Ok(se.into_inner().into_boxed_slice())
    }
}

/// This locked cipher is a simple pwHash type.
pub struct LockedSeedCipherPwHash {
    salt: sodoken::BufReadSized<16>,
    mem_limit: u32,
    ops_limit: u32,
    seed_cipher_header: sodoken::BufReadSized<24>,
    seed_cipher: sodoken::BufReadSized<49>,
    app_data: Arc<[u8]>,
}

impl std::fmt::Debug for LockedSeedCipherPwHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LockedSeedCipherPwHash").finish()
    }
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
        // destructure our decoding data
        let LockedSeedCipherPwHash {
            salt,
            mem_limit,
            ops_limit,
            seed_cipher_header,
            seed_cipher,
            app_data,
        } = self;
        let passphrase = passphrase.into();

        // decrypt the seed with the given passphrase
        let seed = pw_dec(
            passphrase,
            salt,
            mem_limit,
            ops_limit,
            seed_cipher_header,
            seed_cipher,
        )
        .await?;

        // build the "unlocked" seed bundle struct with the seed
        let mut bundle =
            crate::UnlockedSeedBundle::priv_from_seed(seed).await?;

        // apply the app_data
        bundle.set_app_data_bytes(app_data);

        Ok(bundle)
    }
}

/// This locked cipher is based on security questions.
pub struct LockedSeedCipherSecurityQuestions {
    salt: sodoken::BufReadSized<16>,
    mem_limit: u32,
    ops_limit: u32,
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
        // destructure our decoding data
        let LockedSeedCipherSecurityQuestions {
            salt,
            mem_limit,
            ops_limit,
            seed_cipher_header,
            seed_cipher,
            app_data,
            ..
        } = self;

        // generate a deterministic passphrase with the given answers
        let (a1, a2, a3) = answer_list;
        let passphrase = process_security_answers(a1, a2, a3)?;

        // decrypt the seed with the generated passphrase
        let seed = pw_dec(
            passphrase,
            salt,
            mem_limit,
            ops_limit,
            seed_cipher_header,
            seed_cipher,
        )
        .await?;

        // build the "unlocked" seed bundle struct with the seed
        let mut bundle =
            crate::UnlockedSeedBundle::priv_from_seed(seed).await?;

        // apply the app_data
        bundle.set_app_data_bytes(app_data);

        Ok(bundle)
    }
}

/// Enum of Locked SeedCipher types handled by this library.
///
/// These are obtained by calling [crate::UnlockedSeedBundle::from_locked].
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
    /// used by UnlockedSeedBundle::from_locked to get a list of LockedSeeCipher
    pub(crate) fn from_locked(bytes: &[u8]) -> SodokenResult<Vec<Self>> {
        // deserialize the top-level bundle
        let bundle: SeedBundle =
            rmp_serde::from_slice(bytes).map_err(OneErr::new)?;

        // destructure the cipher list and app data
        let SeedBundle {
            cipher_list,
            app_data,
        } = bundle;

        let app_data: Arc<[u8]> = app_data.into();

        let mut out = Vec::new();

        // generate LockedSeedCipher instances for each available cipher
        for cipher in cipher_list.into_vec().into_iter() {
            match cipher {
                SeedCipher::PwHash {
                    salt,
                    mem_limit,
                    ops_limit,
                    header,
                    cipher,
                } => {
                    // this is a PwHash type, emit that
                    out.push(LockedSeedCipher::PwHash(
                        LockedSeedCipherPwHash {
                            salt: salt.into(),
                            mem_limit,
                            ops_limit,
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
                    // this is a SecurityQuestions type, emit that
                    out.push(LockedSeedCipher::SecurityQuestions(
                        LockedSeedCipherSecurityQuestions {
                            salt: salt.into(),
                            mem_limit,
                            ops_limit,
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
