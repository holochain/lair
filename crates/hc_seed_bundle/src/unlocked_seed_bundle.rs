use crate::SharedSizedLockedArray;
use one_err::*;
use parking_lot::Mutex;
use std::future::Future;
use std::sync::Arc;

/// The hcSeedBundle spec specifies a fixed KDF context of b"SeedBndl".
const KDF_CONTEXT: &[u8; 8] = b"SeedBndl";

/// This is the main struct for interacting with SeedBundles.
///
/// To create an [UnlockedSeedBundle]:
/// - A new random bundle: [UnlockedSeedBundle::new_random]
/// - Derived from an existing bundle: [UnlockedSeedBundle::derive]
/// - Unlock encrypted bundle bytes: [UnlockedSeedBundle::from_locked]
///
/// Once unlocked, you can get or set associated app data, or sign messages.
///
/// To "lock" (generate encrypted binary seed bundle representation), use
/// [UnlockedSeedBundle::lock] and supply the desired SeedCiphers.
#[derive(Clone)]
pub struct UnlockedSeedBundle {
    seed: SharedSizedLockedArray<32>,
    sign_pub_key: Arc<[u8; sodoken::sign::PUBLICKEYBYTES]>,
    sign_sec_key: SharedSizedLockedArray<{ sodoken::sign::SECRETKEYBYTES }>,
    app_data: Arc<[u8]>,
}

impl UnlockedSeedBundle {
    /// Private core constructor
    pub(crate) async fn priv_from_seed(
        seed: sodoken::SizedLockedArray<32>,
    ) -> Result<Self, OneErr> {
        let seed = Arc::new(Mutex::new(seed));

        // generate the deterministic signature keypair represented by this seed
        let (pk, sk) = tokio::task::spawn_blocking({
            let seed = seed.clone();
            move || -> Result<_, OneErr> {
                let mut pk = [0; sodoken::sign::PUBLICKEYBYTES];
                let mut sk = sodoken::SizedLockedArray::<
                    { sodoken::sign::SECRETKEYBYTES },
                >::new()?;
                sodoken::sign::seed_keypair(
                    &mut pk,
                    &mut sk.lock(),
                    &seed.lock().lock(),
                )?;

                Ok((pk, sk))
            }
        })
        .await
        .map_err(OneErr::new)??;

        // generate the full struct bundle with blank app_data
        Ok(Self {
            seed,
            sign_pub_key: pk.into(),
            sign_sec_key: Arc::new(Mutex::new(sk)),
            app_data: Arc::new([]),
        })
    }

    /// Construct a new random seed SeedBundle.
    pub async fn new_random() -> Result<Self, OneErr> {
        let mut seed = sodoken::SizedLockedArray::new()?;
        sodoken::random::randombytes_buf(&mut *seed.lock())?;
        Self::priv_from_seed(seed).await
    }

    /// Decode locked SeedBundle bytes into a list of
    /// LockedSeedCiphers to be used for decrypting the bundle.
    pub async fn from_locked(
        bytes: &[u8],
    ) -> Result<Vec<crate::LockedSeedCipher>, OneErr> {
        crate::LockedSeedCipher::from_locked(bytes)
    }

    /// Get the actual seed tracked by this seed bundle.
    pub fn get_seed(&self) -> SharedSizedLockedArray<32> {
        self.seed.clone()
    }

    /// Derive a new sub SeedBundle by given index.
    pub fn derive(
        &self,
        index: u32,
    ) -> impl Future<Output = Result<Self, OneErr>> + 'static + Send {
        let seed = self.seed.clone();
        async move {
            let new_seed =
                tokio::task::spawn_blocking(move || -> Result<_, OneErr> {
                    let mut new_seed = sodoken::SizedLockedArray::new()?;
                    sodoken::kdf::derive_from_key(
                        new_seed.lock().as_mut_slice(),
                        index as u64,
                        KDF_CONTEXT,
                        &seed.lock().lock(),
                    )?;

                    Ok(new_seed)
                })
                .await
                .map_err(OneErr::new)??;

            Self::priv_from_seed(new_seed).await
        }
    }

    /// Get the signature pub key generated by this seed.
    pub fn get_sign_pub_key(&self) -> Arc<[u8; sodoken::sign::PUBLICKEYBYTES]> {
        self.sign_pub_key.clone()
    }

    /// Sign some data with the secret key generated by this seed.
    pub fn sign_detached(
        &self,
        message: Arc<[u8]>,
    ) -> impl Future<Output = Result<[u8; sodoken::sign::SIGNATUREBYTES], OneErr>>
           + 'static
           + Send {
        let sign_sec_key = self.sign_sec_key.clone();
        async move {
            tokio::task::spawn_blocking(move || -> Result<_, OneErr> {
                let mut sig = [0; sodoken::sign::SIGNATUREBYTES];
                sodoken::sign::sign_detached(
                    &mut sig,
                    &message,
                    &sign_sec_key.lock().lock(),
                )?;

                Ok(sig)
            })
            .await
            .map_err(OneErr::new)?
        }
    }

    /// Get the raw appData bytes.
    pub fn get_app_data_bytes(&self) -> &[u8] {
        &self.app_data
    }

    /// Set the raw appData bytes.
    pub fn set_app_data_bytes<B>(&mut self, app_data: B)
    where
        B: Into<Arc<[u8]>>,
    {
        self.app_data = app_data.into();
    }

    /// Get the decoded appData bytes by type.
    pub fn get_app_data<T>(&self) -> Result<T, OneErr>
    where
        T: 'static + for<'de> serde::Deserialize<'de>,
    {
        rmp_serde::from_slice(&self.app_data).map_err(OneErr::new)
    }

    /// Set the encoded appData bytes by type.
    pub fn set_app_data<T>(&mut self, t: &T) -> Result<(), OneErr>
    where
        T: serde::Serialize,
    {
        let mut se =
            rmp_serde::encode::Serializer::new(Vec::new()).with_struct_map();
        t.serialize(&mut se).map_err(OneErr::new)?;
        self.app_data = se.into_inner().into_boxed_slice().into();
        Ok(())
    }

    /// Get a SeedCipherBuilder that will allow us to lock this bundle.
    pub fn lock(&self) -> crate::SeedCipherBuilder {
        crate::SeedCipherBuilder::new(self.seed.clone(), self.app_data.clone())
    }
}

#[cfg(test)]
mod tests {
    use crate::*;
    use parking_lot::Mutex;
    use std::sync::Arc;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_pwhash_cipher() {
        let mut seed = UnlockedSeedBundle::new_random().await.unwrap();
        seed.set_app_data(&42_isize).unwrap();

        let orig_pub_key = seed.get_sign_pub_key();

        let passphrase = Arc::new(Mutex::new(sodoken::LockedArray::from(
            b"test-passphrase".to_vec(),
        )));

        let cipher = PwHashLimits::Minimum
            .with_exec(|| seed.lock().add_pwhash_cipher(passphrase.clone()));

        let encoded = cipher.lock().await.unwrap();

        match UnlockedSeedBundle::from_locked(&encoded)
            .await
            .unwrap()
            .remove(0)
        {
            LockedSeedCipher::PwHash(cipher) => {
                let seed = cipher.unlock(passphrase).await.unwrap();
                assert_eq!(&orig_pub_key, &seed.get_sign_pub_key());
                assert_eq!(42, seed.get_app_data::<isize>().unwrap());
            }
            oth => panic!("unexpected cipher: {:?}", oth),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_security_questions_cipher() {
        let mut seed = UnlockedSeedBundle::new_random().await.unwrap();
        seed.set_app_data(&42_isize).unwrap();

        let orig_pub_key = seed.get_sign_pub_key();

        let q1 = "What Color?";
        let q2 = "What Flavor?";
        let q3 = "What Hair?";
        let a1 = sodoken::LockedArray::from(b"blUe".to_vec());
        let a2 = sodoken::LockedArray::from(b"spicy ".to_vec());
        let a3 = sodoken::LockedArray::from(b" big".to_vec());

        let cipher = PwHashLimits::Minimum.with_exec(|| {
            let q_list = (q1.to_string(), q2.to_string(), q3.to_string());
            let a_list = (a1, a2, a3);
            seed.lock().add_security_question_cipher(q_list, a_list)
        });

        let encoded = cipher.lock().await.unwrap();

        match UnlockedSeedBundle::from_locked(&encoded)
            .await
            .unwrap()
            .remove(0)
        {
            LockedSeedCipher::SecurityQuestions(cipher) => {
                assert_eq!(q1, cipher.get_question_list().0);
                assert_eq!(q2, cipher.get_question_list().1);
                assert_eq!(q3, cipher.get_question_list().2);

                let a1 = sodoken::LockedArray::from(b" blue".to_vec());
                let a2 = sodoken::LockedArray::from(b" spicy".to_vec());
                let a3 = sodoken::LockedArray::from(b" bIg".to_vec());

                let seed = cipher.unlock((a1, a2, a3)).await.unwrap();

                assert_eq!(&orig_pub_key, &seed.get_sign_pub_key());
                assert_eq!(42, seed.get_app_data::<isize>().unwrap());
            }
            oth => panic!("unexpected cipher: {:?}", oth),
        }
    }
}
