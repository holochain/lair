use base64::Engine;
use hc_seed_bundle::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const FIXTURES: &str = include_str!("fixtures/seed_bundle_test_fixtures.json");

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct Unlock {
    r#type: String,
    passphrase: Option<String>,
    question_list: Option<Vec<String>>,
    answer_list: Option<Vec<String>>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct Test {
    cipher: Option<String>,
    unlock: Vec<Unlock>,
    sign_pub_key: String,
    derivations: HashMap<String, String>,
}

fn assert_eq_b64(a: &str, b: &[u8]) {
    let b = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(b);
    assert_eq!(a, &b);
}

impl Test {
    async fn generate(&self) -> String {
        let seed = UnlockedSeedBundle::new_random().await.unwrap();
        let mut cipher = seed.lock();
        for unlock in self.unlock.iter() {
            if &unlock.r#type == "pwHash" {
                let passphrase = unlock.passphrase.as_ref().unwrap();
                let passphrase = Arc::new(Mutex::new(
                    sodoken::LockedArray::from(passphrase.as_bytes().to_vec()),
                ));
                cipher = PwHashLimits::Minimum
                    .with_exec(move || cipher.add_pwhash_cipher(passphrase));
            } else if &unlock.r#type == "securityQuestions" {
                let q_list = unlock.question_list.as_ref().unwrap();
                let a_list = unlock.answer_list.as_ref().unwrap();
                assert_eq!(3, q_list.len());
                assert_eq!(3, a_list.len());
                let q_list = (
                    q_list[0].to_string(),
                    q_list[1].to_string(),
                    q_list[2].to_string(),
                );
                let a1 =
                    sodoken::LockedArray::from(a_list[0].as_bytes().to_vec());
                let a2 =
                    sodoken::LockedArray::from(a_list[1].as_bytes().to_vec());
                let a3 =
                    sodoken::LockedArray::from(a_list[2].as_bytes().to_vec());
                cipher = PwHashLimits::Minimum.with_exec(move || {
                    cipher.add_security_question_cipher(q_list, (a1, a2, a3))
                });
            } else {
                panic!("unsupported cipher type: {}", unlock.r#type);
            }
        }
        let cipher = cipher.lock().await.unwrap();
        base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(cipher)
    }

    async fn check_unlocks(
        &self,
        cipher_list: Vec<LockedSeedCipher>,
    ) -> UnlockedSeedBundle {
        let mut out = None;
        for (cipher_index, cipher) in cipher_list.into_iter().enumerate() {
            match cipher {
                LockedSeedCipher::PwHash(cipher) => {
                    let passphrase = self
                        .unlock
                        .get(cipher_index)
                        .unwrap()
                        .passphrase
                        .as_ref()
                        .unwrap();
                    println!("{cipher:?} with passphrase - {passphrase}");
                    let passphrase =
                        Arc::new(Mutex::new(sodoken::LockedArray::from(
                            passphrase.as_bytes().to_vec(),
                        )));
                    let seed = cipher.unlock(passphrase).await.unwrap();
                    let pub_key = seed.get_sign_pub_key();
                    assert_eq_b64(&self.sign_pub_key, pub_key.as_slice());
                    out = Some(seed);
                }
                LockedSeedCipher::SecurityQuestions(cipher) => {
                    let answer_list = self
                        .unlock
                        .get(cipher_index)
                        .unwrap()
                        .answer_list
                        .as_ref()
                        .unwrap();
                    println!("{cipher:?} with answer_list - {answer_list:?}");
                    // ensure the trimming / lcasing works
                    let a1 = sodoken::LockedArray::from(
                        format!(
                            "\t {} \t",
                            answer_list[0].to_string().to_ascii_uppercase()
                        )
                        .as_bytes()
                        .to_vec(),
                    );
                    let a2 = sodoken::LockedArray::from(
                        answer_list[1].as_bytes().to_vec(),
                    );
                    let a3 = sodoken::LockedArray::from(
                        answer_list[2].as_bytes().to_vec(),
                    );
                    let seed = cipher.unlock((a1, a2, a3)).await.unwrap();
                    let pub_key = seed.get_sign_pub_key();
                    assert_eq_b64(&self.sign_pub_key, pub_key.as_slice());
                    out = Some(seed);
                }
                LockedSeedCipher::UnsupportedCipher(name) => {
                    panic!("invalid unsupported cipher: {}", name);
                }
                _ => {
                    panic!("unsupported unknown cipher");
                }
            }
        }
        out.unwrap()
    }

    async fn check_derives(&self, seed: UnlockedSeedBundle) {
        for (d_path, target) in self.derivations.iter() {
            let mut cur = seed.clone();

            let d_path = d_path.split('/').skip(1).collect::<Vec<_>>();
            println!("deriving subseed by path: {d_path:?}");
            for subkey_id in d_path {
                cur = cur.derive(subkey_id.parse().unwrap()).await.unwrap();
            }

            assert_eq_b64(target.as_str(), cur.get_sign_pub_key().as_slice());
        }
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct Suite {
    success: Vec<Test>,
}

#[tokio::test(flavor = "multi_thread")]
async fn fixture_tests() {
    let s: Suite = serde_json::from_str(FIXTURES).unwrap();
    let Suite { success } = s;
    for test in success {
        if test.cipher.is_none() {
            let cipher = test.generate().await;
            panic!("cipher required, like: ({})", cipher);
        }
        let cipher = base64::prelude::BASE64_URL_SAFE_NO_PAD
            .decode(test.cipher.as_ref().unwrap().as_bytes())
            .unwrap();
        let cipher_list =
            UnlockedSeedBundle::from_locked(&cipher).await.unwrap();
        let seed = test.check_unlocks(cipher_list).await;
        test.check_derives(seed).await;
    }
}
