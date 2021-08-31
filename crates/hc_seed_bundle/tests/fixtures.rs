use hc_seed_bundle::*;

use std::collections::HashMap;

const FIXTURES: &str = include_str!("seed_bundle_test_fixtures.json");

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
    let b = base64::encode_config(b, base64::URL_SAFE_NO_PAD);
    assert_eq!(a, &b);
}

impl Test {
    async fn generate(&self) -> String {
        let seed = UnlockedSeedBundle::new_random().await.unwrap();
        let mut cipher = seed.lock();
        for unlock in self.unlock.iter() {
            if &unlock.r#type == "pwHash" {
                let passphrase = unlock.passphrase.as_ref().unwrap();
                let passphrase =
                    sodoken::BufRead::from(passphrase.as_bytes().to_vec());
                cipher = cipher
                    .add_pwhash_cipher(passphrase, Argon2idLimit::Interactive);
            } else {
                panic!("unsupported cipher type: {}", unlock.r#type);
            }
        }
        let cipher = cipher.lock().await.unwrap();
        base64::encode_config(cipher, base64::URL_SAFE_NO_PAD)
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
                    println!("{:?} with passphrase - {}", cipher, passphrase);
                    let passphrase =
                        sodoken::BufRead::from(passphrase.as_bytes().to_vec());
                    let seed = cipher
                        .unlock(passphrase, Argon2idLimit::Interactive)
                        .await
                        .unwrap();
                    let pub_key = seed.get_sign_pub_key();
                    assert_eq_b64(&self.sign_pub_key, &*pub_key.read_lock());
                    out = Some(seed);
                }
                LockedSeedCipher::UnsupportedCipher(name) => {
                    if &*name == "securityQuestions" {
                        println!("HAVEN'T IMPLEMENTED securityQuestions YET");
                    } else {
                        panic!("invalid unsupported cipher: {}", name);
                    }
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
            println!("deriving subseed by path: {:?}", d_path);
            for subkey_id in d_path {
                cur = cur.derive(subkey_id.parse().unwrap()).await.unwrap();
            }

            assert_eq_b64(&**target, &*cur.get_sign_pub_key().read_lock());
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
        let cipher = base64::decode_config(
            test.cipher.as_ref().unwrap().as_bytes(),
            base64::URL_SAFE_NO_PAD,
        )
        .unwrap();
        let cipher_list =
            UnlockedSeedBundle::from_locked(&cipher).await.unwrap();
        let seed = test.check_unlocks(cipher_list).await;
        test.check_derives(seed).await;
    }
}