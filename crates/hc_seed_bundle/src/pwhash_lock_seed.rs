use crate::{PwHashLimits, SharedLockedArray, UnlockedSeedBundle};
use one_err::OneErr;

/// Wrap a raw 32-byte seed in a passphrase-locked SeedBundle and return the
/// MSGPACK bytes.
///
/// This is a helper for callers that already hold seed material inside a
/// [sodoken::SizedLockedArray] (typically because they extracted it from
/// another protected store) and want a portable, passphrase-locked
/// backup. The intermediate [UnlockedSeedBundle] is never observable —
/// callers cannot sign with the wrapped seed, derive sub-bundles, or
/// otherwise treat it as a working bundle. To recover the seed, decode the
/// returned bytes with [UnlockedSeedBundle::from_locked] and unlock with
/// the same passphrase.
pub async fn pwhash_lock_seed(
    seed: sodoken::SizedLockedArray<32>,
    passphrase: SharedLockedArray,
    limits: PwHashLimits,
) -> Result<Box<[u8]>, OneErr> {
    let unlocked = UnlockedSeedBundle::priv_from_seed(seed).await?;
    let build_cipher = move || unlocked.lock().add_pwhash_cipher(passphrase);
    limits.with_exec(build_cipher).lock().await
}

#[cfg(test)]
mod tests {
    use crate::*;
    use std::sync::{Arc, Mutex};

    #[tokio::test(flavor = "multi_thread")]
    async fn round_trip_via_from_locked_unlock() {
        let mut seed = sodoken::SizedLockedArray::<32>::new().unwrap();
        sodoken::random::randombytes_buf(&mut *seed.lock()).unwrap();
        let original_seed_bytes = *seed.lock();

        let passphrase = Arc::new(Mutex::new(sodoken::LockedArray::from(
            b"correct horse battery staple".to_vec(),
        )));

        let bundle =
            pwhash_lock_seed(seed, passphrase.clone(), PwHashLimits::Minimum)
                .await
                .unwrap();

        // Unlock via the standard public path. This is the same path any
        // third-party tool would use to recover the seed.
        let cipher = UnlockedSeedBundle::from_locked(&bundle)
            .await
            .unwrap()
            .remove(0);
        let restored = match cipher {
            LockedSeedCipher::PwHash(pw) => {
                pw.unlock(passphrase).await.unwrap()
            }
            other => panic!("expected PwHash cipher, got {other:?}"),
        };

        let restored_seed_bytes = *restored.get_seed().lock().unwrap().lock();
        assert_eq!(original_seed_bytes, restored_seed_bytes);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unlock_with_wrong_passphrase_fails() {
        let seed = sodoken::SizedLockedArray::<32>::new().unwrap();
        let right =
            Arc::new(Mutex::new(sodoken::LockedArray::from(b"right".to_vec())));
        let wrong =
            Arc::new(Mutex::new(sodoken::LockedArray::from(b"wrong".to_vec())));

        let bundle = pwhash_lock_seed(seed, right, PwHashLimits::Minimum)
            .await
            .unwrap();

        let cipher = UnlockedSeedBundle::from_locked(&bundle)
            .await
            .unwrap()
            .remove(0);
        match cipher {
            LockedSeedCipher::PwHash(pw) => {
                assert!(pw.unlock(wrong).await.is_err());
            }
            other => panic!("expected PwHash cipher, got {other:?}"),
        }
    }
}
