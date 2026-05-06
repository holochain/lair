use crate::{PwHashLimits, SharedLockedArray, UnlockedSeedBundle};
use one_err::OneErr;

/// Wrap a raw 32-byte seed in a passphrase-locked SeedBundle and return the
/// MSGPACK bytes.
///
/// This is a one-shot helper for callers that already hold seed material
/// inside a [sodoken::SizedLockedArray] (typically because they extracted
/// it from another protected store) and want a portable, passphrase-locked
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
