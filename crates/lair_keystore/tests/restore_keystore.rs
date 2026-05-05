//! Two integration tests demonstrating keystore-loss recovery via
//! `hc_seed_bundle`, one for each deployment model:
//!
//! 1. `restore_keystore_in_process` — application embeds lair as a library
//!    and uses `StandaloneServer::store().insert_seed(...)` for a clean,
//!    detritus-free restore.
//! 2. `restore_keystore_via_ipc` — application talks to lair over IPC and
//!    uses `LairClient::import_seed(...)`. Functional, but leaves a
//!    bootstrap "import-tmp" entry in the new keystore because lair has no
//!    delete-entry API.
//!
//! Both tests share a phase-1/2 helper that populates a keystore, captures
//! signatures and ciphertext, and produces a passphrase-locked seed bundle
//! representing the user's backup.
//!
//! Not covered by this workflow (and therefore not asserted by these tests):
//!   - `WkaTlsCert` entries (random, not seed-derived)
//!   - top-level seeds created via `new_seed` rather than `derive_seed`
//!   - seeds created with `exportable: false`

use lair_keystore::dependencies::*;
use lair_keystore::server::StandaloneServer;
use lair_keystore_api::ipc_keystore::ipc_keystore_connect;
use lair_keystore_api::prelude::*;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

mod common;

/// Captured by phase 1, validated against keystore B in phase 3.
struct Backup {
    locked_bundle: Box<[u8]>,
    bundle_pass: SharedLockedArray,
    root_info: SeedInfo,
    revoke_info: SeedInfo,
    app1_info: SeedInfo,
    app2_info: SeedInfo,
    path_revoke: Box<[u32]>,
    path_app1: Box<[u32]>,
    path_app2: Box<[u32]>,
    signed_msg: Arc<[u8]>,
    sig_a: Ed25519Signature,
    plaintext: Arc<[u8]>,
    sb_nonce: [u8; 24],
    sb_cipher: Arc<[u8]>,
}

/// Phase 1 + Phase 2: populate keystore A with a derived-key hierarchy,
/// capture signatures and a secretbox ciphertext, export the root seed
/// and lock it as an `hc_seed_bundle`. Returns everything we need to
/// validate restoration. Keystore A is fully torn down on return — the
/// `Backup` is the only thing that survives.
async fn populate_and_backup(store_pass: SharedLockedArray) -> Backup {
    let bundle_pass = Arc::new(Mutex::new(sodoken::LockedArray::from(
        b"bundle-pass".to_vec(),
    )));

    let tmpdir_a = tempfile::TempDir::with_prefix("lair-restore-a").unwrap();
    let config_a = common::create_config(&tmpdir_a, store_pass.clone()).await;
    let mut server_a = StandaloneServer::new(config_a.clone()).await.unwrap();
    server_a.run(store_pass.clone()).await.unwrap();
    let client_a = ipc_keystore_connect(
        config_a.connection_url.clone(),
        store_pass.clone(),
    )
    .await
    .unwrap();

    let root_info = client_a.new_seed("root".into(), None, true).await.unwrap();

    let path_revoke: Box<[u32]> = vec![1].into();
    let path_app1: Box<[u32]> = vec![2, 1, 1].into();
    let path_app2: Box<[u32]> = vec![2, 1, 2].into();

    let revoke_info = client_a
        .derive_seed(
            "root".into(),
            None,
            "revoke".into(),
            None,
            path_revoke.clone(),
        )
        .await
        .unwrap();
    let app1_info = client_a
        .derive_seed(
            "root".into(),
            None,
            "app1".into(),
            None,
            path_app1.clone(),
        )
        .await
        .unwrap();
    let app2_info = client_a
        .derive_seed(
            "root".into(),
            None,
            "app2".into(),
            None,
            path_app2.clone(),
        )
        .await
        .unwrap();

    // Sign with one sub-seed. Ed25519 signatures are deterministic, so the
    // restored sub-seed should produce a byte-identical signature.
    let signed_msg: Arc<[u8]> = b"important message".to_vec().into();
    let sig_a = client_a
        .sign_by_pub_key(
            app1_info.ed25519_pub_key.clone(),
            None,
            signed_msg.clone(),
        )
        .await
        .unwrap();

    // Encrypt with another sub-seed via secretbox; the ciphertext lives
    // outside lair, so we must still be able to decrypt it after restore.
    let plaintext: Arc<[u8]> = b"the answer is 42".to_vec().into();
    let (sb_nonce, sb_cipher) = client_a
        .secretbox_xsalsa_by_tag("app2".into(), None, plaintext.clone())
        .await
        .unwrap();

    // Export the root seed (encrypted to a tmp x25519 key we control)
    let mut tmp_pk = [0u8; sodoken::crypto_box::XSALSA_PUBLICKEYBYTES];
    let mut tmp_sk = sodoken::SizedLockedArray::<
        { sodoken::crypto_box::XSALSA_SECRETKEYBYTES },
    >::new()
    .unwrap();
    sodoken::crypto_box::xsalsa_keypair(&mut tmp_pk, &mut tmp_sk.lock())
        .unwrap();

    let (export_nonce, export_cipher) = client_a
        .export_seed_by_tag(
            "root".into(),
            root_info.x25519_pub_key.clone(),
            tmp_pk.into(),
            None,
        )
        .await
        .unwrap();

    // Decrypt the exported seed straight into a locked array, then wrap
    // it as an UnlockedSeedBundle. `from_seed` takes ownership of the
    // locked seed, so the raw bytes never leave protected memory.
    let mut root_seed = sodoken::SizedLockedArray::<32>::new().unwrap();
    {
        let mut guard = root_seed.lock();
        sodoken::crypto_box::xsalsa_open_easy(
            &mut *guard,
            &export_cipher,
            &export_nonce,
            &root_info.x25519_pub_key,
            &tmp_sk.lock(),
        )
        .unwrap();
    }

    let unlocked = hc_seed_bundle::UnlockedSeedBundle::from_seed(root_seed)
        .await
        .unwrap();

    // PwHashLimits::Minimum keeps the test fast; production callers
    // would use Moderate or Sensitive.
    let cipher_builder = PwHashLimits::Minimum
        .with_exec(|| unlocked.lock().add_pwhash_cipher(bundle_pass.clone()));
    let locked_bundle: Box<[u8]> = cipher_builder.lock().await.unwrap();

    // Tear keystore A down. The locked_bundle bytes are all that survives.
    client_a.shutdown().await.unwrap();
    drop(server_a);
    drop(tmpdir_a);

    Backup {
        locked_bundle,
        bundle_pass,
        root_info,
        revoke_info,
        app1_info,
        app2_info,
        path_revoke,
        path_app1,
        path_app2,
        signed_msg,
        sig_a,
        plaintext,
        sb_nonce,
        sb_cipher,
    }
}

/// Decode the locked bundle bytes and unlock with the bundle passphrase.
async fn unlock_bundle(
    locked_bundle: &[u8],
    bundle_pass: SharedLockedArray,
) -> hc_seed_bundle::UnlockedSeedBundle {
    let cipher_list =
        hc_seed_bundle::UnlockedSeedBundle::from_locked(locked_bundle)
            .await
            .unwrap();
    for cipher in cipher_list {
        if let hc_seed_bundle::LockedSeedCipher::PwHash(pw) = cipher {
            if let Ok(b) = pw.unlock(bundle_pass.clone()).await {
                return b;
            }
        }
    }
    panic!("could not unlock seed bundle");
}

/// Common assertions: re-derive sub-seeds, replay the signature, and
/// decrypt the pre-loss secretbox ciphertext. Used by both restore tests.
async fn assert_full_recovery(client_b: &LairClient, b: &Backup) {
    let restored_revoke_info = client_b
        .derive_seed(
            "root".into(),
            None,
            "revoke".into(),
            None,
            b.path_revoke.clone(),
        )
        .await
        .unwrap();
    let restored_app1_info = client_b
        .derive_seed(
            "root".into(),
            None,
            "app1".into(),
            None,
            b.path_app1.clone(),
        )
        .await
        .unwrap();
    let restored_app2_info = client_b
        .derive_seed(
            "root".into(),
            None,
            "app2".into(),
            None,
            b.path_app2.clone(),
        )
        .await
        .unwrap();

    assert_eq!(b.revoke_info, restored_revoke_info);
    assert_eq!(b.app1_info, restored_app1_info);
    assert_eq!(b.app2_info, restored_app2_info);

    // Ed25519 is a deterministic signature scheme: same key, same message,
    // same signature.
    let sig_b = client_b
        .sign_by_pub_key(
            restored_app1_info.ed25519_pub_key.clone(),
            None,
            b.signed_msg.clone(),
        )
        .await
        .unwrap();
    assert_eq!(b.sig_a, sig_b);

    let recovered = client_b
        .secretbox_xsalsa_open_by_tag(
            "app2".into(),
            None,
            b.sb_nonce,
            b.sb_cipher.clone(),
        )
        .await
        .unwrap();
    assert_eq!(&*recovered, &*b.plaintext);
}

async fn list_tags(client: &LairClient) -> HashSet<String> {
    client
        .list_entries()
        .await
        .unwrap()
        .into_iter()
        .map(|e| match e {
            LairEntryInfo::Seed { tag, .. } => tag.to_string(),
            LairEntryInfo::DeepLockedSeed { tag, .. } => tag.to_string(),
            LairEntryInfo::WkaTlsCert { tag, .. } => tag.to_string(),
            other => panic!("unexpected entry: {other:?}"),
        })
        .collect()
}

fn tag_set<const N: usize>(tags: [&str; N]) -> HashSet<String> {
    tags.iter().map(|s| s.to_string()).collect()
}

/// Path B: in-process embedding. Uses `StandaloneServer::store()` to call
/// `LairStore::insert_seed` directly. Clean restore, no detritus.
#[tokio::test(flavor = "multi_thread")]
async fn restore_keystore_in_process() {
    let store_pass = Arc::new(Mutex::new(sodoken::LockedArray::from(
        b"store-pass".to_vec(),
    )));
    let backup = populate_and_backup(store_pass.clone()).await;

    let tmpdir_b = tempfile::TempDir::with_prefix("lair-restore-b").unwrap();
    let config_b = common::create_config(&tmpdir_b, store_pass.clone()).await;
    let mut server_b = StandaloneServer::new(config_b.clone()).await.unwrap();
    server_b.run(store_pass.clone()).await.unwrap();
    let client_b = ipc_keystore_connect(
        config_b.connection_url.clone(),
        store_pass.clone(),
    )
    .await
    .unwrap();

    let restored =
        unlock_bundle(&backup.locked_bundle, backup.bundle_pass.clone()).await;

    let store_b = server_b.store().await.unwrap();
    let restored_root_info = store_b
        .insert_seed(restored.get_seed(), "root".into(), true)
        .await
        .unwrap();
    assert_eq!(
        backup.root_info, restored_root_info,
        "restored root produces the same ed25519/x25519 public keys",
    );

    assert_full_recovery(&client_b, &backup).await;

    // Path B leaves only the entries the application explicitly created.
    assert_eq!(
        list_tags(&client_b).await,
        tag_set(["root", "revoke", "app1", "app2"]),
        "in-process restore leaves no detritus",
    );

    client_b.shutdown().await.unwrap();
}

/// Path A: out-of-process. Uses only `LairClient` (the IPC RPC surface).
/// `import_seed` requires an existing seed in the keystore as the
/// `recipient_pub_key`, so we bootstrap one with `new_seed("import-tmp")`,
/// crypto_box-encrypt the unlocked seed bytes for that recipient, then
/// import.
///
/// Wart: lair has no delete-entry API, so the bootstrap "import-tmp"
/// entry is left behind. Asserted explicitly so the limitation is
/// enforced by the test rather than just documented.
#[tokio::test(flavor = "multi_thread")]
async fn restore_keystore_via_ipc() {
    let store_pass = Arc::new(Mutex::new(sodoken::LockedArray::from(
        b"store-pass".to_vec(),
    )));
    let backup = populate_and_backup(store_pass.clone()).await;

    let tmpdir_b = tempfile::TempDir::with_prefix("lair-restore-b").unwrap();
    let config_b = common::create_config(&tmpdir_b, store_pass.clone()).await;
    let mut server_b = StandaloneServer::new(config_b.clone()).await.unwrap();
    server_b.run(store_pass.clone()).await.unwrap();
    let client_b = ipc_keystore_connect(
        config_b.connection_url.clone(),
        store_pass.clone(),
    )
    .await
    .unwrap();

    let restored =
        unlock_bundle(&backup.locked_bundle, backup.bundle_pass.clone()).await;

    // Bootstrap recipient seed inside keystore B so we have an x25519
    // pubkey lair already knows about. This is the wart: there's no
    // way to delete it after the import succeeds.
    let recipient_info = client_b
        .new_seed("import-tmp".into(), None, true)
        .await
        .unwrap();

    // Tmp sender keypair — the "from" side of the crypto_box.
    let mut tmp_pk = [0u8; sodoken::crypto_box::XSALSA_PUBLICKEYBYTES];
    let mut tmp_sk = sodoken::SizedLockedArray::<
        { sodoken::crypto_box::XSALSA_SECRETKEYBYTES },
    >::new()
    .unwrap();
    sodoken::crypto_box::xsalsa_keypair(&mut tmp_pk, &mut tmp_sk.lock())
        .unwrap();

    // Encrypt the (still locked) seed bytes for the bootstrap recipient.
    let mut nonce = [0u8; sodoken::crypto_box::XSALSA_NONCEBYTES];
    sodoken::random::randombytes_buf(&mut nonce).unwrap();
    let mut cipher = vec![0u8; 32 + sodoken::crypto_box::XSALSA_MACBYTES];
    {
        let shared_seed = restored.get_seed();
        let mut outer = shared_seed.lock().unwrap();
        let inner = outer.lock();
        sodoken::crypto_box::xsalsa_easy(
            &mut cipher,
            &*inner,
            &nonce,
            &recipient_info.x25519_pub_key,
            &tmp_sk.lock(),
        )
        .unwrap();
    }

    let restored_root_info = client_b
        .import_seed(
            tmp_pk.into(),
            recipient_info.x25519_pub_key.clone(),
            None,
            nonce,
            cipher.into(),
            "root".into(),
            true,
        )
        .await
        .unwrap();
    assert_eq!(
        backup.root_info, restored_root_info,
        "restored root produces the same ed25519/x25519 public keys",
    );

    assert_full_recovery(&client_b, &backup).await;

    // The bootstrap entry survives — no delete API exists today.
    let tags = list_tags(&client_b).await;
    assert!(
        tags.contains("import-tmp"),
        "IPC restore leaves the bootstrap recipient seed behind",
    );
    assert_eq!(
        tags,
        tag_set(["root", "revoke", "app1", "app2", "import-tmp"]),
    );

    client_b.shutdown().await.unwrap();
}
