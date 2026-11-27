//! Integration test demonstrating keystore-loss recovery via the
//! `export_seed_bundle_by_tag` / `import_seed_bundle` IPC verbs.
//!
//! Phase 1: populate keystore A with a derived-key hierarchy, capture a
//! signature and a secretbox ciphertext, ask lair for a passphrase-locked
//! `hc_seed_bundle` of the root seed, then tear keystore A down.
//!
//! Phase 2: start a fresh keystore B, hand it the locked bundle bytes via
//! `import_seed_bundle`, re-derive the same sub-seeds, replay the
//! signature, and decrypt the pre-loss ciphertext.
//!
//! Not covered by this workflow:
//!   - `WkaTlsCert` entries (random, not seed-derived)
//!   - top-level seeds created via `new_seed` rather than `derive_seed`
//!   - seeds created with `exportable: false`

use lair_keystore::dependencies::*;
use lair_keystore::server::StandaloneServer;
use lair_keystore_api::ipc_keystore::ipc_keystore_connect;
use lair_keystore_api::prelude::*;
use std::sync::{Arc, Mutex};

mod common;

#[tokio::test(flavor = "multi_thread")]
async fn restore_keystore_via_seed_bundle() {
    let store_pass = Arc::new(Mutex::new(sodoken::LockedArray::from(
        b"store-pass".to_vec(),
    )));
    let bundle_pass = Arc::new(Mutex::new(sodoken::LockedArray::from(
        b"bundle-pass".to_vec(),
    )));

    // ---- Phase 1: populate keystore A and produce the backup bytes. ----

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

    // Sign with one sub-seed. Ed25519 is deterministic, so the restored
    // sub-seed should produce a byte-identical signature.
    let signed_msg: Arc<[u8]> = b"important message".to_vec().into();
    let sig_a = client_a
        .sign_by_pub_key(
            app1_info.ed25519_pub_key.clone(),
            None,
            signed_msg.clone(),
        )
        .await
        .unwrap();

    // Encrypt with another sub-seed; the ciphertext lives outside lair, so
    // we must still be able to decrypt it after restore.
    let plaintext: Arc<[u8]> = b"the answer is 42".to_vec().into();
    let (sb_nonce, sb_cipher) = client_a
        .secretbox_xsalsa_by_tag("app2".into(), None, plaintext.clone())
        .await
        .unwrap();

    // Ask lair for a passphrase-locked seed bundle of the root seed. The
    // raw seed never leaves the server.
    let locked_bundle = client_a
        .export_seed_bundle_by_tag(
            "root".into(),
            bundle_pass.clone(),
            PwHashLimits::Minimum,
        )
        .await
        .unwrap();

    client_a.shutdown().await.unwrap();
    drop(server_a);
    drop(tmpdir_a);

    // ---- Phase 2: fresh keystore B, restore from the bundle. ----

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

    let restored_root_info = client_b
        .import_seed_bundle(
            locked_bundle,
            bundle_pass.clone(),
            "root".into(),
            true,
        )
        .await
        .unwrap();
    assert_eq!(
        root_info, restored_root_info,
        "restored root produces the same ed25519/x25519 public keys",
    );

    let restored_revoke_info = client_b
        .derive_seed("root".into(), None, "revoke".into(), None, path_revoke)
        .await
        .unwrap();
    let restored_app1_info = client_b
        .derive_seed("root".into(), None, "app1".into(), None, path_app1)
        .await
        .unwrap();
    let restored_app2_info = client_b
        .derive_seed("root".into(), None, "app2".into(), None, path_app2)
        .await
        .unwrap();

    assert_eq!(revoke_info, restored_revoke_info);
    assert_eq!(app1_info, restored_app1_info);
    assert_eq!(app2_info, restored_app2_info);

    let sig_b = client_b
        .sign_by_pub_key(
            restored_app1_info.ed25519_pub_key.clone(),
            None,
            signed_msg,
        )
        .await
        .unwrap();
    assert_eq!(sig_a, sig_b);

    let recovered = client_b
        .secretbox_xsalsa_open_by_tag("app2".into(), None, sb_nonce, sb_cipher)
        .await
        .unwrap();
    assert_eq!(&*recovered, &*plaintext);

    client_b.shutdown().await.unwrap();
}

/// Helper: bring up a standalone keystore + connected client. Returns the
/// tempdir last so the caller can keep it alive for the test's lifetime.
async fn spawn_keystore(
    prefix: &str,
    store_pass: SharedLockedArray,
) -> (StandaloneServer, LairClient, tempfile::TempDir) {
    let tmpdir = tempfile::TempDir::with_prefix(prefix).unwrap();
    let config = common::create_config(&tmpdir, store_pass.clone()).await;
    let mut server = StandaloneServer::new(config.clone()).await.unwrap();
    server.run(store_pass.clone()).await.unwrap();
    let client =
        ipc_keystore_connect(config.connection_url.clone(), store_pass.clone())
            .await
            .unwrap();
    (server, client, tmpdir)
}

/// A bundle exported via lair's IPC verb must be unlockable by stand-alone
/// `hc_seed_bundle` tooling — i.e. the on-disk format isn't lair-specific.
/// This is the cross-tool portability proof: we never let lair touch the
/// unlock side, only `UnlockedSeedBundle::from_locked` + `unlock`.
#[tokio::test(flavor = "multi_thread")]
async fn exported_bundle_unlocks_via_hc_seed_bundle_directly() {
    let store_pass = Arc::new(Mutex::new(sodoken::LockedArray::from(
        b"store-pass".to_vec(),
    )));
    let bundle_pass = Arc::new(Mutex::new(sodoken::LockedArray::from(
        b"correct horse battery staple".to_vec(),
    )));

    let (_server, client, _tmpdir) =
        spawn_keystore("lair-portable-a", store_pass).await;

    let seed_info = client.new_seed("root".into(), None, true).await.unwrap();

    let locked_bundle = client
        .export_seed_bundle_by_tag(
            "root".into(),
            bundle_pass.clone(),
            PwHashLimits::Minimum,
        )
        .await
        .unwrap();

    // Drive the unlock side purely through hc_seed_bundle's public API —
    // no lair, no IPC, no prehashing, just `from_locked` + `unlock`.
    let cipher =
        hc_seed_bundle::UnlockedSeedBundle::from_locked(&locked_bundle)
            .await
            .unwrap()
            .into_iter()
            .find_map(|c| match c {
                hc_seed_bundle::LockedSeedCipher::PwHash(pw) => Some(pw),
                _ => None,
            })
            .expect("bundle contains a PwHash cipher");

    let unlocked = cipher.unlock(bundle_pass).await.expect(
        "hc_seed_bundle unlocks lair-produced bundle with raw passphrase",
    );

    // The ed25519 pubkey derived from the seed inside the bundle must match
    // the one lair reported when it created the seed.
    assert_eq!(
        unlocked.get_sign_pub_key().as_slice(),
        seed_info.ed25519_pub_key.as_ref(),
    );

    client.shutdown().await.unwrap();
}

/// Importing with the wrong passphrase must fail rather than silently
/// inserting garbage.
#[tokio::test(flavor = "multi_thread")]
async fn import_seed_bundle_with_wrong_passphrase_fails() {
    let store_pass = Arc::new(Mutex::new(sodoken::LockedArray::from(
        b"store-pass".to_vec(),
    )));
    let right_pass = Arc::new(Mutex::new(sodoken::LockedArray::from(
        b"the right one".to_vec(),
    )));
    let wrong_pass = Arc::new(Mutex::new(sodoken::LockedArray::from(
        b"the wrong one".to_vec(),
    )));

    let (_server_a, client_a, _tmpdir_a) =
        spawn_keystore("lair-wrongpass-a", store_pass.clone()).await;
    client_a.new_seed("root".into(), None, true).await.unwrap();
    let locked_bundle = client_a
        .export_seed_bundle_by_tag(
            "root".into(),
            right_pass,
            PwHashLimits::Minimum,
        )
        .await
        .unwrap();
    client_a.shutdown().await.unwrap();

    let (_server_b, client_b, _tmpdir_b) =
        spawn_keystore("lair-wrongpass-b", store_pass).await;
    let result = client_b
        .import_seed_bundle(locked_bundle, wrong_pass, "root".into(), true)
        .await;
    assert!(result.is_err(), "import with wrong passphrase must error");

    // The keystore must not contain a "root" entry after a failed import.
    assert!(client_b.get_entry("root".into()).await.is_err());

    client_b.shutdown().await.unwrap();
}

/// Asking to export a tag that doesn't exist must surface as an error,
/// not panic and not return an empty bundle.
#[tokio::test(flavor = "multi_thread")]
async fn export_seed_bundle_for_missing_tag_fails() {
    let store_pass = Arc::new(Mutex::new(sodoken::LockedArray::from(
        b"store-pass".to_vec(),
    )));
    let bundle_pass = Arc::new(Mutex::new(sodoken::LockedArray::from(
        b"bundle-pass".to_vec(),
    )));

    let (_server, client, _tmpdir) =
        spawn_keystore("lair-missingtag", store_pass).await;

    let result = client
        .export_seed_bundle_by_tag(
            "no-such-tag".into(),
            bundle_pass,
            PwHashLimits::Minimum,
        )
        .await;
    assert!(result.is_err(), "exporting a missing tag must error");

    client.shutdown().await.unwrap();
}

/// A seed created with `exportable: false` must not be exportable as a
/// bundle either — otherwise the flag would be a paper protection.
#[tokio::test(flavor = "multi_thread")]
async fn export_seed_bundle_for_non_exportable_seed_fails() {
    let store_pass = Arc::new(Mutex::new(sodoken::LockedArray::from(
        b"store-pass".to_vec(),
    )));
    let bundle_pass = Arc::new(Mutex::new(sodoken::LockedArray::from(
        b"bundle-pass".to_vec(),
    )));

    let (_server, client, _tmpdir) =
        spawn_keystore("lair-nonexport", store_pass).await;

    // exportable: false
    client
        .new_seed("locked-root".into(), None, false)
        .await
        .unwrap();

    let result = client
        .export_seed_bundle_by_tag(
            "locked-root".into(),
            bundle_pass,
            PwHashLimits::Minimum,
        )
        .await;
    assert!(
        result.is_err(),
        "exporting a non-exportable seed as a bundle must error",
    );

    client.shutdown().await.unwrap();
}
