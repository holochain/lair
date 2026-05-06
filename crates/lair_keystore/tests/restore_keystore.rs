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
