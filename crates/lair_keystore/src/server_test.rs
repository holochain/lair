use crate::*;
use std::sync::Arc;

async fn connect(tmpdir: &tempdir::TempDir) -> lair_keystore_api::LairClient {
    // set up a passphrase
    let passphrase = sodoken::BufRead::from(&b"passphrase"[..]);

    // create the config for the test server
    let config = Arc::new(
        hc_seed_bundle::PwHashLimits::Minimum
            .with_exec(|| {
                LairServerConfigInner::new(tmpdir.path(), passphrase.clone())
            })
            .await
            .unwrap(),
    );

    // execute the server
    crate::server::StandaloneServer::new(config.clone())
        .await
        .unwrap()
        .run(passphrase.clone())
        .await
        .unwrap();

    // create a client connection
    lair_keystore_api::ipc_keystore::ipc_keystore_connect(
        config.connection_url.clone(),
        passphrase,
    )
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn server_test_happy_path() {
    let tmpdir = tempdir::TempDir::new("lair keystore test").unwrap();
    let tmpdir2 = tempdir::TempDir::new("lair keystore test2").unwrap();

    let client = connect(&tmpdir).await;
    let client2 = connect(&tmpdir2).await;

    // create a new seed
    let seed_info_ref = client
        .new_seed("test-tag".into(), None, true)
        .await
        .unwrap();

    // new seed with same tag errors
    assert!(client
        .new_seed("test-tag".into(), None, true)
        .await
        .is_err());

    // list keystore contents
    let mut entry_list = client.list_entries().await.unwrap();

    assert_eq!(1, entry_list.len());
    match entry_list.remove(0) {
        LairEntryInfo::Seed { tag, seed_info } => {
            assert_eq!("test-tag", &*tag);
            assert_eq!(seed_info, seed_info_ref);
        }
        oth => panic!("unexpected: {:?}", oth),
    }

    let entry = client.get_entry("test-tag".into()).await.unwrap();

    match entry {
        LairEntryInfo::Seed { tag, seed_info } => {
            assert_eq!("test-tag", &*tag);
            assert_eq!(seed_info, seed_info_ref);
        }
        oth => panic!("unexpected: {:?}", oth),
    }

    let sig = client
        .sign_by_pub_key(
            seed_info_ref.ed25519_pub_key.clone(),
            None,
            b"hello".to_vec().into(),
        )
        .await
        .unwrap();
    assert!(seed_info_ref
        .ed25519_pub_key
        .verify_detached(sig, &b"hello"[..])
        .await
        .unwrap());

    // create a new deep-locked seed
    let _seed_info_ref_deep = hc_seed_bundle::PwHashLimits::Minimum
        .with_exec(|| {
            client.new_seed(
                "test-tag-deep".into(),
                Some(sodoken::BufRead::from(&b"deep"[..])),
                false,
            )
        })
        .await
        .unwrap();

    // create a new tls certificate
    let cert_info = client.new_wka_tls_cert("test-cert".into()).await.unwrap();
    println!("{cert_info:#?}");

    let priv_key = client
        .get_wka_tls_cert_priv_key("test-cert".into())
        .await
        .unwrap();
    println!("got priv key: {} bytes", priv_key.len());

    println!("{:#?}", client.list_entries().await.unwrap());

    // secretbox encrypt some data
    let (nonce, cipher) = client
        .secretbox_xsalsa_by_tag(
            "test-tag".into(),
            None,
            b"hello".to_vec().into(),
        )
        .await
        .unwrap();

    // make sure we can decrypt our own message
    let msg = client
        .secretbox_xsalsa_open_by_tag("test-tag".into(), None, nonce, cipher)
        .await
        .unwrap();

    assert_eq!(b"hello", &*msg);

    let seed_info_ref2 = client2
        .new_seed("test-tag2".into(), None, true)
        .await
        .unwrap();

    // try exporting the seed (just to ourselves)
    let (nonce, cipher) = client
        .export_seed_by_tag(
            "test-tag".into(),
            seed_info_ref.x25519_pub_key.clone(),
            seed_info_ref2.x25519_pub_key.clone(),
            None,
        )
        .await
        .unwrap();

    // try importing the exported seed
    let imported_seed_info = client2
        .import_seed(
            seed_info_ref.x25519_pub_key.clone(),
            seed_info_ref2.x25519_pub_key.clone(),
            None,
            nonce,
            cipher,
            "test-tag".into(),
            true,
        )
        .await
        .unwrap();

    assert_eq!(seed_info_ref, imported_seed_info);
}
