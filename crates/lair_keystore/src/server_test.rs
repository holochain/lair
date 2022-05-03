use crate::*;
use std::sync::Arc;

#[tokio::test(flavor = "multi_thread")]
async fn server_test_happy_path() {
    let tmpdir = tempdir::TempDir::new("lair keystore test").unwrap();

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
    let client = lair_keystore_api::ipc_keystore::ipc_keystore_connect(
        config.connection_url.clone(),
        passphrase,
    )
    .await
    .unwrap();

    // create a new seed
    let seed_info_ref = client.new_seed("test-tag".into(), None).await.unwrap();

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
            )
        })
        .await
        .unwrap();

    // create a new tls certificate
    let cert_info = client.new_wka_tls_cert("test-cert".into()).await.unwrap();
    println!("{:#?}", cert_info);

    let priv_key = client
        .get_wka_tls_cert_priv_key("test-cert".into())
        .await
        .unwrap();
    println!("got priv key: {} bytes", priv_key.len());

    println!("{:#?}", client.list_entries().await.unwrap());
}
