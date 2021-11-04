use lair_keystore_api::dependencies::*;
use lair_keystore_api::in_proc_keystore::*;
use lair_keystore_api::mem_store::*;
use lair_keystore_api::prelude::*;
use std::sync::Arc;

fn init_tracing() {
    let _ = tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .compact()
            .finish(),
    );
}

async fn spawn_test(test_name: &str) -> LairClient {
    init_tracing();

    let passphrase = sodoken::BufRead::from(&b"passphrase"[..]);

    let mut config = hc_seed_bundle::PwHashLimits::Minimum
        .with_exec(|| LairServerConfigInner::new("/", passphrase.clone()))
        .await
        .unwrap();

    let fix_cmd = assert_cmd::cargo::cargo_bin("fixture-sig-fallback");

    config.signature_fallback = LairServerSignatureFallback::Command {
        program: fix_cmd,
        args: Some([test_name.to_string()].to_vec()),
    };

    let keystore = InProcKeystore::new(
        Arc::new(config),
        create_mem_store_factory(),
        passphrase.clone(),
    )
    .await
    .unwrap();

    keystore.new_client().await.unwrap()
}

// - `alternate` - switch between success and error responses
#[tokio::test(flavor = "multi_thread")]
async fn sf_alternate() {
    let client = spawn_test("alternate").await;

    // our fixture bin alternates between "good" sigs and errors
    let sig_good = client
        .sign_by_pub_key([0; 32].into(), None, b"hello".to_vec().into())
        .await
        .unwrap();
    assert_eq!([0; 64], *sig_good.0);

    // our fixture bin alternates between "good" sigs and errors
    assert!(client
        .sign_by_pub_key([0; 32].into(), None, b"hello".to_vec().into(),)
        .await
        .is_err());
}

// - `one_and_done` - one success, then close executable
#[tokio::test(flavor = "multi_thread")]
async fn sf_one_and_done() {
    let client = spawn_test("one_and_done").await;

    println!("req 1");

    let sig_good = client
        .sign_by_pub_key([0; 32].into(), None, b"hello".to_vec().into())
        .await
        .unwrap();
    assert_eq!([0; 64], *sig_good.0);

    // give windows a chance to understand the broken pipe :/
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    println!("req 2");

    // even though our executable exited between the requests
    // it should be re-spawned and accept the second request
    let sig_good = client
        .sign_by_pub_key([0; 32].into(), None, b"hello".to_vec().into())
        .await
        .unwrap();
    assert_eq!([0; 64], *sig_good.0);
}

// - `never_3` - takes 3 requests without responding and closes
#[tokio::test(flavor = "multi_thread")]
async fn sf_never_3() {
    let client = spawn_test("never_3").await;

    let res = futures::future::join_all([
        client.sign_by_pub_key([0; 32].into(), None, b"hello".to_vec().into()),
        client.sign_by_pub_key([0; 32].into(), None, b"hello".to_vec().into()),
        client.sign_by_pub_key([0; 32].into(), None, b"hello".to_vec().into()),
    ])
    .await;

    for res in res {
        assert!(res.is_err());
    }
}
