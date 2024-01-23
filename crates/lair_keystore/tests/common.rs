use lair_keystore::dependencies::*;
use lair_keystore_api::prelude::*;
use std::sync::Arc;

pub async fn create_config(tmpdir: &tempdir::TempDir, passphrase: sodoken::BufRead) -> Arc<LairServerConfigInner> {
    // create the config for the test server
    Arc::new(
        hc_seed_bundle::PwHashLimits::Minimum
            .with_exec(|| {
                LairServerConfigInner::new(tmpdir.path(), passphrase.clone())
            })
            .await
            .unwrap(),
    )
}

pub async fn connect_with_config(config: Arc<LairServerConfigInner>, passphrase: sodoken::BufRead) -> LairResult<lair_keystore_api::LairClient> {
    // execute the server
    lair_keystore::server::StandaloneServer::new(config.clone())
        .await?
        .run(passphrase.clone())
        .await?;

    // create a client connection
    lair_keystore_api::ipc_keystore::ipc_keystore_connect(
        config.connection_url.clone(),
        passphrase,
    )
    .await
}

#[allow(dead_code)]
pub async fn connect(tmpdir: &tempdir::TempDir) -> lair_keystore_api::LairClient {
    // set up a passphrase
    let passphrase = sodoken::BufRead::from(&b"passphrase"[..]);

    let config = create_config(tmpdir, passphrase.clone()).await;

    connect_with_config(config, passphrase).await.unwrap()
}
