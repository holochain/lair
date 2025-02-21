use lair_keystore::dependencies::*;
use lair_keystore_api::prelude::*;
use parking_lot::Mutex;
use std::sync::Arc;

pub async fn create_config(
    tmpdir: &tempdir::TempDir,
    passphrase: Arc<Mutex<sodoken::LockedArray>>,
) -> Arc<LairServerConfigInner> {
    // create the config for the test server
    Arc::new(
        hc_seed_bundle::PwHashLimits::Minimum
            .with_exec(|| LairServerConfigInner::new(tmpdir.path(), passphrase))
            .await
            .unwrap(),
    )
}

pub async fn connect_with_config(
    config: Arc<LairServerConfigInner>,
    passphrase: Arc<Mutex<sodoken::LockedArray>>,
) -> LairResult<LairClient> {
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
pub async fn connect(tmpdir: &tempdir::TempDir) -> LairClient {
    // set up a passphrase
    let passphrase = Arc::new(Mutex::new(sodoken::LockedArray::from(
        b"passphrase".to_vec(),
    )));

    let config = create_config(tmpdir, passphrase.clone()).await;

    connect_with_config(config, passphrase).await.unwrap()
}
