use lair_keystore::dependencies::*;
use lair_keystore::store_lock::acquire_store_lock;
use lair_keystore_api::prelude::*;
use std::sync::{Arc, Mutex};

async fn create_config(
    tmpdir: &tempfile::TempDir,
    passphrase: SharedLockedArray,
) -> LairServerConfig {
    Arc::new(
        PwHashLimits::Minimum
            .with_exec(|| LairServerConfigInner::new(tmpdir.path(), passphrase))
            .await
            .unwrap(),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn in_proc_keystore_persists_and_locks() {
    let tmpdir =
        tempfile::TempDir::with_prefix("lair-store-lock-test").unwrap();
    let passphrase = Arc::new(Mutex::new(sodoken::LockedArray::from(
        b"passphrase".to_vec(),
    )));
    let config = create_config(&tmpdir, passphrase.clone()).await;

    {
        let keystore = lair_keystore::InProcKeystore::new(
            config.clone(),
            passphrase.clone(),
        )
        .await
        .unwrap();

        let client = keystore.new_client().await.unwrap();
        client
            .new_seed("persist".into(), None, false)
            .await
            .unwrap();

        // a competing in-process keystore for the same store is rejected
        assert!(lair_keystore::InProcKeystore::new(
            config.clone(),
            passphrase.clone()
        )
        .await
        .is_err());

        // close the connection so the background server task releases its
        // store handle
        client.shutdown().await.unwrap();
    }

    // wait for background connection tasks to release their store handles
    let store_file = config.store_file.clone();
    let lock =
        tokio::time::timeout(std::time::Duration::from_secs(5), async move {
            loop {
                match acquire_store_lock(&store_file) {
                    Ok(lock) => break lock,
                    Err(_) => {
                        tokio::time::sleep(std::time::Duration::from_millis(10))
                            .await
                    }
                }
            }
        })
        .await
        .expect("store lock was not released");
    drop(lock);

    // reopening the store sees the persisted seed
    let keystore = lair_keystore::InProcKeystore::new(config, passphrase)
        .await
        .unwrap();
    let client = keystore.new_client().await.unwrap();
    let entries = client.list_entries().await.unwrap();
    assert!(entries.iter().any(|entry| matches!(
        entry,
        LairEntryInfo::Seed { tag, .. } if &**tag == "persist"
    )));
}
