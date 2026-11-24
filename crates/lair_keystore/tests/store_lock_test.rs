use lair_keystore::dependencies::*;
use lair_keystore::store_lock::acquire_store_lock;
use lair_keystore_api::prelude::*;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

const HOLD_ENV: &str = "LAIR_TEST_HOLD_STORE_LOCK";

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

#[test]
fn cross_process_hold_child() {
    // This test doubles as the helper process for `cross_process_ownership`.
    // When the env var is absent it is a no-op so normal test runs pass.
    let store_file = match std::env::var_os(HOLD_ENV) {
        Some(path) => std::path::PathBuf::from(path),
        None => return,
    };

    let _lock = acquire_store_lock(&store_file).unwrap();

    // signal the parent that we hold the lock
    println!("\nLOCKED");
    std::io::stdout().flush().unwrap();

    // hold the lock until the parent kills us
    std::thread::sleep(std::time::Duration::from_secs(60));
}

#[test]
fn cross_process_ownership() {
    let tmpdir =
        tempfile::TempDir::with_prefix("lair-store-lock-test").unwrap();
    let store_file = tmpdir.path().join("store_file");

    let mut child = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("cross_process_hold_child")
        .arg("--nocapture")
        .env(HOLD_ENV, &store_file)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();

    let stdout = child.stdout.take().unwrap();
    let lines = BufReader::new(stdout).lines();
    let mut locked = false;
    for line in lines {
        if line.unwrap().trim() == "LOCKED" {
            locked = true;
            break;
        }
    }
    assert!(locked, "child failed to acquire the store lock");

    // we cannot acquire the store owned by the child process
    assert!(acquire_store_lock(&store_file).is_err());

    child.kill().unwrap();
    child.wait().unwrap();

    // the OS releases the lock when the owning process exits
    let _lock = acquire_store_lock(&store_file).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn standalone_servers_are_exclusive() {
    let tmpdir =
        tempfile::TempDir::with_prefix("lair-store-lock-test").unwrap();
    let passphrase = Arc::new(Mutex::new(sodoken::LockedArray::from(
        b"passphrase".to_vec(),
    )));
    let config = create_config(&tmpdir, passphrase).await;

    let _server = lair_keystore::server::StandaloneServer::new(config.clone())
        .await
        .unwrap();

    // a second server for the same store is rejected
    assert!(lair_keystore::server::StandaloneServer::new(config.clone())
        .await
        .is_err());
}
