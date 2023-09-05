use hc_seed_bundle::dependencies::sodoken;
use lair_keystore_api::prelude::*;
use std::{env::current_dir, path::PathBuf};

#[cfg(not(windows))]
#[tokio::test(flavor = "multi_thread")]
async fn lair_config_connection_url_relative_root() {
    use std::fs::{create_dir, remove_dir};

    let passphrase = sodoken::BufRead::from(&b"passphrase"[..]);

    let _ = create_dir("./config-root-path-test");
    let config = hc_seed_bundle::PwHashLimits::Minimum
        .with_exec(|| {
            LairServerConfigInner::new(
                "./config-root-path-test",
                passphrase.clone(),
            )
        })
        .await
        .unwrap();
    let _ = remove_dir("./config-root-path-test");

    let mut expected_path: PathBuf = current_dir().unwrap();
    expected_path.push("config-root-path-test");
    let expected_path_str = expected_path.to_str().unwrap();

    assert_eq!(
        true,
        config.connection_url.as_str().contains(expected_path_str)
    );
}

#[cfg(not(windows))]
#[tokio::test(flavor = "multi_thread")]
async fn lair_config_connection_url_absolute_root() {
    use std::fs::{create_dir, remove_dir};

    let passphrase = sodoken::BufRead::from(&b"passphrase"[..]);

    let _ = create_dir("./config-root-path-test");
    let mut lair_root = current_dir().unwrap();
    lair_root.push("config-root-path-test");
    let config = hc_seed_bundle::PwHashLimits::Minimum
        .with_exec(|| {
            LairServerConfigInner::new(lair_root.clone(), passphrase.clone())
        })
        .await
        .unwrap();
    let _ = remove_dir("./config-root-path-test");

    let mut expected_path: PathBuf = current_dir().unwrap();
    expected_path.push("config-root-path-test");
    let expected_path_str = lair_root.to_str().unwrap();

    assert_eq!(
        true,
        config.connection_url.as_str().contains(expected_path_str)
    );
}
