use hc_seed_bundle::dependencies::sodoken;
use lair_keystore_api::prelude::*;
use std::{env::current_dir, path::PathBuf};
use tempdir::TempDir;

#[cfg(not(windows))]
#[tokio::test(flavor = "multi_thread")]
async fn lair_config_connection_url_relative_root() {
    // Lair config should use an absolute path for 'connection_url'
    // when passed an relative path for 'lair_root'

    let passphrase = sodoken::BufRead::from(&b"passphrase"[..]);

    let dir = TempDir::new_in(".", "example").unwrap();

    let mut relative_lair_root = PathBuf::from(".");
    relative_lair_root.push(dir.path().components().last().unwrap());

    let config = hc_seed_bundle::PwHashLimits::Minimum
        .with_exec(|| {
            LairServerConfigInner::new(relative_lair_root, passphrase.clone())
        })
        .await
        .unwrap();

    let mut expected_path = current_dir().unwrap();
    expected_path.push(dir.path().components().last().unwrap());
    let expected_path_str = expected_path.to_str().unwrap();

    assert!(config.connection_url.as_str().contains(expected_path_str));
}

#[cfg(not(windows))]
#[tokio::test(flavor = "multi_thread")]
async fn lair_config_connection_url_absolute_root() {
    // Lair config should use an absolute path for 'connection_url'
    // when passed an absolute path for 'lair_root'

    let passphrase = sodoken::BufRead::from(&b"passphrase"[..]);

    let dir = TempDir::new_in(".", "example").unwrap();
    let mut absolute_lair_root = current_dir().unwrap();
    absolute_lair_root.push(dir.path().components().last().unwrap());

    let config = hc_seed_bundle::PwHashLimits::Minimum
        .with_exec(|| {
            LairServerConfigInner::new(
                absolute_lair_root.clone(),
                passphrase.clone(),
            )
        })
        .await
        .unwrap();

    let mut expected_path = current_dir().unwrap();
    expected_path.push(dir.path().components().last().unwrap());
    let expected_path_str = expected_path.to_str().unwrap();

    assert!(config.connection_url.as_str().contains(expected_path_str));
}
