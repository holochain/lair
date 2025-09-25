mod common;

use assert_cmd::Command;
use common::create_config;
use lair_keystore::dependencies::*;
use std::sync::{Arc, Mutex};
use std::{fs::File, io::Write};

#[tokio::test(flavor = "multi_thread")]
async fn test_url_command_only_outputs_connection_url() {
    let tmp_dir = tempfile::TempDir::with_prefix("lair keystore test").unwrap();
    let passphrase = Arc::new(Mutex::new(sodoken::LockedArray::from(
        b"passphrase".to_vec(),
    )));

    let config = create_config(&tmp_dir, passphrase.clone()).await;
    let config_path = tmp_dir.path().join("lair-keystore-config.yaml");
    let mut config_file =
        File::create_new(config_path).expect("test config file already exists");

    config_file
        .write_all(config.to_string().as_bytes())
        .expect("failed to write config to file");

    let mut cmd = Command::cargo_bin("lair-keystore").unwrap();
    cmd.env("RUST_LOG", "trace"); // Enable all logging levels to make sure nothing gets printed to stdout
    cmd.arg(format!("--lair-root={}", tmp_dir.path().display()));
    cmd.arg("url");

    let expected_stdout = format!("{}\n", config.connection_url);
    cmd.assert().success().stdout(expected_stdout);
}
