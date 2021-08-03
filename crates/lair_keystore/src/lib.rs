#![deny(missing_docs)]
#![deny(warnings)]
// it's not possible to specify required
// bounds with the `async fn` syntax.
#![allow(clippy::manual_async_fn)]

//! secret lair private keystore
//!
//! # Usage
//!
//! ## Communications  Protocol
//!
//! See [docs/protocol.md](./docs/protocol.md)

include!(concat!(env!("OUT_DIR"), "/ver.rs"));

use crate::store::EntryStoreSender;
use lair_keystore_api::*;
use std::io::{BufRead, BufReader, Error, ErrorKind};
use std::sync::Arc;

pub mod internal;

pub mod store;

pub mod ipc;

/// Main loop of lair executable.
pub async fn execute_lair() -> LairResult<()> {
    let mut config = Config::builder();

    if let Some(lair_dir) = std::env::var_os("LAIR_DIR") {
        config = config.set_root_path(lair_dir);
    }

    let config = config.build();

    println!("#lair-keystore-dir:{:?}#", config.get_root_path());

    let internal::pid_check::PidCheckResult {} =
        internal::pid_check::pid_check(&config)?;

    ipc::spawn_bind_server_ipc(config).await?;

    Ok(())
}

/// Gen loop of lair executable with file path.
pub async fn execute_load_ed25519_keypair_from_file(
    load_ed25519_keypair_from_file: std::path::PathBuf,
) -> LairResult<()> {
    use std::fs::File;
    let file = File::open(load_ed25519_keypair_from_file)?;
    let encrypted_blob = BufReader::new(file)
        .lines()
        .map(|line| {
            line.and_then(|v| {
                v.parse().map_err(|e| Error::new(ErrorKind::InvalidData, e))
            })
        })
        .collect::<Result<Vec<u8>, Error>>()?;
    execute_load_ed25519_keypair(encrypted_blob.to_vec()).await
}

/// Gen loop of lair executable with encrypted blob.
pub async fn execute_load_ed25519_keypair(
    load_ed25519_keypair: Vec<u8>,
) -> LairResult<()> {
    let mut config = Config::builder();

    if let Some(lair_dir) = std::env::var_os("LAIR_DIR") {
        config = config.set_root_path(lair_dir);
    }

    let config = config.build();

    println!("#lair-keystore-dir:{:?}#", config.get_root_path());

    let internal::pid_check::PidCheckResult {} =
        internal::pid_check::pid_check(&config)?;

    let store_actor = store::spawn_entry_store_actor(config.clone()).await?;

    let keypair = entry::EntrySignEd25519 {
        priv_key:
            lair_keystore_api::internal::sign_ed25519::SignEd25519PrivKey::from(
                load_ed25519_keypair[64..].to_vec(),
            ),
        pub_key:
            lair_keystore_api::internal::sign_ed25519::SignEd25519PubKey::from(
                load_ed25519_keypair[32..64].to_vec(),
            ),
    };

    store_actor
        .add_initial_sign_ed25519_keypair(keypair)
        .await?;
    Ok(())
}
