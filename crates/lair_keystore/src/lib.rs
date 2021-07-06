#![deny(missing_docs)]
#![deny(warnings)]
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

    let internal::pid_check::PidCheckResult { store_file } =
        internal::pid_check::pid_check(&config)?;

    ipc::spawn_bind_server_ipc(config, store_file).await?;

    Ok(())
}

/// Gen loop of lair executable.
pub async fn execute_load_ed25519_keypair(
    load_ed25519_keypair: std::path::PathBuf,
) -> LairResult<()> {
    let mut config = Config::builder();

    if let Some(lair_dir) = std::env::var_os("LAIR_DIR") {
        config = config.set_root_path(lair_dir);
    }

    let config = config.build();

    println!("#lair-keystore-dir:{:?}#", config.get_root_path());

    let internal::pid_check::PidCheckResult { store_file } =
        internal::pid_check::pid_check(&config)?;

    let store_actor =
        store::spawn_entry_store_actor(config.clone(), store_file).await?;

    use std::fs::File;
    let file = File::open(load_ed25519_keypair)?;
    let blob = BufReader::new(file)
        .lines()
        .map(|line| {
            line.and_then(|v| {
                v.parse().map_err(|e| Error::new(ErrorKind::InvalidData, e))
            })
        })
        .collect::<Result<Vec<u8>, Error>>()?;

    let keypair = entry::EntrySignEd25519 {
        priv_key:
            lair_keystore_api::internal::sign_ed25519::SignEd25519PrivKey::from(
                blob[64..].to_vec(),
            ),
        pub_key:
            lair_keystore_api::internal::sign_ed25519::SignEd25519PubKey::from(
                blob[32..64].to_vec(),
            ),
    };

    store_actor
        .add_initial_sign_ed25519_keypair(keypair)
        .await?;
    Ok(())
}
