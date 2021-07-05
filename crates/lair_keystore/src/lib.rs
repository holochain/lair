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
pub async fn execute_load_ed25519_keypair_from_yaml(
    load_ed25519_keypair_from_yaml: std::path::PathBuf,
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
    let file = File::open(load_ed25519_keypair_from_yaml)?;
    let keypair: entry::EntrySignEd25519 = serde_yaml::from_reader(&file)?;
    store_actor
        .add_initial_sign_ed25519_keypair(keypair)
        .await?;
    Ok(())
}
