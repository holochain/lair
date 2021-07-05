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

use lair_keystore_api::*;
use std::sync::Arc;
use crate::store::EntryStoreSender;

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
pub async fn execute_gen() -> LairResult<()> {
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

    let keypair: entry::EntrySignEd25519 = lair_keystore_api::internal::sign_ed25519::sign_ed25519_keypair_new_from_entropy().await?;

    // TODO : handle the error here
    store_actor.add_initial_sign_ed25519_keypair(keypair).await?;

    Ok(())
}

