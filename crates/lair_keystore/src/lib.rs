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

    let internal::pid_check::PidCheckResult { sql_db_path } =
        internal::pid_check::pid_check(&config)?;

    ipc::spawn_bind_server_ipc(config, sql_db_path).await?;

    Ok(())
}
