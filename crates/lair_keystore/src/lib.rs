#![deny(missing_docs)]
#![deny(warnings)]
//! secret lair private keystore

use lair_keystore_api::{Config, LairError, LairResult};
use std::sync::Arc;

mod statics;
pub use statics::*;

pub mod internal;

pub mod entry;

pub mod store;

pub mod ipc;

/// Main loop of lair executable.
pub async fn execute_lair() -> LairResult<()> {
    let mut config = Config::builder();

    if let Some(lair_dir) = std::env::var_os("LAIR_DIR") {
        config = config.set_root_path(lair_dir);
    }

    let config = config.build();

    let internal::pid_check::PidCheckResult { store_file } =
        internal::pid_check::pid_check(&config)?;

    ipc::spawn_bind_server_ipc(config, store_file).await?;

    Ok(())
}
