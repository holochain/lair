#![deny(missing_docs)]
#![deny(warnings)]
//! secret lair private keystore

use lair_api::{Config, LairError, LairResult};
use std::sync::Arc;

mod statics;
pub use statics::*;

pub mod internal;

pub mod entry;

pub mod store;

/// Main loop of lair executable.
pub async fn execute_lair() -> LairResult<()> {
    let mut config = Config::builder();

    if let Some(lair_dir) = std::env::var_os("LAIR_DIR") {
        config = config.set_root_path(lair_dir);
    }

    let config = config.build();

    let internal::pid_check::PidCheckResult { .. } =
        internal::pid_check::pid_check(&config)?;

    // wait forever... i.e. ctrl-c
    futures::future::pending::<()>().await;

    Ok(())
}
