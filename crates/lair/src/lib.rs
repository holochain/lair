#![deny(missing_docs)]
#![deny(warnings)]
//! secret lair private keystore

use lair_api::{Config, LairError, LairResult};
use std::sync::Arc;

mod statics;
pub use statics::*;

pub mod internal;

pub mod entry;

/// Main loop of lair executable.
pub async fn execute_lair() -> LairResult<()> {
    let config = Config::builder().build();

    let internal::pid_check::PidCheckResult { .. } =
        internal::pid_check::pid_check(&config)?;

    // wait forever... i.e. ctrl-c
    futures::future::pending::<()>().await;

    Ok(())
}
