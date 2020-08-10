#![deny(missing_docs)]
#![deny(warnings)]
//! secret lair private keystore

use lair_api::{Config, LairError, LairResult};

mod statics;
pub use statics::*;

pub mod internal;

mod pid_check;
pub use pid_check::*;

/// Main loop of lair executable.
pub async fn execute_lair() -> LairResult<()> {
    let config = Config::builder().build();

    let PidCheckResult { .. } = pid_check(&config)?;

    // wait forever... i.e. ctrl-c
    futures::future::pending::<()>().await;

    Ok(())
}
