// grrr clippy... you cannot specify extra bounds with the async fn syntax...
#![allow(clippy::manual_async_fn)]
// default implementations don't always make sense...
#![allow(clippy::new_without_default)]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(warnings)]

//! Secret lair private keystore
#![doc = include_str!("./docs/help.md")]
#![doc = include_str!("./docs/init-help.md")]
#![doc = include_str!("./docs/url-help.md")]
#![doc = include_str!("./docs/import-seed-help.md")]
#![doc = include_str!("./docs/server-help.md")]

include!(concat!(env!("OUT_DIR"), "/ver.rs"));

/// re-exported dependencies
pub mod dependencies {
    pub use hc_seed_bundle::dependencies::*;
    pub use lair_keystore_api;
    pub use lair_keystore_api::dependencies::*;
    pub use rpassword;
    pub use structopt;
    pub use sysinfo;
    pub use tracing_subscriber;
}

use dependencies::*;
use lair_keystore_api::prelude::*;

pub(crate) mod sql;

pub mod pid_check;
pub mod server;
pub mod store_sqlite;

#[cfg(test)]
mod server_test;
