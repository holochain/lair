// grrr clippy... you cannot specify extra bounds with the async fn syntax...
#![allow(clippy::manual_async_fn)]
// default implementations don't always make sense...
#![allow(clippy::new_without_default)]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(warnings)]

//! Secret lair private keystore
//!
//! [![Project](https://img.shields.io/badge/project-holochain-blue.svg?style=flat-square)](http://holochain.org/)
//! [![Forum](https://img.shields.io/badge/chat-forum%2eholochain%2enet-blue.svg?style=flat-square)](https://forum.holochain.org)
//! [![Chat](https://img.shields.io/badge/chat-chat%2eholochain%2enet-blue.svg?style=flat-square)](https://chat.holochain.org)
//!
//! [![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
//!
//! This crate mostly provides the `lair-keystore` executable allowing
//! initialization, configuration, and running of a Lair keystore.
//!
//! If you want to run an in-process keystore, this crate also provides the
//! canonical sqlite store.
//!
//! For making use of a Lair keystore in a client application, see the
//! lair_keystore_api crate.
//!
//! # Naming quirks
//!
//! - Install with an underscore: `cargo install lair_keystore`
//! - Use binary with a dash: `$ lair-keystore help`
//! - Cargo.toml with an underscore:
//!
//! ```text
//! [dependencies]
//! lair_keystore = "0.1.1"
//! ```
//!
//! - Library usage with underscores and postfix `_lib`:
//!
//! ```
//! use lair_keystore_lib::create_sql_pool_factory;
//! let _sqlite_store_factory = create_sql_pool_factory(".");
//! ```
//!
//! We might clean up the `_lib` thing in version "0.2.0".
//!
//! # `lair-keystore` commandline executable usage:
//!
#![doc = include_str!("./docs/help.md")]
#![doc = include_str!("./docs/init-help.md")]
#![doc = include_str!("./docs/url-help.md")]
#![doc = include_str!("./docs/import-seed-help.md")]
#![doc = include_str!("./docs/server-help.md")]

include!(concat!(env!("OUT_DIR"), "/ver.rs"));

/// Re-exported dependencies.
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

#[doc(inline)]
pub use store_sqlite::create_sql_pool_factory;

#[cfg(test)]
mod server_test;
