// grrr clippy... you cannot specify extra bounds with the async fn syntax...
#![allow(clippy::manual_async_fn)]
// default implementations don't always make sense...
#![allow(clippy::new_without_default)]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(warnings)]

//! secret lair private keystore

include!(concat!(env!("OUT_DIR"), "/ver.rs"));

pub mod pid_check;
pub mod server;
pub mod store_sqlite;
