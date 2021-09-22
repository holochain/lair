// grrr clippy... you cannot specify extra bounds with the async fn syntax...
#![allow(clippy::manual_async_fn)]
// default implementations don't always make sense...
#![allow(clippy::new_without_default)]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(warnings)]

//! secret lair private keystore types

include!(concat!(env!("OUT_DIR"), "/ver.rs"));

/// Lair Result Type
pub type LairResult<T> = Result<T, one_err::OneErr>;

pub mod internal;
pub mod sodium_secretstream;
