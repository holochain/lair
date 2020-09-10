#![deny(missing_docs)]
#![deny(warnings)]
//! secret lair private keystore types

include!(concat!(env!("OUT_DIR"), "/ver.rs"));

use ghost_actor::dependencies::tracing::*;
use std::sync::Arc;

mod error;
pub use error::*;

mod config;
pub use config::*;

pub mod internal;
pub use internal::rayon::init_once_rayon_thread_pool;
pub(crate) use internal::rayon::rayon_exec;

pub mod entry;

pub mod actor;

pub mod ipc;

pub mod test;
