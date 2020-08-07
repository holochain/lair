#![deny(missing_docs)]
#![deny(warnings)]
//! secret lair private keystore

use lair_api::{LairError, LairResult};

mod statics;
pub use statics::*;

pub mod internal;
