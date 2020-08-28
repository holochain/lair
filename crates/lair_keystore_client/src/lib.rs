#![deny(missing_docs)]
#![deny(warnings)]
//! client connector to secret lair private keystore

include!(concat!(env!("OUT_DIR"), "/ver.rs"));

use lair_keystore_api::*;
use std::sync::Arc;

pub mod internal;
