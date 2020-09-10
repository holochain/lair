//! Internal utility functions - note, the api for anything in this module
//! is unstable and may change even for patch versions of this library.

/// utilities for lair build.rs files
pub mod build;

pub mod codec;
pub mod ipc;
pub(crate) mod rayon;
pub mod sign_ed25519;
pub mod tls;
pub mod util;
pub mod wire;
