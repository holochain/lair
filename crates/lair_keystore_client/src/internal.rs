//! Internal utility functions - note, the api for anything in this module
//! is unstable and may change even for patch versions of this library.

mod run_lair_executable;
pub use run_lair_executable::*;
mod cargo_build_lair_executable;
pub use cargo_build_lair_executable::*;
