//! Common types used in the Lair keystore API.

use crate::dependencies::sodoken;
use std::sync::{Arc, Mutex};

/// SharedLockedArray type alias for a [sodoken::LockedArray] wrapped in an [Arc] and [Mutex].
pub type SharedLockedArray = Arc<Mutex<sodoken::LockedArray>>;

/// SharedSizedLockedArray type alias for a [sodoken::SizedLockedArray] wrapped in an [Arc] and [Mutex].
pub type SharedSizedLockedArray<const N: usize> =
    Arc<Mutex<sodoken::SizedLockedArray<N>>>;
