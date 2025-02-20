use crate::dependencies::sodoken;
use parking_lot::Mutex;
use std::sync::Arc;

pub type SharedLockedArray = Arc<Mutex<sodoken::LockedArray>>;

pub type SharedSizedLockedArray<const N: usize> =
    Arc<Mutex<sodoken::SizedLockedArray<N>>>;
