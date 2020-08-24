use crate::*;

/// If any clones of this struct are dropped, they all say we should stop looping.
#[derive(Clone)]
pub struct KillSwitch(Arc<std::sync::atomic::AtomicBool>);

impl Drop for KillSwitch {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::Relaxed)
    }
}

impl KillSwitch {
    /// Create a new kill switch
    pub fn new() -> Self {
        Self(Arc::new(std::sync::atomic::AtomicBool::new(true)))
    }

    /// Should we continue?
    pub fn cont(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl Default for KillSwitch {
    fn default() -> Self {
        Self::new()
    }
}
