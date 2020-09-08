use crate::*;

/// If any clones of this struct are dropped,
/// they all say we should stop looping.
/// You can `mix` in a future that will abort
/// if the kill switch is triggered.
#[derive(Clone)]
pub struct KillSwitch(
    Arc<(
        std::sync::atomic::AtomicBool,
        tokio::sync::broadcast::Sender<()>,
    )>,
);

impl Drop for KillSwitch {
    fn drop(&mut self) {
        (self.0).0.store(false, std::sync::atomic::Ordering::SeqCst);
        let _ = (self.0).1.send(());
    }
}

impl KillSwitch {
    /// Create a new kill switch
    pub fn new() -> Self {
        let (tx, _) = tokio::sync::broadcast::channel(10);
        Self(Arc::new((std::sync::atomic::AtomicBool::new(true), tx)))
    }

    /// Should we continue?
    pub fn cont(&self) -> bool {
        (self.0).0.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Mix in another future so it will abort
    /// if this kill switch is triggered.
    pub async fn mix<R, F>(&self, f: F) -> LairResult<R>
    where
        F: std::future::Future<Output = LairResult<R>>,
    {
        if !self.cont() {
            return Err("kill_switch triggered".into());
        }
        let mut r = (self.0).1.subscribe();
        let r = r.recv();
        tokio::pin!(r, f);
        match futures::future::select(r, f).await {
            futures::future::Either::Left(_) => {
                Err("kill_switch triggered".into())
            }
            futures::future::Either::Right((res, _)) => res,
        }
    }
}

impl Default for KillSwitch {
    fn default() -> Self {
        Self::new()
    }
}
