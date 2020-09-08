use crate::*;

/// Kill Callback - Invoked on Kill
pub type KillCallback = Box<
    dyn FnOnce() -> std::pin::Pin<
            Box<dyn std::future::Future<Output = ()> + 'static + Send>,
        >
        + 'static
        + Send,
>;

type IsWeak = bool;

type InnerArc = Arc<(
    std::sync::atomic::AtomicBool,
    tokio::sync::broadcast::Sender<()>,
    tokio::sync::Mutex<Vec<KillCallback>>,
)>;

/// If any clones of this struct are dropped,
/// they all say we should stop looping.
/// You can `mix` in a future that will abort
/// if the kill switch is triggered.
#[derive(Clone)]
pub struct KillSwitch {
    inner: InnerArc,
    is_weak: IsWeak,
}

fn cont(inner: &InnerArc) -> bool {
    inner.0.load(std::sync::atomic::Ordering::SeqCst)
}

macro_rules! inner_mix {
    ($inner:expr, $f:ident) => {{
        let mut r = $inner.1.subscribe();
        let r = r.recv();
        if !cont(&$inner) {
            // check *after* we create the receiver
            return Err("kill_switch triggered".into());
        }
        tokio::pin!(r, $f);
        match futures::future::select(r, $f).await {
            futures::future::Either::Left(_) => {
                Err("kill_switch triggered".into())
            }
            futures::future::Either::Right((res, _)) => res,
        }
    }};
}

impl Drop for KillSwitch {
    fn drop(&mut self) {
        if self.is_weak {
            return;
        }
        (self.inner)
            .0
            .store(false, std::sync::atomic::Ordering::SeqCst);
        let _ = (self.inner).1.send(());
        let inner = self.inner.clone();
        tokio::task::spawn(async move {
            let mut lock = inner.2.lock().await;
            let all = lock.drain(..).map(|cb| cb());
            futures::future::join_all(all).await;
        });
    }
}

impl KillSwitch {
    /// Create a new kill switch
    pub fn new() -> Self {
        let (tx, _) = tokio::sync::broadcast::channel(10);
        Self {
            inner: Arc::new((
                std::sync::atomic::AtomicBool::new(true),
                tx,
                tokio::sync::Mutex::new(Vec::new()),
            )),
            is_weak: false,
        }
    }

    /// Get a "Weak" version of this kill_switch that will
    /// allow mixing/checking the kill status, but will not
    /// kill other instances when dropped.
    pub fn weak(&self) -> Self {
        let mut out = self.clone();
        out.is_weak = true;
        out
    }

    /// Register an async callback that will be invoked on kill.
    pub async fn register_kill_callback(&self, cb: KillCallback) {
        let mut lock = self.inner.2.lock().await;
        lock.push(cb);
    }

    /// Should we continue?
    pub fn cont(&self) -> bool {
        cont(&self.inner)
    }

    /// Mix in another future so it will abort
    /// if this kill switch is triggered.
    pub async fn mix<R, F>(&self, f: F) -> LairResult<R>
    where
        F: std::future::Future<Output = LairResult<R>>,
    {
        inner_mix!(self.inner, f)
    }

    /// Mix in another future so it will abort
    /// if this kill switch is triggered.
    /// Sometimes we need static futures.
    pub fn mix_static<R, F>(
        &self,
        f: F,
    ) -> impl std::future::Future<Output = LairResult<R>> + 'static
    where
        F: 'static + std::future::Future<Output = LairResult<R>>,
    {
        let inner = self.inner.clone();
        async move { inner_mix!(inner, f) }
    }
}

impl Default for KillSwitch {
    fn default() -> Self {
        Self::new()
    }
}
