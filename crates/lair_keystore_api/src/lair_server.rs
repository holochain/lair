//! host a lair keystore

use crate::LairResult2 as LairResult;
use futures::future::{BoxFuture, FutureExt};
use parking_lot::RwLock;
use std::future::Future;
use std::sync::Arc;

/// Traits related to LairServer. Unless you're writing a new
/// implementation, you probably don't need these.
pub mod traits {
    use super::*;

    /// trait object type for AsyncWrite instance.
    pub type RawSend = Box<dyn tokio::io::AsyncWrite + 'static + Send + Unpin>;

    /// trait object type for AsyncRead instance.
    pub type RawRecv = Box<dyn tokio::io::AsyncRead + 'static + Send + Unpin>;

    /// host a lair keystore
    pub trait AsLairServer: 'static + Send + Sync {
        /// accept an incoming connection, servicing the lair protocol.
        fn accept(
            &self,
            send: RawSend,
            recv: RawRecv,
        ) -> BoxFuture<'static, LairResult<()>>;
    }
}
use traits::*;

/// host a lair keystore
#[derive(Clone)]
pub struct LairServer(pub Arc<dyn AsLairServer>);

impl LairServer {
    /// accept an incoming connection, servicing the lair protocol.
    pub fn accept<S, R>(
        &self,
        send: RawSend,
        recv: RawRecv,
    ) -> impl Future<Output = LairResult<()>> + 'static + Send
    where
        S: tokio::io::AsyncWrite + 'static + Send + Unpin,
        R: tokio::io::AsyncRead + 'static + Send + Unpin,
    {
        AsLairServer::accept(&*self.0, Box::new(send), Box::new(recv))
    }
}

/// spawn a tokio task managing a lair server with given store factory.
pub async fn spawn_lair_server_task(
    store_factory: crate::lair_core::LairStoreFactory,
) -> LairResult<LairServer> {
    let inner = SrvPendingInner { store_factory };

    let inner = SrvInnerEnum::Pending(inner);
    let inner = Arc::new(RwLock::new(inner));

    Ok(LairServer(Arc::new(Srv(inner))))
}

// -- private -- //

struct SrvPendingInner {
    #[allow(dead_code)]
    store_factory: crate::lair_core::LairStoreFactory,
}

struct SrvRunningInner {}

enum SrvInnerEnum {
    Pending(SrvPendingInner),
    #[allow(dead_code)]
    Running(SrvRunningInner),
}

struct Srv(Arc<RwLock<SrvInnerEnum>>);

impl AsLairServer for Srv {
    fn accept(
        &self,
        _send: RawSend,
        _recv: RawRecv,
    ) -> BoxFuture<'static, LairResult<()>> {
        async move { unimplemented!() }.boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_lair_server() {
        let store = crate::mem_store::create_mem_store_factory();
        let _srv = spawn_lair_server_task(store).await.unwrap();
    }
}
