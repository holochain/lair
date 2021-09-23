//! host a lair keystore

use crate::lair_api::traits::AsLairCodec;
use crate::prelude::*;
use futures::future::{BoxFuture, FutureExt};
use futures::stream::StreamExt;
use parking_lot::RwLock;
use std::future::Future;
use std::sync::atomic;
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
        /// It is much more secure to unlock a lair keystore server
        /// interactively, to mitigate a MitM capturing the passphrase.
        fn unlock(
            &self,
            passphrase: sodoken::BufRead,
        ) -> BoxFuture<'static, LairResult<()>>;

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
    /// It is much more secure to unlock a lair keystore server
    /// interactively, to mitigate a MitM capturing the passphrase.
    pub fn unlock(
        &self,
        passphrase: sodoken::BufRead,
    ) -> impl Future<Output = LairResult<()>> + 'static + Send {
        AsLairServer::unlock(&*self.0, passphrase)
    }

    /// accept an incoming connection, servicing the lair protocol.
    pub fn accept<S, R>(
        &self,
        send: S,
        recv: R,
    ) -> impl Future<Output = LairResult<()>> + 'static + Send
    where
        S: tokio::io::AsyncWrite + 'static + Send + Unpin,
        R: tokio::io::AsyncRead + 'static + Send + Unpin,
    {
        AsLairServer::accept(&*self.0, Box::new(send), Box::new(recv))
    }
}

/// spawn a tokio task managing a lair server with given store factory.
pub fn spawn_lair_server_task<C>(
    config: C,
    server_name: Arc<str>,
    server_version: Arc<str>,
    store_factory: LairStoreFactory,
) -> impl Future<Output = LairResult<LairServer>> + 'static + Send
where
    C: Into<LairServerConfig> + 'static + Send,
{
    async move {
        let inner = SrvPendingInner {
            config: config.into(),
            server_name,
            server_version,
            store_factory,
        };

        let inner = SrvInnerEnum::Pending(Box::new(inner));
        let inner = Arc::new(RwLock::new(inner));

        Ok(LairServer(Arc::new(Srv(inner))))
    }
}

// -- private -- //

mod priv_srv;
use priv_srv::*;

mod priv_api;
use priv_api::*;
