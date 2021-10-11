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
        /// accept an incoming connection, servicing the lair protocol.
        fn accept(
            &self,
            send: RawSend,
            recv: RawRecv,
        ) -> BoxFuture<'static, LairResult<()>>;

        /// get a handle to the LairStore instantiated by this server,
        /// may error if a store has not yet been created.
        fn store(&self) -> BoxFuture<'static, LairResult<LairStore>>;
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
        send: S,
        recv: R,
    ) -> impl Future<Output = LairResult<()>> + 'static + Send
    where
        S: tokio::io::AsyncWrite + 'static + Send + Unpin,
        R: tokio::io::AsyncRead + 'static + Send + Unpin,
    {
        AsLairServer::accept(&*self.0, Box::new(send), Box::new(recv))
    }

    /// get a handle to the LairStore instantiated by this server,
    /// may error if a store has not yet been created.
    pub fn store(
        &self,
    ) -> impl Future<Output = LairResult<LairStore>> + 'static + Send {
        AsLairServer::store(&*self.0)
    }
}

/// spawn a tokio task managing a lair server with given store factory.
pub fn spawn_lair_server_task<C>(
    config: C,
    server_name: Arc<str>,
    server_version: Arc<str>,
    store_factory: LairStoreFactory,
    passphrase: sodoken::BufRead,
) -> impl Future<Output = LairResult<LairServer>> + 'static + Send
where
    C: Into<LairServerConfig> + 'static + Send,
{
    async move {
        let srv = Srv::new(
            config.into(),
            server_name,
            server_version,
            store_factory,
            passphrase,
        )
        .await?;

        Ok(LairServer(Arc::new(srv)))
    }
}

// -- private -- //

mod priv_srv;
use priv_srv::*;

mod priv_api;
use priv_api::*;
