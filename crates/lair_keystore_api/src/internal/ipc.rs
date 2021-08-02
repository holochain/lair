//! Abstraction over unix domain sockets / windows named pipes

use crate::internal::util::*;
use crate::internal::wire::*;
use crate::*;

use futures::future::{BoxFuture, FutureExt};
use futures::stream::{BoxStream, StreamExt};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::future::Future;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[cfg(not(windows))]
mod unix_ipc;
#[cfg(not(windows))]
use unix_ipc::*;

#[cfg(windows)]
mod win_ipc;
#[cfg(windows)]
use win_ipc::*;

mod low_level;
pub(crate) use low_level::*;

struct Ipc2Inner {
    pending: HashMap<u64, tokio::sync::oneshot::Sender<LairResult<LairWire>>>,
}

struct PendingCleanup(u64, Arc<Mutex<Ipc2Inner>>);

impl Drop for PendingCleanup {
    fn drop(&mut self) {
        let mut inner = self.1.lock();
        let _ = inner.pending.remove(&self.0);
    }
}

/// make outgoing lair requests
#[derive(Clone)]
pub struct IpcSender {
    ll_send: LowLevelWireSender,
    inner: Arc<Mutex<Ipc2Inner>>,
}

impl IpcSender {
    /// respond to an incoming lair wire request
    pub fn respond(
        &self,
        msg: LairWire,
    ) -> impl Future<Output = LairResult<()>> + 'static + Send {
        let ll_send = self.ll_send.clone();

        async move {
            ll_send.send(msg).await?;
            Ok(())
        }
    }

    /// make a lair wire request, and await a response
    pub fn request(
        &self,
        msg: LairWire,
    ) -> impl Future<Output = LairResult<LairWire>> + 'static + Send {
        let ll_send = self.ll_send.clone();
        let inner = self.inner.clone();

        let msg_id = msg.get_msg_id();

        let (r_send, r_recv) = tokio::sync::oneshot::channel();
        inner.lock().pending.insert(msg_id, r_send);
        let cleanup = PendingCleanup(msg_id, inner);

        async move {
            let _cleanup = cleanup;

            ll_send.send(msg).await?;

            tokio::time::timeout(std::time::Duration::from_secs(30), r_recv)
                .await
                .map_err(LairError::other)?
                .map_err(LairError::other)?
        }
    }
}

/// receive incoming lair requests
pub struct IpcReceiver(BoxStream<'static, LairResult<LairWire>>);

impl IpcReceiver {
    #[allow(dead_code)]
    pub(crate) fn new(
        ll_send: LowLevelWireSender,
        ll_recv: LowLevelWireReceiver,
    ) -> (IpcSender, Self) {
        let inner = Arc::new(Mutex::new(Ipc2Inner {
            pending: HashMap::new(),
        }));

        let sender = IpcSender {
            ll_send,
            inner: inner.clone(),
        };

        struct State {
            ll_recv: LowLevelWireReceiver,
            inner: Arc<Mutex<Ipc2Inner>>,
        }

        let state = State { ll_recv, inner };

        let stream =
            futures::stream::try_unfold(state, move |state| async move {
                let State { mut ll_recv, inner } = state;

                while let Some(res) = ll_recv.next().await {
                    let msg = res?;
                    if msg.is_req() {
                        return Ok(Some((msg, State { ll_recv, inner })));
                    } else if let Some(resp) =
                        inner.lock().pending.remove(&msg.get_msg_id())
                    {
                        let _ = resp.send(Ok(msg));
                    }
                }
                Ok(None)
            })
            .boxed();

        (sender, Self(stream))
    }
}

impl futures::stream::Stream for IpcReceiver {
    type Item = LairResult<LairWire>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        futures::stream::Stream::poll_next(std::pin::Pin::new(&mut self.0), cx)
    }
}

/// Passphrase
pub type Passphrase = sodoken::BufRead;

/// Stream of incoming requests to Ipc Server
pub struct IncomingIpcReceiver(
    BoxStream<
        'static,
        BoxFuture<'static, LairResult<(Passphrase, IpcSender, IpcReceiver)>>,
    >,
);

impl IncomingIpcReceiver {
    pub(crate) fn new(config: Arc<Config>) -> LairResult<Self> {
        let srv = IpcServer::bind(config)?;

        struct State {
            srv: IpcServer,
        }

        let state = State { srv };

        let stream = futures::stream::unfold(state, move |state| async move {
            let State { mut srv } = state;

            if let Ok((read_half, write_half)) = srv.accept().await {
                let ll_send = LowLevelWireSender::new(write_half);
                let ll_recv = LowLevelWireReceiver::new(read_half);

                let res_fut = get_passphrase(ll_send, ll_recv).boxed();
                return Some((res_fut, State { srv }));
            }

            None
        })
        .boxed();

        Ok(Self(stream))
    }
}

async fn get_passphrase(
    ll_send: LowLevelWireSender,
    mut ll_recv: LowLevelWireReceiver,
) -> LairResult<(Passphrase, IpcSender, IpcReceiver)> {
    let msg_id = next_msg_id();
    let msg = LairWire::ToCliRequestUnlockPassphrase { msg_id };

    ll_send.send(msg).await?;

    let msg = match tokio::time::timeout(
        std::time::Duration::from_secs(30),
        ll_recv.next(),
    )
    .await
    .map_err(LairError::other)?
    {
        None => return Err("no result".into()),
        Some(msg) => msg?,
    };

    if msg.get_msg_id() != msg_id {
        let msg = LairWire::ErrorResponse {
            msg_id: msg.get_msg_id(),
            message: "Invalid msg_id".to_string(),
        };
        ll_send.send(msg).await?;
        return Err("Invalid msg_id".into());
    }

    let passphrase = if let LairWire::ToLairRequestUnlockPassphraseResponse {
        passphrase,
        ..
    } = msg
    {
        passphrase
    } else {
        let message =
            format!("Expected PassphraseResponse, Invalid msg {:?}", msg,);
        let msg = LairWire::ErrorResponse {
            msg_id: msg.get_msg_id(),
            message: message.clone(),
        };
        ll_send.send(msg).await?;
        return Err(message.into());
    };

    // TODO - some way to secure this earlier??
    let pw_out = sodoken::BufWrite::new_mem_locked(passphrase.len())
        .map_err(LairError::other)?;
    pw_out.write_lock().copy_from_slice(passphrase.as_bytes());
    let pw_out = pw_out.to_read();

    let (send, recv) = IpcReceiver::new(ll_send, ll_recv);
    Ok((pw_out, send, recv))
}

impl futures::stream::Stream for IncomingIpcReceiver {
    type Item =
        BoxFuture<'static, LairResult<(Passphrase, IpcSender, IpcReceiver)>>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        futures::stream::Stream::poll_next(std::pin::Pin::new(&mut self.0), cx)
    }
}

/// Spawn/bind a new ipc listener connection awaiting incoming clients.
pub fn spawn_bind_ipc(config: Arc<Config>) -> LairResult<IncomingIpcReceiver> {
    IncomingIpcReceiver::new(config)
}

/// Establish an outgoing client ipc connection to a lair server.
pub async fn spawn_ipc_connection(
    config: Arc<Config>,
) -> LairResult<(IpcSender, IpcReceiver)> {
    let (read_half, write_half) = ipc_connect(config).await?;
    let ll_send = LowLevelWireSender::new(write_half);
    let ll_recv = LowLevelWireReceiver::new(read_half);
    let (send, recv) = IpcReceiver::new(ll_send, ll_recv);

    Ok((send, recv))
}
