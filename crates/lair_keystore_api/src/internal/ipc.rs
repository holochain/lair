//! Abstraction over unix domain sockets / windows named pipes

use crate::internal::util::*;
use crate::internal::wire::*;
use crate::*;

use futures::future::{BoxFuture, FutureExt};
use futures::sink::SinkExt;
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
pub struct IpcSender2 {
    ll_send: LowLevelWireSender,
    inner: Arc<Mutex<Ipc2Inner>>,
}

impl IpcSender2 {
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
pub struct IpcReceiver2(BoxStream<'static, LairResult<LairWire>>);

impl IpcReceiver2 {
    #[allow(dead_code)]
    pub(crate) fn new(
        ll_send: LowLevelWireSender,
        ll_recv: LowLevelWireReceiver2,
    ) -> (IpcSender2, Self) {
        let inner = Arc::new(Mutex::new(Ipc2Inner {
            pending: HashMap::new(),
        }));

        let sender = IpcSender2 {
            ll_send,
            inner: inner.clone(),
        };

        struct State {
            ll_recv: LowLevelWireReceiver2,
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

impl futures::stream::Stream for IpcReceiver2 {
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
pub struct IncomingIpcReceiver2(
    BoxStream<
        'static,
        BoxFuture<'static, LairResult<(Passphrase, IpcSender2, IpcReceiver2)>>,
    >,
);

impl IncomingIpcReceiver2 {
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
                let ll_recv = LowLevelWireReceiver2::new(read_half);

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
    mut ll_recv: LowLevelWireReceiver2,
) -> LairResult<(Passphrase, IpcSender2, IpcReceiver2)> {
    let msg_id = next_msg_id();
    let msg = LairWire::ToCliRequestUnlockPassphrase { msg_id };

    ll_send.send(msg).await?;

    let msg = match ll_recv.next().await {
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

    let (send, recv) = IpcReceiver2::new(ll_send, ll_recv);
    Ok((pw_out, send, recv))
}

impl futures::stream::Stream for IncomingIpcReceiver2 {
    type Item =
        BoxFuture<'static, LairResult<(Passphrase, IpcSender2, IpcReceiver2)>>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        futures::stream::Stream::poll_next(std::pin::Pin::new(&mut self.0), cx)
    }
}

/// Spawn/bind a new ipc listener connection awaiting incoming clients.
pub fn spawn_bind_ipc2(
    config: Arc<Config>,
) -> LairResult<IncomingIpcReceiver2> {
    IncomingIpcReceiver2::new(config)
}

/// Establish an outgoing client ipc connection to a lair server.
pub async fn spawn_ipc_connection2(
    config: Arc<Config>,
) -> LairResult<(IpcSender2, IpcReceiver2)> {
    let (read_half, write_half) = ipc_connect(config).await?;
    let ll_send = LowLevelWireSender::new(write_half);
    let ll_recv = LowLevelWireReceiver2::new(read_half);
    let (send, recv) = IpcReceiver2::new(ll_send, ll_recv);

    Ok((send, recv))
}

/// IpcSender
pub type IpcSender = ghost_actor::GhostSender<IpcWireApi>;

/// IpcReceiver
pub type IpcReceiver = futures::channel::mpsc::Receiver<IpcWireApi>;

/// IncomingIpcReceiver
pub type IncomingIpcSender = futures::channel::mpsc::Sender<(
    KillSwitch,
    ghost_actor::GhostSender<IpcWireApi>,
    IpcReceiver,
)>;

/// IncomingIpcReceiver
pub type IncomingIpcReceiver = futures::channel::mpsc::Receiver<(
    KillSwitch,
    ghost_actor::GhostSender<IpcWireApi>,
    IpcReceiver,
)>;

ghost_actor::ghost_chan! {
    /// Ipc wire api for both incoming api requests and outgoing event requests.
    pub chan IpcWireApi<LairError> {
        /// Make an Ipc request.
        fn request(msg: LairWire) -> LairWire;
    }
}

/// Spawn/bind a new ipc listener connection awaiting incoming clients.
pub async fn spawn_bind_ipc(
    config: Arc<Config>,
) -> LairResult<(KillSwitch, IncomingIpcReceiver)> {
    let kill_switch = KillSwitch::new();
    let (in_send, in_recv) = futures::channel::mpsc::channel(10);

    let srv = IpcServer::bind(config)?;

    err_spawn(
        "srv-bind",
        srv_main_bind_task(kill_switch.clone(), srv, in_send),
    );

    Ok((kill_switch, in_recv))
}

async fn srv_main_bind_task(
    kill_switch: KillSwitch,
    mut srv: IpcServer,
    mut in_send: IncomingIpcSender,
) -> LairResult<()> {
    while let Ok((read_half, write_half)) = kill_switch.mix(srv.accept()).await
    {
        let (con_kill_switch, send, recv) = kill_switch
            .mix(async { spawn_connection_pair(read_half, write_half).await })
            .await?;

        kill_switch
            .mix(async {
                trace!("notify new connection");
                in_send
                    .send((con_kill_switch, send, recv))
                    .await
                    .map_err(LairError::other)
            })
            .await?;
    }
    Ok(())
}

/// Establish an outgoing client ipc connection to a lair server.
pub async fn spawn_ipc_connection(
    config: Arc<Config>,
) -> LairResult<(
    KillSwitch,
    ghost_actor::GhostSender<IpcWireApi>,
    IpcReceiver,
)> {
    let (read_half, write_half) = ipc_connect(config).await?;

    spawn_connection_pair(read_half, write_half).await
}

async fn spawn_connection_pair(
    read_half: IpcRead,
    write_half: IpcWrite,
) -> LairResult<(
    KillSwitch,
    ghost_actor::GhostSender<IpcWireApi>,
    IpcReceiver,
)> {
    let kill_switch = KillSwitch::new();

    let (evt_send, evt_recv) = futures::channel::mpsc::channel(10);

    let builder = ghost_actor::actor_builder::GhostActorBuilder::new();

    let sender = builder
        .channel_factory()
        .create_channel::<IpcWireApi>()
        .await?;

    let kill_sender = sender.clone();
    kill_switch
        .register_kill_callback(Box::new(move || {
            Box::pin(async move {
                use ghost_actor::GhostControlSender;
                if let Err(err) = kill_sender.ghost_actor_shutdown().await {
                    error!(?err);
                }
            })
        }))
        .await;

    let reader = spawn_low_level_read_half(kill_switch.clone(), read_half)?;
    builder.channel_factory().attach_receiver(reader).await?;

    let writer = LowLevelWireSender::new(write_half);

    tokio::task::spawn(builder.spawn(Internal {
        kill_switch: kill_switch.clone(),
        pending: HashMap::new(),
        writer,
        evt_send,
    }));

    Ok((kill_switch, sender, evt_recv))
}

struct Internal {
    kill_switch: KillSwitch,
    pending: HashMap<u64, tokio::sync::oneshot::Sender<LairWire>>,
    writer: LowLevelWireSender,
    evt_send: futures::channel::mpsc::Sender<IpcWireApi>,
}

impl ghost_actor::GhostControlHandler for Internal {}

impl ghost_actor::GhostHandler<LowLevelWireApi> for Internal {}

impl LowLevelWireApiHandler for Internal {
    fn handle_low_level_send(
        &mut self,
        msg: LairWire,
    ) -> LowLevelWireApiHandlerResult<()> {
        trace!(?msg, "RECV MSG");
        if msg.is_req() {
            let fut = self.kill_switch.mix_static(self.evt_send.request(msg));
            let writer_clone = self.writer.clone();
            let weak_kill_switch = self.kill_switch.weak();
            Ok(async move {
                if let Ok(res) = fut.await {
                    let _ = weak_kill_switch.mix(writer_clone.send(res)).await;
                }
                // TODO - send errors back so we don't have dangling reqs!!
                Ok(())
            }
            .boxed()
            .into())
        } else {
            if let Some(send) = self.pending.remove(&msg.get_msg_id()) {
                trace!("outgoing response received");
                let _ = send.send(msg);
            }
            Ok(async move { Ok(()) }.boxed().into())
        }
    }
}

impl ghost_actor::GhostHandler<IpcWireApi> for Internal {}

impl IpcWireApiHandler for Internal {
    fn handle_request(
        &mut self,
        msg: LairWire,
    ) -> IpcWireApiHandlerResult<LairWire> {
        let (send, recv) = tokio::sync::oneshot::channel();
        self.pending.insert(msg.get_msg_id(), send);
        trace!("con write {:?}", msg);
        let fut = self.kill_switch.mix_static(self.writer.send(msg));
        let weak_kill_switch = self.kill_switch.weak();
        Ok(async move {
            fut.await?;
            weak_kill_switch
                .mix(async move {
                    trace!("await incoming request...");
                    let res = recv.await.map_err(LairError::other);
                    trace!(?res, "respond to incoming request");
                    res
                })
                .await
        }
        .boxed()
        .into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_tracing() {
        let _ = subscriber::set_global_default(
            tracing_subscriber::FmtSubscriber::builder()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::from_default_env(),
                )
                .compact()
                .finish(),
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_ipc_raw_wire() -> LairResult<()> {
        init_tracing();

        let tmpdir = tempfile::tempdir().unwrap();

        let config = Config::builder().set_root_path(tmpdir.path()).build();

        let (srv_kill, mut srv_recv) = spawn_bind_ipc(config.clone()).await?;

        let srv_task_kill = srv_kill.clone();
        err_spawn("test-outer", async move {
            while let Some((con_kill, con_send, mut con_recv)) =
                srv_recv.next().await
            {
                err_spawn("test-inner", async move {
                    println!("GOT CONNECTION!!");
                    let r = con_send
                        .request(LairWire::ToCliRequestUnlockPassphrase {
                            msg_id: 0,
                        })
                        .await
                        .unwrap();
                    println!("passphrase req RESPONSE: {:?}", r);
                    match r {
                        LairWire::ToLairRequestUnlockPassphraseResponse {
                            passphrase,
                            ..
                        } => {
                            assert_eq!("test-passphrase", &passphrase);
                        }
                        _ => panic!("unexpected: {:?}", r),
                    }
                    println!("DONE WITH PASSPHRASE LOOP\n\n");
                    while let Some(msg) = con_recv.next().await {
                        println!("GOT MESSAGE!!: {:?}", msg);
                        match msg {
                            IpcWireApi::Request { respond, msg, .. } => {
                                println!("GOT MESSAGE!!: {:?}", msg);
                                if let LairWire::ToLairLairGetLastEntryIndex {
                                    msg_id,
                                } = msg
                                {
                                    respond.respond(Ok(async move {
                                        Ok(LairWire::ToCliLairGetLastEntryIndexResponse {
                                            msg_id,
                                            last_keystore_index: 42.into(),
                                        })
                                    }.boxed().into()));
                                }
                            }
                        }
                        if !con_kill.cont() {
                            break;
                        }
                    }
                    LairResult::<()>::Ok(())
                });
                if !srv_task_kill.cont() {
                    break;
                }
            }
            LairResult::<()>::Ok(())
        });

        let (cli_kill, cli_send, mut cli_recv) =
            spawn_ipc_connection(config).await?;

        match cli_recv.next().await.unwrap() {
            IpcWireApi::Request { respond, msg, .. } => {
                println!("GOT: {:?}", msg);
                match msg {
                    LairWire::ToCliRequestUnlockPassphrase { msg_id } => {
                        respond.respond(Ok(async move {
                            Ok(LairWire::ToLairRequestUnlockPassphraseResponse {
                                msg_id,
                                passphrase: "test-passphrase".to_string(),
                            })
                        }
                        .boxed()
                        .into()));
                    }
                    _ => panic!("unexpected: {:?}", msg),
                }
            }
        }

        let res = cli_send
            .request(LairWire::ToLairLairGetLastEntryIndex { msg_id: 0 })
            .await
            .unwrap();
        println!("GOT: {:?}", res);

        match res {
            LairWire::ToCliLairGetLastEntryIndexResponse {
                last_keystore_index,
                ..
            } => {
                assert_eq!(42, last_keystore_index.0);
            }
            _ => panic!("unexpected: {:?}", res),
        }

        println!("COMPLETE - DROPPING ITEMS");

        drop(cli_kill);
        drop(srv_kill);
        drop(tmpdir);

        println!("COMPLETE - ITEMS DROPPED - exiting test");

        Ok(())
    }
}
