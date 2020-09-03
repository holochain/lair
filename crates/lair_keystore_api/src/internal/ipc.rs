//! Abstraction over unix domain sockets / windows named pipes

use crate::internal::util::*;
use crate::internal::wire::*;
use crate::*;

use futures::{future::FutureExt, sink::SinkExt, stream::StreamExt};
use ghost_actor::dependencies::tracing;
use std::collections::HashMap;
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

/// IpcRespond
type IpcRespond = ghost_actor::GhostRespond<IpcWireApiHandlerResult<LairWire>>;

/// IpcSender
pub type IpcSender = futures::channel::mpsc::Sender<IpcWireApi>;

/// IpcReceiver
pub type IpcReceiver = futures::channel::mpsc::Receiver<IpcWireApi>;

/// IncomingIpcReceiver
pub type IncomingIpcSender =
    futures::channel::mpsc::Sender<(KillSwitch, IpcSender, IpcReceiver)>;

/// IncomingIpcReceiver
pub type IncomingIpcReceiver =
    futures::channel::mpsc::Receiver<(KillSwitch, IpcSender, IpcReceiver)>;

/// IncomingIpcReceiver
pub type IncomingIpcSender2 =
    futures::channel::mpsc::Sender<(KillSwitch, ghost_actor::GhostSender<IpcWireApi>, IpcReceiver)>;

/// IncomingIpcReceiver
pub type IncomingIpcReceiver2 =
    futures::channel::mpsc::Receiver<(KillSwitch, ghost_actor::GhostSender<IpcWireApi>, IpcReceiver)>;

/// Establish an outgoing client ipc connection to a lair server.
pub async fn spawn_ipc_connection(
    config: Arc<Config>,
) -> LairResult<(KillSwitch, IpcSender, IpcReceiver)> {
    let (read_half, write_half) = ipc_connect(config).await?;
    spawn_connection_pair(read_half, write_half)
}

/// Spawn/bind a new ipc listener connection awaiting incomming clients.
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
    loop {
        if let Ok((read_half, write_half)) = srv.accept().await {
            let (con_kill_switch, send, recv) =
                spawn_connection_pair(read_half, write_half)?;

            in_send
                .send((con_kill_switch, send, recv))
                .await
                .map_err(LairError::other)?;
        }
        if !kill_switch.cont() {
            break;
        }
    }
    Ok(())
}

/// hack
pub async fn spawn_bind_ipc_2(
    config: Arc<Config>,
) -> LairResult<(KillSwitch, IncomingIpcReceiver2)> {
    let kill_switch = KillSwitch::new();
    let (in_send, in_recv) = futures::channel::mpsc::channel(10);

    let srv = IpcServer::bind(config)?;

    err_spawn(
        "srv-bind",
        srv_main_bind_task_2(kill_switch.clone(), srv, in_send),
    );

    Ok((kill_switch, in_recv))
}

async fn srv_main_bind_task_2(
    kill_switch: KillSwitch,
    mut srv: IpcServer,
    mut in_send: IncomingIpcSender2,
) -> LairResult<()> {
    while let Ok((read_half, write_half)) = srv.accept().await {
        let (con_kill_switch, send, recv) = kill_switch.mix(async {
            spawn_connection_pair_2(read_half, write_half).await
        }).await?;

        kill_switch.mix(async {
            in_send
                .send((con_kill_switch, send, recv))
                .await
                .map_err(LairError::other)
        }).await?;
    }
    Ok(())
}

/// hack
pub async fn spawn_ipc_connection_2(
    config: Arc<Config>,
) -> LairResult<(
    KillSwitch,
    ghost_actor::GhostSender<IpcWireApi>,
    IpcReceiver,
)> {
    let (read_half, write_half) = ipc_connect(config).await?;

    spawn_connection_pair_2(read_half, write_half).await
}

async fn spawn_connection_pair_2(
    read_half: IpcRead,
    write_half: IpcWrite,
) -> LairResult<(
    KillSwitch,
    ghost_actor::GhostSender<IpcWireApi>,
    IpcReceiver,
)> {
    let kill_switch = KillSwitch::new();

    let writer = spawn_low_level_write_half(kill_switch.clone(), write_half)?;
    let reader = spawn_low_level_read_half(kill_switch.clone(), read_half)?;

    let (evt_send, evt_recv) =
        futures::channel::mpsc::channel(10);

    let builder = ghost_actor::actor_builder::GhostActorBuilder::new();

    builder
        .channel_factory()
        .attach_receiver(reader).await?;

    let sender = builder
        .channel_factory()
        .create_channel::<IpcWireApi>().await?;

    tokio::task::spawn(builder.spawn(Internal {
        _kill_switch: kill_switch.clone(),
        pending: HashMap::new(),
        writer,
        evt_send,
    }));

    Ok((kill_switch, sender, evt_recv))
}

struct Internal {
    _kill_switch: KillSwitch,
    pending: HashMap<u64, tokio::sync::oneshot::Sender<LairWire>>,
    writer: futures::channel::mpsc::Sender<LowLevelWireApi>,
    evt_send: IpcSender,
}

impl ghost_actor::GhostControlHandler for Internal {}

impl ghost_actor::GhostHandler<LowLevelWireApi> for Internal {}

impl LowLevelWireApiHandler for Internal {
    fn handle_low_level_send(
        &mut self,
        msg: LairWire,
    ) -> LowLevelWireApiHandlerResult<()> {
        if msg.is_req() {
            let fut = self.evt_send.request(msg);
            let writer_clone = self.writer.clone();
            Ok(async move {
                if let Ok(res) = fut.await {
                    let _ = writer_clone.low_level_send(res).await;
                }
                // TODO - send errors back so we don't have dangling reqs!!
                Ok(())
            }.boxed().into())
        } else {
            if let Some(send) = self.pending.remove(&msg.get_msg_id()) {
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
        tracing::trace!("con write {:?}", msg);
        let fut = self.writer.low_level_send(msg);
        Ok(async move {
            fut.await?;
            Ok(recv.await.map_err(LairError::other)?)
        }.boxed().into())
    }
}

fn spawn_connection_pair(
    read_half: IpcRead,
    write_half: IpcWrite,
) -> LairResult<(KillSwitch, IpcSender, IpcReceiver)> {
    let respond_track = RespondTrack::new();
    let kill_switch = KillSwitch::new();

    let writer = spawn_low_level_write_half(kill_switch.clone(), write_half)?;
    let reader = spawn_low_level_read_half(kill_switch.clone(), read_half)?;

    let (outgoing_msg_send, outgoing_msg_recv) =
        futures::channel::mpsc::channel(10);
    let (incoming_msg_send, incoming_msg_recv) =
        futures::channel::mpsc::channel(10);

    err_spawn(
        "con-write",
        spawn_write_task(
            respond_track.clone(),
            kill_switch.clone(),
            outgoing_msg_recv,
            writer.clone(),
        ),
    );
    err_spawn(
        "con-read",
        spawn_read_task(
            respond_track,
            kill_switch.clone(),
            incoming_msg_send,
            reader,
            writer,
        ),
    );

    Ok((kill_switch, outgoing_msg_send, incoming_msg_recv))
}

async fn spawn_write_task(
    respond_track: RespondTrack,
    kill_switch: KillSwitch,
    mut outgoing_msg_recv: IpcReceiver,
    writer: LowLevelWireSender,
) -> LairResult<()> {
    while let Some(msg) = outgoing_msg_recv.next().await {
        match msg {
            IpcWireApi::Request { respond, msg, .. } => {
                respond_track.register(msg.get_msg_id(), respond).await;
                tracing::trace!("con write {:?}", msg);
                writer.low_level_send(msg).await?;
            }
        }
        if !kill_switch.cont() {
            break;
        }
    }
    Ok(())
}

async fn spawn_read_task(
    respond_track: RespondTrack,
    kill_switch: KillSwitch,
    incoming_msg_send: IpcSender,
    mut reader: LowLevelWireReceiver,
    writer: LowLevelWireSender,
) -> LairResult<()> {
    while let Some(msg) = reader.next().await {
        match msg {
            LowLevelWireApi::LowLevelSend { respond, msg, .. } => {
                // respond right away, so it can start processing the
                // next message.
                respond.respond(Ok(async move { Ok(()) }.boxed().into()));

                if msg.is_req() {
                    let fut = incoming_msg_send.request(msg);
                    let writer_clone = writer.clone();
                    err_spawn("req-mini", async move {
                        if let Ok(res) = fut.await {
                            let _ = writer_clone.low_level_send(res).await;
                        }
                        LairResult::<()>::Ok(())
                    });
                } else {
                    respond_track.respond(msg).await;
                }
            }
        }
        if !kill_switch.cont() {
            break;
        }
    }
    Ok(())
}

#[derive(Clone)]
struct RespondTrack(Arc<tokio::sync::Mutex<HashMap<u64, IpcRespond>>>);

impl RespondTrack {
    pub fn new() -> Self {
        Self(Arc::new(tokio::sync::Mutex::new(HashMap::new())))
    }

    pub async fn register(&self, msg_id: u64, respond: IpcRespond) {
        let mut lock = self.0.lock().await;
        lock.insert(msg_id, respond);
    }

    pub async fn respond(&self, msg: LairWire) {
        let mut lock = self.0.lock().await;
        let msg_id = msg.get_msg_id();
        if let Some(respond) = lock.remove(&msg_id) {
            respond.respond(Ok(async move { Ok(msg) }.boxed().into()));
        }
    }
}

ghost_actor::ghost_chan! {
    /// Ipc wire api for both incoming api requsets and outgoing event requests.
    pub chan IpcWireApi<LairError> {
        /// Make an Ipc request.
        fn request(msg: LairWire) -> LairWire;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_tracing() {
        let _ = tracing::subscriber::set_global_default(
            tracing_subscriber::FmtSubscriber::builder()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::from_default_env(),
                )
                .compact()
                .finish(),
        );
    }

    #[tokio::test(threaded_scheduler)]
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

        drop(cli_kill);
        drop(srv_kill);
        drop(tmpdir);

        Ok(())
    }
}
