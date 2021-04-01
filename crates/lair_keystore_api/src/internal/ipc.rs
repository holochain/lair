//! Abstraction over unix domain sockets / windows named pipes

use crate::internal::util::*;
use crate::internal::wire::*;
use crate::*;

use futures::{future::FutureExt, sink::SinkExt, stream::StreamExt};
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

    let writer = spawn_low_level_write_half(kill_switch.clone(), write_half)?;

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
    writer: futures::channel::mpsc::Sender<LowLevelWireApi>,
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
                    let _ = weak_kill_switch
                        .mix(writer_clone.low_level_send(res))
                        .await;
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
        let fut = self.kill_switch.mix_static(self.writer.low_level_send(msg));
        let weak_kill_switch = self.kill_switch.weak();
        Ok(async move {
            fut.await?;
            Ok(weak_kill_switch
                .mix(async move {
                    trace!("await incoming request...");
                    let res = recv.await.map_err(LairError::other);
                    trace!(?res, "respond to incoming request");
                    res
                })
                .await?)
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
