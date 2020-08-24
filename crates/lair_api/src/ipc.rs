//! Ipc spawn functions.

use crate::actor::*;
use crate::internal::util::*;
use crate::*;

mod spawn_client_ipc;

/// Spawn a client Ipc connection.
pub async fn spawn_client_ipc(
    config: Arc<Config>,
) -> LairResult<(
    ghost_actor::GhostSender<LairClientApi>,
    LairClientEventReceiver,
)> {
    let (evt_send, evt_recv) = futures::channel::mpsc::channel(10);

    let api_send = spawn_client_ipc::spawn_client_ipc(config, evt_send).await?;

    //let (kill_switch, ipc_send, ipc_recv) = spawn_ipc_connection(config);

    Ok((api_send, evt_recv))
}

/// Incoming Connection Receiver.
pub type IncomingIpcConnectionReceiver =
    futures::channel::mpsc::Receiver<(KillSwitch, LairClientEventSenderType)>;

mod spawn_bind_server_ipc;

/// Bind a server Ipc connection.
pub async fn spawn_bind_server_ipc<S>(
    config: Arc<Config>,
    api_sender: S,
) -> LairResult<IncomingIpcConnectionReceiver>
where
    S: ghost_actor::GhostChannelSender<LairClientApi>,
{
    let (incoming_send, incoming_recv) = futures::channel::mpsc::channel(10);

    spawn_bind_server_ipc::spawn_bind_server_ipc(
        config,
        api_sender,
        incoming_send,
    )
    .await?;

    Ok(incoming_recv)
}
