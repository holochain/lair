//! Ipc spawn functions.

use crate::actor::*;
use crate::internal::util::*;
//use crate::internal::ipc::*;
use crate::*;

/// Spawn a client Ipc connection.
pub fn spawn_client_ipc(
    _config: Arc<Config>,
) -> (LairClientSender, LairClientEventReceiver) {
    let (api_send, _api_recv) = futures::channel::mpsc::channel(10);
    let (_evt_send, evt_recv) = futures::channel::mpsc::channel(10);

    //let (kill_switch, ipc_send, ipc_recv) = spawn_ipc_connection(config);

    (api_send, evt_recv)
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
    /*
    let (kill_switch, incoming_ipc_recv) = spawn_bind_ipc(config);
    while let Some((kill_switch, ipc_send, ipc_recv)) =
        incoming_ipc_recv.next().await
    {
    }
    */

    Ok(incoming_recv)
}
