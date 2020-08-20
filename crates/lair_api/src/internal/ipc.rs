//! Abstraction over unix domain sockets / windows named pipes

use crate::internal::wire::*;
use crate::*;

use futures::{sink::SinkExt, stream::StreamExt};
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

/// IpcRespond
pub type IpcRespond = tokio::sync::oneshot::Sender<LairWire>;

/// IpcSender
pub type IpcSender =
    futures::channel::mpsc::Sender<(LairWire, Option<IpcRespond>)>;

/// IpcReceiver
pub type IpcReceiver =
    futures::channel::mpsc::Receiver<(LairWire, Option<IpcRespond>)>;

/// IncomingIpcReceiver
pub type IncomingIpcSender =
    futures::channel::mpsc::Sender<(IpcSender, IpcReceiver)>;

/// IncomingIpcReceiver
pub type IncomingIpcReceiver =
    futures::channel::mpsc::Receiver<(IpcSender, IpcReceiver)>;

/// Spawn/bind a new ipc listener connection awaiting incomming clients.
pub async fn spawn_bind_ipc(
    config: Arc<Config>,
) -> LairResult<IncomingIpcReceiver> {
    let (in_send, in_recv) = futures::channel::mpsc::channel(10);

    let srv = IpcServer::bind(config)?;

    tokio::task::spawn(srv_main_bind_task(srv, in_send));

    Ok(in_recv)
}

async fn srv_main_bind_task(
    mut srv: IpcServer,
    mut in_send: IncomingIpcSender,
) -> LairResult<()> {
    loop {
        if let Ok((read_half, write_half)) = srv.accept().await {
            let (api_send, api_recv) = futures::channel::mpsc::channel(10);
            let (evt_send, evt_recv) = futures::channel::mpsc::channel(10);

            let respond_track = RespondTrack::new();
            let kill_switch = KillSwitch::new();

            tokio::task::spawn(con_write_task(
                false,
                respond_track.clone(),
                kill_switch.clone(),
                evt_recv,
                write_half,
            ));
            tokio::task::spawn(con_read_task(
                false,
                respond_track,
                kill_switch,
                api_send,
                read_half,
            ));

            in_send
                .send((evt_send, api_recv))
                .await
                .map_err(LairError::other)?;
        }
    }
}

/// Establish an outgoing client ipc connection to a lair server.
pub async fn spawn_ipc_connection(
    config: Arc<Config>,
) -> LairResult<(IpcSender, IpcReceiver)> {
    let (api_send, api_recv) = futures::channel::mpsc::channel(10);
    let (evt_send, evt_recv) = futures::channel::mpsc::channel(10);

    let (read_half, write_half) = ipc_connect(config).await?;

    let respond_track = RespondTrack::new();
    let kill_switch = KillSwitch::new();

    tokio::task::spawn(con_write_task(
        true,
        respond_track.clone(),
        kill_switch.clone(),
        api_recv,
        write_half,
    ));
    tokio::task::spawn(con_read_task(
        true,
        respond_track,
        kill_switch,
        evt_send,
        read_half,
    ));

    Ok((api_send, evt_recv))
}

async fn con_write_task(
    is_client: bool,
    respond_track: RespondTrack,
    kill_switch: KillSwitch,
    mut api_recv: IpcReceiver,
    mut write_half: IpcWrite,
) -> LairResult<()> {
    while let Some((msg, respond)) = api_recv.next().await {
        let enc = msg.encode()?;
        if is_client && msg.is_event() || !is_client && !msg.is_event() {
            /* pass */
        } else {
            respond_track
                .register(msg.get_msg_id(), respond.unwrap())
                .await;
        }
        write_half.write_all(&enc).await.map_err(LairError::other)?;

        if !kill_switch.cont() {
            break;
        }
    }
    Ok(())
}

async fn con_read_task(
    is_client: bool,
    respond_track: RespondTrack,
    kill_switch: KillSwitch,
    mut evt_send: IpcSender,
    mut read_half: IpcRead,
) -> LairResult<()> {
    let mut pending_data = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let read = read_half
            .read(&mut buffer)
            .await
            .map_err(LairError::other)?;
        pending_data.extend_from_slice(&buffer[..read]);
        if let Ok(size) = LairWire::peek_size(&pending_data) {
            let msg = LairWire::decode(&pending_data)?;
            let _ = pending_data.drain(..size);
            if is_client && msg.is_event() || !is_client && !msg.is_event() {
                evt_send.send((msg, None)).await.map_err(LairError::other)?;
            } else {
                respond_track.respond(msg).await;
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
            let _ = respond.send(msg);
        }
    }
}

/// If any of these are dropped, they all say we should stop looping.
#[derive(Clone)]
struct KillSwitch(Arc<std::sync::atomic::AtomicBool>);

impl Drop for KillSwitch {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::Relaxed)
    }
}

impl KillSwitch {
    pub fn new() -> Self {
        Self(Arc::new(std::sync::atomic::AtomicBool::new(true)))
    }

    pub fn cont(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::Relaxed)
    }
}
