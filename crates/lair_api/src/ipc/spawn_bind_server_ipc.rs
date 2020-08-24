use super::*;
use crate::internal::ipc::*;
use futures::stream::StreamExt;

pub(crate) async fn spawn_bind_server_ipc<S>(
    config: Arc<Config>,
    api_sender: S,
    incoming_send: futures::channel::mpsc::Sender<(
        KillSwitch,
        LairClientEventSenderType,
    )>,
) -> LairResult<()>
where
    S: ghost_actor::GhostChannelSender<LairClientApi>,
{
    Inner::spawn(config, api_sender, incoming_send).await
}

struct Inner<S>
where
    S: ghost_actor::GhostChannelSender<LairClientApi>,
{
    _config: Arc<Config>,
    _api_sender: S,
    _incoming_send:
        futures::channel::mpsc::Sender<(KillSwitch, LairClientEventSenderType)>,
    kill_switch: KillSwitch,
    incoming_ipc_recv: IncomingIpcReceiver,
}

impl<S> Inner<S>
where
    S: ghost_actor::GhostChannelSender<LairClientApi>,
{
    pub async fn spawn(
        config: Arc<Config>,
        _api_sender: S,
        _incoming_send: futures::channel::mpsc::Sender<(
            KillSwitch,
            LairClientEventSenderType,
        )>,
    ) -> LairResult<()> {
        let (kill_switch, incoming_ipc_recv) =
            spawn_bind_ipc(config.clone()).await?;
        tokio::task::spawn(async move {
            let mut i = Inner {
                _config: config,
                _api_sender,
                _incoming_send,
                kill_switch,
                incoming_ipc_recv,
            };
            while i.process().await.is_ok() {}
        });
        Ok(())
    }

    pub async fn process(&mut self) -> LairResult<()> {
        let (_kill_switch, _ipc_send, _ipc_recv) =
            match self.incoming_ipc_recv.next().await {
                Some(r) => r,
                None => return Err("incoming stream end".into()),
            };

        if !self.kill_switch.cont() {
            return Err("kill_switch triggered".into());
        }
        Ok(())
    }
}
