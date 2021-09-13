use super::*;
use futures::stream::BoxStream;
use parking_lot::Mutex;
use std::future::Future;

#[derive(Clone)]
pub(crate) struct LowLevelWireSender {
    limit: Arc<tokio::sync::Semaphore>,
    notify_kill: Arc<tokio::sync::Notify>,
    inner: Arc<Mutex<Option<IpcWrite>>>,
}

impl LowLevelWireSender {
    pub fn new(
        raw_send: IpcWrite,
        limit: Arc<tokio::sync::Semaphore>,
        notify_kill: Arc<tokio::sync::Notify>,
    ) -> Self {
        let inner = Arc::new(Mutex::new(Some(raw_send)));
        Self {
            limit,
            notify_kill,
            inner,
        }
    }

    pub fn close(&self) {
        self.limit.close();
        self.notify_kill.notify_waiters();
    }

    pub fn send(
        &self,
        msg: LairWire,
    ) -> impl Future<Output = LairResult<()>> + 'static + Send {
        let limit = self.limit.clone();
        let notify_kill = self.notify_kill.clone();
        let inner = self.inner.clone();
        async move {
            let msg_enc = msg.encode()?;

            let _permit = limit
                .clone()
                .acquire_owned()
                .await
                .map_err(LairError::other)?;

            // if we have a permit, the sender is available
            let mut raw_send = inner.lock().take().unwrap();

            let write_fut = raw_send.write_all(&msg_enc);
            let kill_fut = notify_kill.clone();
            let kill_fut = kill_fut.notified();
            tokio::select! {
                _ = kill_fut => {
                    // killed from the receiver side? let's try to shuttdown
                    let _ = raw_send.shutdown().await;
                    return Err("closed".into());
                }
                res = write_fut => {
                    if let Err(err) = res.map_err(LairError::other) {
                        limit.close();
                        notify_kill.notify_waiters();
                        return Err(err);
                    }
                }
            }

            *(inner.lock()) = Some(raw_send);

            Ok(())
        }
    }
}

pub(crate) struct LowLevelWireReceiver(
    BoxStream<'static, LairResult<LairWire>>,
);

impl LowLevelWireReceiver {
    pub fn new(
        raw_recv: IpcRead,
        limit: Arc<tokio::sync::Semaphore>,
        notify_kill: Arc<tokio::sync::Notify>,
    ) -> Self {
        struct State {
            limit: Arc<tokio::sync::Semaphore>,
            notify_kill: Arc<tokio::sync::Notify>,
            raw_recv: IpcRead,
            pending_msgs: Vec<LairWire>,
            pending_data: Vec<u8>,
            buffer: [u8; 4096],
        }

        let state = State {
            limit,
            notify_kill,
            raw_recv,
            pending_msgs: Vec::new(),
            pending_data: Vec::new(),
            buffer: [0; 4096],
        };

        let stream = futures::stream::try_unfold(state, |state| async move {
            let State {
                limit,
                notify_kill,
                mut raw_recv,
                mut pending_msgs,
                mut pending_data,
                mut buffer,
            } = state;

            loop {
                if !pending_msgs.is_empty() {
                    return Ok(Some((
                        pending_msgs.remove(0),
                        State {
                            limit,
                            notify_kill,
                            raw_recv,
                            pending_msgs,
                            pending_data,
                            buffer,
                        },
                    )));
                }

                if limit.is_closed() {
                    return Err("closed".into());
                }

                trace!("ll read tick");
                let read_fut = raw_recv.read(&mut buffer);
                let kill_fut = notify_kill.clone();
                let kill_fut = kill_fut.notified();
                let read = tokio::select! {
                    _ = kill_fut => {
                        return Err("closed".into());
                    }
                    read = read_fut => {
                        match read.map_err(LairError::other) {
                            Ok(read) => read,
                            Err(err) => {
                                limit.close();
                                notify_kill.notify_waiters();
                                return Err(err);
                            }
                        }
                    }
                };
                trace!(?read, "ll read count");
                if read == 0 {
                    trace!("ll read end");
                    limit.close();
                    notify_kill.notify_waiters();
                    return Err("read returned 0 bytes".into());
                }
                pending_data.extend_from_slice(&buffer[..read]);
                while let Ok(size) = LairWire::peek_size(&pending_data) {
                    trace!(?size, "ll read peek size");
                    if pending_data.len() < size {
                        break;
                    }
                    let msg = match LairWire::decode(&pending_data) {
                        Ok(msg) => msg,
                        Err(err) => {
                            limit.close();
                            notify_kill.notify_waiters();
                            return Err(err);
                        }
                    };
                    let _ = pending_data.drain(..size);
                    trace!("ll read {:?}", msg);
                    pending_msgs.push(msg);
                }
            }
        })
        .boxed();
        Self(stream)
    }
}

impl futures::stream::Stream for LowLevelWireReceiver {
    type Item = LairResult<LairWire>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        futures::stream::Stream::poll_next(std::pin::Pin::new(&mut self.0), cx)
    }
}
