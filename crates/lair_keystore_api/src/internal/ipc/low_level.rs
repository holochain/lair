use super::*;
use futures::stream::BoxStream;
use parking_lot::Mutex;
use std::future::Future;

#[allow(dead_code)]
#[derive(Clone)]
pub(crate) struct LowLevelWireSender {
    limit: Arc<tokio::sync::Semaphore>,
    inner: Arc<Mutex<Option<IpcWrite>>>,
}

impl LowLevelWireSender {
    #[allow(dead_code)]
    pub fn new(raw_send: IpcWrite) -> Self {
        // rather than having a single permit, it would be more efficient
        // to batch up some number of messages while any sends are outstanding
        // then send the whole batch at once while we have cpu time.
        let limit = Arc::new(tokio::sync::Semaphore::new(1));
        let inner = Arc::new(Mutex::new(Some(raw_send)));
        Self { limit, inner }
    }

    #[allow(dead_code)]
    pub fn close(&self) {
        self.limit.close();
    }

    #[allow(dead_code)]
    pub fn send(
        &self,
        msg: LairWire,
    ) -> impl Future<Output = LairResult<()>> + 'static + Send {
        let limit = self.limit.clone();
        let inner = self.inner.clone();
        async move {
            let msg_enc = msg.encode()?;

            let _permit =
                limit.acquire_owned().await.map_err(LairError::other)?;

            // if we have a permit, the sender is available
            let mut raw_send = inner.lock().take().unwrap();

            let res =
                raw_send.write_all(&msg_enc).await.map_err(LairError::other);
            *(inner.lock()) = Some(raw_send);
            trace!("ll wrote {:?}", &msg);
            res
        }
    }
}

#[allow(dead_code)]
pub(crate) struct LowLevelWireReceiver(
    BoxStream<'static, LairResult<LairWire>>,
);

impl LowLevelWireReceiver {
    #[allow(dead_code)]
    pub fn new(raw_recv: IpcRead) -> Self {
        struct State {
            raw_recv: IpcRead,
            pending_msgs: Vec<LairWire>,
            pending_data: Vec<u8>,
            buffer: [u8; 4096],
        }

        let state = State {
            raw_recv,
            pending_msgs: Vec::new(),
            pending_data: Vec::new(),
            buffer: [0; 4096],
        };

        let stream = futures::stream::try_unfold(state, |state| async move {
            let State {
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
                            raw_recv,
                            pending_msgs,
                            pending_data,
                            buffer,
                        },
                    )));
                }

                trace!("ll read tick");
                let read = raw_recv
                    .read(&mut buffer)
                    .await
                    .map_err(LairError::other)?;
                trace!(?read, "ll read count");
                if read == 0 {
                    trace!("ll read end");
                    return Err("read returned 0 bytes".into());
                }
                pending_data.extend_from_slice(&buffer[..read]);
                while let Ok(size) = LairWire::peek_size(&pending_data) {
                    trace!(?size, "ll read peek size");
                    if pending_data.len() < size {
                        break;
                    }
                    let msg = LairWire::decode(&pending_data)?;
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
