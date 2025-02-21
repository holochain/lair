use super::*;

/// Internal state for the typed sender.
pub(crate) struct PrivSendInner {
    /// Resource gate for our single sender.
    limit: Arc<tokio::sync::Semaphore>,

    /// The single encryption sender.
    send: Option<PrivCryptSend>,

    /// Our transmit encryption key
    tx: SharedSizedLockedArray<{ sodoken::secretstream::KEYBYTES }>,

    /// Our receive decryption key
    rx: SharedSizedLockedArray<{ sodoken::secretstream::KEYBYTES }>,
}

/// Typed sender.
pub(crate) struct PrivSend<T>(
    Arc<Mutex<PrivSendInner>>,
    std::marker::PhantomData<fn() -> *const T>,
)
where
    T: 'static + serde::Serialize + Send;

impl<T> PrivSend<T>
where
    T: 'static + serde::Serialize + Send,
{
    /// Initialize a new typed sender.
    pub(crate) fn new(
        send: PrivCryptSend,
        tx: SharedSizedLockedArray<{ sodoken::secretstream::KEYBYTES }>,
        rx: SharedSizedLockedArray<{ sodoken::secretstream::KEYBYTES }>,
    ) -> Self {
        Self(
            Arc::new(Mutex::new(PrivSendInner {
                limit: Arc::new(tokio::sync::Semaphore::new(1)),
                send: Some(send),
                tx,
                rx,
            })),
            std::marker::PhantomData,
        )
    }
}

impl<T> AsS3Sender<T> for PrivSend<T>
where
    T: 'static + serde::Serialize + Send,
{
    fn send(&self, t: T) -> BoxFuture<'static, LairResult<()>> {
        let inner = self.0.clone();
        async move {
            // serialize the typed data
            let mut se = rmp_serde::encode::Serializer::new(Vec::new())
                .with_struct_map();
            t.serialize(&mut se).map_err(OneErr::new)?;
            let t = se.into_inner().into_boxed_slice();

            // capture a resource permit
            let limit = inner.lock().limit.clone();
            let _permit = limit.acquire_owned().await.map_err(OneErr::new)?;

            // we have a permit, get the sender
            let mut send = inner.lock().send.take().unwrap();

            // send the data
            let r = send.send(t).await;

            // return our sender resource,
            // the permit will drop as this future ends.
            inner.lock().send = Some(send);

            r
        }
        .boxed()
    }

    fn get_enc_ctx_key(
        &self,
    ) -> SharedSizedLockedArray<{ sodoken::secretstream::KEYBYTES }> {
        self.0.lock().tx.clone()
    }

    fn get_dec_ctx_key(
        &self,
    ) -> SharedSizedLockedArray<{ sodoken::secretstream::KEYBYTES }> {
        self.0.lock().rx.clone()
    }

    fn shutdown(&self) -> BoxFuture<'static, LairResult<()>> {
        let inner = self.0.clone();
        async move {
            // capture a resource permit
            let limit = inner.lock().limit.clone();
            let _permit = limit.acquire_owned().await.map_err(OneErr::new)?;

            // we have a permit, get the sender
            let mut send = inner.lock().send.take().unwrap();

            // shutdown the sender
            let r = send.shutdown().await;

            // return it so errors can still propagate up
            inner.lock().send = Some(send);

            r
        }
        .boxed()
    }
}

/// Typed receiver.
pub(crate) struct PrivRecv<T>(BoxStream<'static, LairResult<T>>);

impl<T> PrivRecv<T>
where
    T: 'static + for<'de> serde::Deserialize<'de> + Send,
{
    /// Initialize the new typed receiver.
    pub(crate) fn new(recv: PrivCryptRecv) -> Self {
        let recv = futures::stream::try_unfold(recv, |mut recv| async move {
            let msg = match recv.next().await {
                None => return Ok(None),
                Some(msg) => msg?,
            };

            let item: T = rmp_serde::from_read(&*msg).map_err(OneErr::new)?;

            Ok(Some((item, recv)))
        });
        Self(recv.boxed())
    }
}

impl<T> Stream for PrivRecv<T>
where
    T: 'static + for<'de> serde::Deserialize<'de> + Send,
{
    type Item = LairResult<T>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        Stream::poll_next(std::pin::Pin::new(&mut self.0), cx)
    }
}

impl<T> AsS3Receiver<T> for PrivRecv<T> where
    T: 'static + for<'de> serde::Deserialize<'de> + Send
{
}
