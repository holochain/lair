use super::*;

/// wrap our streams with framing so we know message boundaries.
pub(crate) fn priv_framed(
    send: PrivRawSend,
    recv: PrivRawRecv,
) -> (PrivFramedSend, PrivFramedRecv) {
    let send = PrivFramedSend(send);
    let recv = PrivFramedRecv::new(recv);
    (send, recv)
}

/// A framed sender.
pub(crate) struct PrivFramedSend(PrivRawSend);

impl PrivFramedSend {
    /// Send framed data.
    pub(crate) fn send(
        &mut self,
        d: Box<[u8]>,
    ) -> impl Future<Output = LairResult<()>> + '_ + Send {
        async move {
            if d.len() > MAX_FRAME {
                return Err(OneErr::with_message(
                    "FrameOverflow",
                    format!("{} > {}", d.len(), MAX_FRAME),
                ));
            }

            let ltag = (d.len() as u16).to_le_bytes();

            // something more efficient than just writing both buffers?

            self.0.write_all(&ltag).await?;
            self.0.write_all(&d).await?;
            Ok(())
        }
    }

    /// Forwards shutdown to the underlying raw sender.
    pub(crate) fn shutdown(
        &mut self,
    ) -> impl Future<Output = LairResult<()>> + '_ + Send {
        async move { self.0.shutdown().await.map_err(OneErr::new) }
    }
}

/// A framed receiver.
pub(crate) struct PrivFramedRecv(BoxStream<'static, LairResult<Box<[u8]>>>);

impl PrivFramedRecv {
    /// Initialize the framed receiver.
    pub fn new(recv: PrivRawRecv) -> Self {
        let recv = futures::stream::try_unfold(recv, |mut recv| async move {
            // something more efficient than doing this in 2 steps?

            // first, receive the u16_le frame length
            let mut ltag = [0; 2];
            recv.read_exact(&mut ltag).await?;
            let ltag = u16::from_le_bytes(ltag) as usize;

            // check if the length tag is out of bounds
            if ltag > MAX_FRAME {
                return Err(OneErr::with_message(
                    "FrameOverflow",
                    format!("{} > {}", ltag, MAX_FRAME),
                ));
            }

            // initialize our receive buffer
            let mut msg = Vec::with_capacity(ltag);

            // we could try to figure out the async uninit thing
            // (https://docs.rs/tokio/1.11.0/tokio/io/struct.ReadBuf.html#method.uninit)
            // but this is actually safe given the reader doesn't inspect
            // the uninitialized data, and in the case of an error
            // this potentially partially filled buffer is not returned.
            #[allow(unsafe_code)]
            unsafe {
                msg.set_len(ltag);
            }

            // read the incoming data
            recv.read_exact(&mut msg).await?;

            Ok(Some((msg.into_boxed_slice(), recv)))
        });
        Self(recv.boxed())
    }
}

impl Stream for PrivFramedRecv {
    type Item = LairResult<Box<[u8]>>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        Stream::poll_next(std::pin::Pin::new(&mut self.0), cx)
    }
}
