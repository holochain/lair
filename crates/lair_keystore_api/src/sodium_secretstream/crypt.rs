use super::*;
use crate::dependencies::sodoken::secretstream::Tag;
use assert_cmd::assert::IntoOutputPredicate;

/// wrap our streams with cryptography.
pub(crate) fn priv_crypt(
    send: PrivFramedSend,
    enc: sodoken::secretstream::State,
    recv: PrivFramedRecv,
    dec: sodoken::secretstream::State,
) -> (PrivCryptSend, PrivCryptRecv) {
    let send = PrivCryptSend::new(send, enc);
    let recv = PrivCryptRecv::new(recv, dec);
    (send, recv)
}

/// Encryption sender.
pub(crate) struct PrivCryptSend {
    send: PrivFramedSend,
    enc: sodoken::secretstream::State,
}

impl PrivCryptSend {
    /// Initialize the encryption sender.
    pub(crate) fn new(
        send: PrivFramedSend,
        enc: sodoken::secretstream::State,
    ) -> Self {
        Self { send, enc }
    }

    /// Send encrypted data to the remote.
    pub(crate) fn send(
        &mut self,
        data: Box<[u8]>,
    ) -> impl Future<Output = LairResult<()>> + '_ + Send {
        async move {
            // calculate the cipher length
            let len = data.len() + sodoken::secretstream::ABYTES;

            // initialize the cipher buffer
            let mut cipher = sodoken::LockedArray::new(len)?;

            // encrypt the message
            sodoken::secretstream::push(
                &mut self.enc,
                &mut cipher.lock(),
                data.as_ref(),
                None,
                Tag::Message,
            )?;

            // extract the raw cipher data
            let cipher = cipher.lock().into();

            // send the cipher to the remote
            self.send.send(cipher).await?;

            Ok(())
        }
    }

    /// Forwards shutdown to the underlying framed sender.
    pub(crate) fn shutdown(
        &mut self,
    ) -> impl Future<Output = LairResult<()>> + '_ + Send {
        async move { self.send.shutdown().await }
    }
}

/// Decryption receiver.
pub(crate) struct PrivCryptRecv(BoxStream<'static, LairResult<Box<[u8]>>>);

impl PrivCryptRecv {
    /// Initialize the new decryption receiver.
    pub fn new(
        recv: PrivFramedRecv,
        dec: sodoken::secretstream::State,
    ) -> Self {
        let recv = futures::stream::try_unfold(
            (recv, dec),
            |(mut recv, mut dec)| async move {
                let cipher = match recv.next().await {
                    None => return Ok(None),
                    Some(cipher) => cipher?,
                };
                let mut cipher = sodoken::LockedArray::from(cipher);
                let mut msg = sodoken::LockedArray::new(
                    cipher.lock().len() - sodoken::secretstream::ABYTES,
                )?;

                sodoken::secretstream::pull(
                    &mut dec,
                    &mut msg.lock(),
                    &cipher.lock(),
                    None,
                )?;

                let out = Box::<[u8]>::from(&*msg.lock());

                Ok(Some((out, (recv, dec))))
            },
        );
        Self(recv.boxed())
    }
}

impl Stream for PrivCryptRecv {
    type Item = LairResult<Box<[u8]>>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        Stream::poll_next(std::pin::Pin::new(&mut self.0), cx)
    }
}
