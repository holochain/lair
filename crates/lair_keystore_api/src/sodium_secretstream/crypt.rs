use super::*;
use crate::dependencies::sodoken::secretstream::Tag;

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
            let mut cipher = vec![0; len];

            // encrypt the message
            sodoken::secretstream::push(
                &mut self.enc,
                cipher.as_mut_slice(),
                data.as_ref(),
                None,
                Tag::Message,
            )?;

            // send the cipher to the remote
            self.send.send(cipher.into()).await?;

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

                let mut msg =
                    vec![0; cipher.len() - sodoken::secretstream::ABYTES];
                sodoken::secretstream::pull(
                    &mut dec,
                    msg.as_mut_slice(),
                    &cipher,
                    None,
                )?;

                Ok(Some((msg.into(), (recv, dec))))
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
