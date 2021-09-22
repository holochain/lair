use super::*;

/// wrap our streams with cryptography.
pub(crate) fn priv_crypt(
    send: PrivFramedSend,
    enc: sss::SecretStreamEncrypt,
    recv: PrivFramedRecv,
    dec: sss::SecretStreamDecrypt,
) -> (PrivCryptSend, PrivCryptRecv) {
    let send = PrivCryptSend::new(send, enc);
    let recv = PrivCryptRecv::new(recv, dec);
    (send, recv)
}

/// Encryption sender.
pub(crate) struct PrivCryptSend {
    send: PrivFramedSend,
    enc: sss::SecretStreamEncrypt,
}

impl PrivCryptSend {
    /// Initialize the encryption sender.
    pub(crate) fn new(
        send: PrivFramedSend,
        enc: sss::SecretStreamEncrypt,
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
            let len = data.len() + sss::ABYTES;

            // initialize the cipher buffer
            let cipher = sodoken::BufExtend::new_no_lock(len);

            // encrypt the message
            self.enc
                .push_message(
                    data,
                    <Option<sodoken::BufRead>>::None,
                    cipher.clone(),
                )
                .await?;

            // extract the raw cipher data
            let cipher = cipher.try_unwrap().unwrap();

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
    pub fn new(recv: PrivFramedRecv, dec: sss::SecretStreamDecrypt) -> Self {
        let recv = futures::stream::try_unfold(
            (recv, dec),
            |(mut recv, mut dec)| async move {
                let cipher = match recv.next().await {
                    None => return Ok(None),
                    Some(cipher) => cipher?,
                };
                let cipher = sodoken::BufRead::from(cipher);
                let msg =
                    sodoken::BufWrite::new_no_lock(cipher.len() - sss::ABYTES);
                dec.pull(cipher, <Option<sodoken::BufRead>>::None, msg.clone())
                    .await?;
                let msg = msg.try_unwrap().unwrap();
                Ok(Some((msg, (recv, dec))))
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
