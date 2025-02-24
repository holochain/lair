//! Wrap a raw tokio::io::Async{Read, Write} channel into a LairClient.

use super::*;

/// Wrap a raw tokio::io::Async{Read, Write} channel into a LairClient.
pub fn new_async_io_lair_client<S, R>(
    send: S,
    recv: R,
    srv_id_pub_key: BinDataSized<32>,
) -> impl Future<Output = LairResult<LairClient>> + 'static + Send
where
    S: tokio::io::AsyncWrite + 'static + Send + Unpin,
    R: tokio::io::AsyncRead + 'static + Send + Unpin,
{
    async move {
        // wrap the channels in sodium_secretstream
        let (send, recv) = sodium_secretstream::new_s3_client::<
            LairApiEnum,
            _,
            _,
        >(send, recv, srv_id_pub_key)
        .await?;

        // derive our encryption (to server) secret context key
        let mut enc_ctx_key = sodoken::SizedLockedArray::<32>::new()?;
        sodoken::kdf::derive_from_key(
            &mut *enc_ctx_key.lock(),
            142,
            b"ToSrvCxK",
            &send.get_enc_ctx_key().lock().unwrap().lock(),
        )?;

        // derive our decryption (from server) secret context key
        let mut dec_ctx_key = sodoken::SizedLockedArray::<32>::new()?;
        sodoken::kdf::derive_from_key(
            &mut *dec_ctx_key.lock(),
            42,
            b"ToCliCxK",
            &send.get_dec_ctx_key().lock().unwrap().lock(),
        )?;

        // build up our inner item
        let inner = CliInner {
            enc_ctx_key: Arc::new(Mutex::new(enc_ctx_key)),
            dec_ctx_key: Arc::new(Mutex::new(dec_ctx_key)),
            send: send.clone(),
            pending: HashMap::new(),
        };

        let inner = Arc::new(RwLock::new(inner));

        {
            // spawn a task to manage incoming data
            let inner = inner.clone();
            tokio::task::spawn(async move {
                let inner = &inner;
                let send = &send;

                recv.for_each_concurrent(4096, move |incoming| async move {
                    let incoming = match incoming {
                        Err(e) => {
                            tracing::warn!("incoming channel error: {:?}", e);
                            return;
                        }
                        Ok(incoming) => incoming,
                    };

                    // if we were waiting for this response, match up / respond.
                    let msg_id = incoming.msg_id();
                    if let Some(resp) =
                        inner.write().unwrap().pending.remove(&msg_id)
                    {
                        let _ = resp.send(incoming);
                    }
                })
                .await;

                let _ = send.shutdown().await;

                tracing::warn!("lair connection recv loop ended");

                // kill any pending requests - they won't ever get responses.
                inner.write().unwrap().pending.clear();
            });
        }

        Ok(LairClient(Arc::new(Cli(inner))))
    }
}

// -- private -- //

struct CliInner {
    enc_ctx_key: SharedSizedLockedArray<32>,
    dec_ctx_key: SharedSizedLockedArray<32>,
    send: sodium_secretstream::S3Sender<LairApiEnum>,
    pending: HashMap<Arc<str>, tokio::sync::oneshot::Sender<LairApiEnum>>,
}

struct Cli(Arc<RwLock<CliInner>>);

impl AsLairClient for Cli {
    fn get_enc_ctx_key(&self) -> SharedSizedLockedArray<32> {
        self.0.read().unwrap().enc_ctx_key.clone()
    }

    fn get_dec_ctx_key(&self) -> SharedSizedLockedArray<32> {
        self.0.read().unwrap().dec_ctx_key.clone()
    }

    fn shutdown(&self) -> BoxFuture<'static, LairResult<()>> {
        let send = self.0.read().unwrap().send.clone();
        send.shutdown().boxed()
    }

    fn request(
        &self,
        request: LairApiEnum,
    ) -> BoxFuture<'static, LairResult<LairApiEnum>> {
        let (s, r) = tokio::sync::oneshot::channel();
        let msg_id = request.msg_id();

        // set up a struct to clean up our pending entry
        // whether this call completes or times out.
        struct Clean(Arc<RwLock<CliInner>>, Arc<str>);

        impl Drop for Clean {
            fn drop(&mut self) {
                let _ = self.0.write().unwrap().pending.remove(&self.1);
            }
        }

        let clean = Clean(self.0.clone(), msg_id.clone());

        let send = {
            let mut lock = self.0.write().unwrap();
            lock.pending.insert(msg_id, s);
            lock.send.clone()
        };

        async move {
            // keep the raii clean instance here
            // it will clean up our pending entry when this future is dropped.
            let _clean = clean;

            // send our request on the channel
            send.send(request).await?;

            // either time out or get our response from the pending store
            tokio::time::timeout(std::time::Duration::from_secs(30), r)
                .await
                .map_err(|_| {
                    one_err::OneErr::from(std::io::ErrorKind::TimedOut)
                })?
                .map_err(|_| {
                    one_err::OneErr::from(std::io::ErrorKind::ConnectionAborted)
                })
        }
        .boxed()
    }
}
