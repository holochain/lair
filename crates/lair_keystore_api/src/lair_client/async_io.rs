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

        let (teardown_done, teardown_wait) =
            tokio::sync::watch::channel(Teardown::Pending);

        // build up our inner item
        let inner = CliInner {
            enc_ctx_key: Arc::new(Mutex::new(enc_ctx_key)),
            dec_ctx_key: Arc::new(Mutex::new(dec_ctx_key)),
            send: send.clone(),
            pending: HashMap::new(),
            recv_loop: None,
            closed: false,
            teardown_done,
            teardown_wait,
        };

        let inner = Arc::new(RwLock::new(inner));

        // spawn a task to manage incoming data, keeping its join handle so
        // `shutdown` can await the connection teardown before returning
        let recv_loop = {
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
            })
        };

        inner.write().expect("mutex poisoned").recv_loop = Some(recv_loop);

        Ok(LairClient(Arc::new(Cli(inner))))
    }
}

// -- private -- //

#[derive(Clone, Copy, PartialEq, Eq)]
enum Teardown {
    Pending,
    Done,
    Failed,
}

struct CliInner {
    enc_ctx_key: SharedSizedLockedArray<32>,
    dec_ctx_key: SharedSizedLockedArray<32>,
    send: sodium_secretstream::S3Sender<LairApiEnum>,
    pending: HashMap<Arc<str>, tokio::sync::oneshot::Sender<LairApiEnum>>,
    recv_loop: Option<tokio::task::JoinHandle<()>>,
    closed: bool,
    teardown_done: tokio::sync::watch::Sender<Teardown>,
    teardown_wait: tokio::sync::watch::Receiver<Teardown>,
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
        let inner = self.0.clone();
        async move {
            let (send, recv_loop, mut teardown_done) = {
                let mut lock = inner.write().expect("poisoned");
                lock.closed = true;
                let teardown_done = lock.teardown_wait.clone();
                let recv_loop = lock.recv_loop.take();
                if recv_loop.is_some() {
                    let _ = lock.teardown_done.send(Teardown::Pending);
                }
                (lock.send.clone(), recv_loop, teardown_done)
            };

            if recv_loop.is_none() {
                // another caller is already tearing down - await its completion
                return match teardown_done
                    .wait_for(|state| *state != Teardown::Pending)
                    .await
                {
                    Ok(state) if *state == Teardown::Done => Ok(()),
                    Ok(_) => Err(OneErr::new("Shutdown failed")),
                    Err(err) => Err(OneErr::new(format!(
                        "Could not receive teardown completion {err}"
                    ))),
                };
            }

            // close our write side so the remote sees EOF and closes too
            if let Err(err) = send.shutdown().await {
                let mut lock = inner.write().expect("poisoned");
                lock.closed = false;
                lock.recv_loop = recv_loop;
                let _ = lock.teardown_done.send(Teardown::Failed);
                return Err(err);
            };

            // await the recv loop so the whole connection is torn down by
            // the time shutdown returns
            if let Some(recv_loop) = recv_loop {
                let _ = recv_loop.await;
            }

            let mut lock = inner.write().expect("poisoned");
            // kill any pending requests - they won't ever get responses.
            lock.pending.clear();
            let _ = lock.teardown_done.send(Teardown::Done);

            Ok(())
        }
        .boxed()
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
            if lock.closed {
                return async move {
                    Err::<LairApiEnum, _>(one_err::OneErr::from(
                        std::io::ErrorKind::ConnectionAborted,
                    ))
                }
                .boxed();
            }
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
