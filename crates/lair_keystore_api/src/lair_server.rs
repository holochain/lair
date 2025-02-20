//! Items for acting as a lair keystore server.

use crate::lair_api::api_traits::AsLairCodec;
use crate::*;
use base64::Engine;
use futures::future::{BoxFuture, FutureExt};
use futures::stream::StreamExt;
use parking_lot::{Mutex, RwLock};
use std::future::Future;
use std::sync::atomic;
use std::sync::Arc;

/// Traits related to LairServer. Unless you're writing a new
/// implementation, you probably don't need these.
pub mod server_traits {
    use super::*;

    /// Trait object type for AsyncWrite instance.
    pub type RawSend = Box<dyn tokio::io::AsyncWrite + 'static + Send + Unpin>;

    /// Trait object type for AsyncRead instance.
    pub type RawRecv = Box<dyn tokio::io::AsyncRead + 'static + Send + Unpin>;

    /// Object-safe lair server trait. Implement this to provide a new
    /// lair server backend implementation.
    pub trait AsLairServer: 'static + Send + Sync {
        /// accept an incoming connection, servicing the lair protocol.
        fn accept(
            &self,
            send: RawSend,
            recv: RawRecv,
        ) -> BoxFuture<'static, LairResult<()>>;

        /// get a handle to the LairStore instantiated by this server,
        /// may error if a store has not yet been created.
        fn store(&self) -> BoxFuture<'static, LairResult<LairStore>>;
    }
}
use server_traits::*;

/// A lair keystore server handle.
/// Use this to handle incoming client connections.
#[derive(Clone)]
pub struct LairServer(pub Arc<dyn AsLairServer>);

impl LairServer {
    /// Accept an incoming connection, servicing the lair protocol.
    pub fn accept<S, R>(
        &self,
        send: S,
        recv: R,
    ) -> impl Future<Output = LairResult<()>> + 'static + Send
    where
        S: tokio::io::AsyncWrite + 'static + Send + Unpin,
        R: tokio::io::AsyncRead + 'static + Send + Unpin,
    {
        AsLairServer::accept(&*self.0, Box::new(send), Box::new(recv))
    }

    /// Get a handle to the LairStore instantiated by this server,
    /// may error if a store has not yet been created.
    pub fn store(
        &self,
    ) -> impl Future<Output = LairResult<LairStore>> + 'static + Send {
        AsLairServer::store(&*self.0)
    }
}

/// Spawn a tokio task managing a lair server with given store factory.
pub fn spawn_lair_server_task<C>(
    config: C,
    server_name: Arc<str>,
    server_version: Arc<str>,
    store_factory: LairStoreFactory,
    passphrase: Arc<Mutex<sodoken::LockedArray>>,
) -> impl Future<Output = LairResult<LairServer>> + 'static + Send
where
    C: Into<LairServerConfig> + 'static + Send,
{
    async move {
        let srv = Srv::new(
            config.into(),
            server_name,
            server_version,
            store_factory,
            passphrase,
        )
        .await?;

        Ok(LairServer(Arc::new(srv)))
    }
}

// -- private -- //

mod priv_srv;
use priv_srv::*;

mod priv_api;
use priv_api::*;

type SubProcReqSender = tokio::sync::mpsc::Sender<(
    LairApiReqSignByPubKey,
    tokio::sync::oneshot::Sender<LairResult<LairApiResSignByPubKey>>,
)>;

struct FallbackCmdInner {
    id: String,
    sender: SubProcReqSender,
    child: tokio::process::Child,
}

/// Helper for managing a signature_fallback sub-process
#[derive(Clone)]
pub(crate) struct FallbackCmd {
    config: LairServerConfig,
    inner: Arc<RwLock<Option<FallbackCmdInner>>>,
}

impl FallbackCmd {
    /// spawn a new sub-process for fallback signature requests
    pub(crate) async fn new(config: &LairServerConfig) -> LairResult<Self> {
        Ok(Self {
            config: config.clone(),
            inner: Arc::new(RwLock::new(None)),
        })
    }

    fn check_get_sub_process_sender(
        &self,
    ) -> impl Future<Output = LairResult<SubProcReqSender>> + 'static + Send
    {
        let config = self.config.clone();
        let inner = self.inner.clone();
        async move {
            let (send, mut recv, mut stdin, stdout, id) = {
                let mut lock = inner.write();

                if let Some(inner) = &mut *lock {
                    if let Ok(None) = inner.child.try_wait() {
                        tracing::trace!("@sig_fb@ using existing child");

                        // child is still running
                        return Ok(inner.sender.clone());
                    }
                }

                let id = nanoid::nanoid!();

                // otherwise, we need to spawn a new child
                let (send, recv) = tokio::sync::mpsc::channel::<(
                    LairApiReqSignByPubKey,
                    tokio::sync::oneshot::Sender<
                        LairResult<LairApiResSignByPubKey>,
                    >,
                )>(4096);

                let (program, args) = match &config.signature_fallback {
                    LairServerSignatureFallback::Command { program, args } => {
                        (program.clone(), args.clone())
                    }
                    oth => {
                        return Err(format!(
                            "invalid signature_fallback type: {oth:?}",
                        )
                        .into());
                    }
                };

                let program = dunce::canonicalize(program)?;
                let args = args.unwrap_or_default();

                // spawn the actual sub-process
                let mut child = tokio::process::Command::new(program);
                child
                    .args(args)
                    .kill_on_drop(true)
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::inherit());
                tracing::info!("@sig_fb@ spawn new child: {:?}", child);
                let mut child = child.spawn()?;

                // get our pipe handles
                let stdin = child.stdin.take().unwrap();
                let stdout = child.stdout.take().unwrap();

                // set at the beginning BEFORE ANY AWAITS
                // so we don't have a race condition
                *lock = Some(FallbackCmdInner {
                    id: id.clone(),
                    sender: send.clone(),
                    child,
                });

                (send, recv, stdin, stdout, id)
            };

            use std::collections::HashMap;
            struct Pending {
                running: bool,
                pending: HashMap<
                    Arc<str>,
                    tokio::sync::oneshot::Sender<
                        LairResult<LairApiResSignByPubKey>,
                    >,
                >,
            }

            use parking_lot::Mutex;
            let pending = Arc::new(Mutex::new(Pending {
                running: true,
                pending: HashMap::new(),
            }));

            // spawn a tokio task to manage sending requests into the sub-process
            let inner2 = inner.clone();
            let pending2 = pending.clone();
            let id2 = id.clone();
            tokio::task::spawn(async move {
                while let Some((req, res)) = recv.recv().await {
                    {
                        let mut lock = pending2.lock();
                        if !lock.running {
                            tracing::warn!("@sig_fb@ exit write loop due to shutdown from read side");
                            let _ = res.send(Err(
                                "signature fallback process closed".into(),
                            ));
                            break;
                        }
                        lock.pending.insert(req.msg_id.clone(), res);
                    }
                    let pub_key = base64::prelude::BASE64_URL_SAFE_NO_PAD
                        .encode(*req.pub_key.0);
                    let data =
                        base64::prelude::BASE64_STANDARD.encode(req.data);
                    let output = format!(
                        "{}\n",
                        serde_json::to_string(&serde_json::json!({
                            "msgId": req.msg_id.clone(),
                            "pubKey": pub_key,
                            "dataToSign": data,
                        }))
                        .unwrap(),
                    );
                    use tokio::io::AsyncWriteExt;
                    if let Err(e) = stdin.write_all(output.as_bytes()).await {
                        let e =
                            format!("signature_fallback write error: {e:?}");
                        tracing::error!("@sig_fb@ {}", e);
                        let respond =
                            pending2.lock().pending.remove(&req.msg_id);
                        if let Some(respond) = respond {
                            let _ = respond.send(Err(e.into()));
                        }
                        break;
                    }
                }

                tracing::warn!("@sig_fb@ write loop exiting");

                let mut lock = inner2.write();
                let remove = if let Some(inner) = &mut *lock {
                    inner.id == id2
                } else {
                    false
                };
                if remove {
                    *lock = None
                }
            });

            // spawn a tokio task to manage receiving responses from the sub-process
            tokio::task::spawn(async move {
                use tokio::io::AsyncBufReadExt;
                let stdout = tokio::io::BufReader::new(stdout);
                let mut lines = stdout.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    // parse the response
                    #[derive(Debug, serde::Deserialize)]
                    #[serde(rename_all = "camelCase")]
                    struct Res {
                        msg_id: Arc<str>,
                        signature: Option<String>,
                        error: Option<String>,
                    }
                    let res: Res = match serde_json::from_str(&line) {
                        Err(e) => {
                            tracing::error!(
                                "signature_fallback read error: {:?}",
                                e
                            );
                            break;
                        }
                        Ok(r) => r,
                    };

                    // send the response back to the requesting logic
                    let respond = pending.lock().pending.remove(&res.msg_id);
                    if let Some(respond) = respond {
                        if let Some(error) = res.error {
                            let _ = respond.send(Err(error.into()));
                        } else if let Some(signature) = res.signature {
                            let signature =
                                match base64::prelude::BASE64_STANDARD
                                    .decode(&signature)
                                {
                                    Ok(s) => s,
                                    Err(e) => {
                                        let e = format!(
                                        "signature_fallback read error: {e:?}"
                                    );
                                        tracing::error!("@sig_fb@ {}", e);
                                        let _ = respond.send(Err(e.into()));
                                        break;
                                    }
                                };
                            if signature.len() != 64 {
                                let e =
                                    "signature_fallback read error: invalid signature size";
                                tracing::error!("@sig_fb@ {}", e);
                                let _ = respond.send(Err(e.into()));
                                break;
                            }
                            let mut sized_sig = [0; 64];
                            sized_sig.copy_from_slice(&signature);
                            let _ = respond.send(Ok(LairApiResSignByPubKey {
                                msg_id: res.msg_id,
                                signature: sized_sig.into(),
                            }));
                        }
                    }
                }

                tracing::warn!("@sig_fb@ read loop exiting");

                {
                    let mut lock = inner.write();
                    let remove = if let Some(inner) = &mut *lock {
                        inner.id == id
                    } else {
                        false
                    };
                    if remove {
                        *lock = None
                    }
                }

                let mut lock = pending.lock();
                lock.running = false;
                for (_, respond) in lock.pending.drain() {
                    let _ =
                        respond.send(Err("fallback executable closed".into()));
                }
            });

            Ok(send)
        }
    }

    /// make a request of the sub-process to sign some data
    pub(crate) fn sign_by_pub_key(
        &self,
        req: LairApiReqSignByPubKey,
    ) -> impl Future<Output = LairResult<LairApiResSignByPubKey>> + 'static + Send
    {
        let send_fut = self.check_get_sub_process_sender();
        async move {
            let send = send_fut.await?;
            let (s, r) = tokio::sync::oneshot::channel();
            send.send((req, s))
                .await
                .map_err(|_| one_err::OneErr::new("no fallback cmd task"))?;
            r.await
                .map_err(|_| one_err::OneErr::new("no fallback cmd task"))?
        }
    }
}
