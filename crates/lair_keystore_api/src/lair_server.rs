//! host a lair keystore

use crate::lair_api::traits::AsLairCodec;
use crate::prelude::*;
use futures::future::{BoxFuture, FutureExt};
use futures::stream::StreamExt;
use parking_lot::RwLock;
use std::future::Future;
use std::sync::atomic;
use std::sync::Arc;

/// Traits related to LairServer. Unless you're writing a new
/// implementation, you probably don't need these.
pub mod traits {
    use super::*;

    /// trait object type for AsyncWrite instance.
    pub type RawSend = Box<dyn tokio::io::AsyncWrite + 'static + Send + Unpin>;

    /// trait object type for AsyncRead instance.
    pub type RawRecv = Box<dyn tokio::io::AsyncRead + 'static + Send + Unpin>;

    /// host a lair keystore
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
use traits::*;

/// host a lair keystore
#[derive(Clone)]
pub struct LairServer(pub Arc<dyn AsLairServer>);

impl LairServer {
    /// accept an incoming connection, servicing the lair protocol.
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

    /// get a handle to the LairStore instantiated by this server,
    /// may error if a store has not yet been created.
    pub fn store(
        &self,
    ) -> impl Future<Output = LairResult<LairStore>> + 'static + Send {
        AsLairServer::store(&*self.0)
    }
}

/// spawn a tokio task managing a lair server with given store factory.
pub fn spawn_lair_server_task<C>(
    config: C,
    server_name: Arc<str>,
    server_version: Arc<str>,
    store_factory: LairStoreFactory,
    passphrase: sodoken::BufRead,
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

/// Helper for managing a signature_fallback sub-process
#[derive(Clone)]
pub(crate) struct FallbackCmd {
    req: tokio::sync::mpsc::Sender<(
        LairApiReqSignByPubKey,
        tokio::sync::oneshot::Sender<LairResult<LairApiResSignByPubKey>>,
    )>,
    child: Arc<tokio::process::Child>,
}

impl FallbackCmd {
    /// spawn a new sub-process for fallback signature requests
    pub(crate) async fn new(config: &LairServerConfig) -> LairResult<Self> {
        let (program, args) = match &config.signature_fallback {
            LairServerSignatureFallback::Command { program, args } => {
                (program.clone(), args.clone())
            }
            oth => {
                return Err(format!(
                    "invalid signature_fallback type: {:?}",
                    oth,
                )
                .into());
            }
        };

        let program = dunce::canonicalize(program)?;
        let args = args.unwrap_or_else(Vec::new);

        // spawn the actual sub-process
        let mut child = tokio::process::Command::new(program)
            .args(args)
            .kill_on_drop(true)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()?;

        // get our pipe handles
        let mut stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();

        let (send, mut recv) = tokio::sync::mpsc::channel::<(
            LairApiReqSignByPubKey,
            tokio::sync::oneshot::Sender<LairResult<LairApiResSignByPubKey>>,
        )>(4096);

        use std::collections::HashMap;
        struct Inner {
            p: HashMap<
                Arc<str>,
                tokio::sync::oneshot::Sender<
                    LairResult<LairApiResSignByPubKey>,
                >,
            >,
        }

        use parking_lot::Mutex;
        let inner = Arc::new(Mutex::new(Inner { p: HashMap::new() }));

        // spawn a tokio task to manage sending requests into the sub-process
        let inner2 = inner.clone();
        tokio::task::spawn(async move {
            while let Some((req, res)) = recv.recv().await {
                inner2.lock().p.insert(req.msg_id.clone(), res);
                let pub_key = base64::encode_config(
                    &*req.pub_key.0,
                    base64::URL_SAFE_NO_PAD,
                );
                let data = base64::encode(req.data);
                let output = format!(
                    "{}\n",
                    serde_json::to_string(&serde_json::json!({
                        "msgId": req.msg_id,
                        "pubKey": pub_key,
                        "dataToSign": data,
                    }))
                    .unwrap(),
                );
                use tokio::io::AsyncWriteExt;
                if let Err(e) = stdin.write_all(output.as_bytes()).await {
                    tracing::error!("signature_fallback write error: {:?}", e);
                    return;
                }
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
                        return;
                    }
                    Ok(r) => r,
                };

                // send the response back to the requesting logic
                let respond = inner.lock().p.remove(&res.msg_id);
                if let Some(respond) = respond {
                    if let Some(error) = res.error {
                        let _ = respond.send(Err(error.into()));
                    } else if let Some(signature) = res.signature {
                        let signature = match base64::decode(&signature) {
                            Ok(s) => s,
                            Err(e) => {
                                tracing::error!(
                                    "signature_fallback read error: {:?}",
                                    e
                                );
                                return;
                            }
                        };
                        if signature.len() != 64 {
                            tracing::error!("signature_fallback read error: invalid signature size");
                            return;
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
        });

        Ok(Self {
            req: send,
            child: Arc::new(child),
        })
    }

    /// make a request of the sub-process to sign some data
    pub(crate) fn sign_by_pub_key(
        &self,
        req: LairApiReqSignByPubKey,
    ) -> impl Future<Output = LairResult<LairApiResSignByPubKey>> + 'static + Send
    {
        let send = self.req.clone();
        async move {
            let (s, r) = tokio::sync::oneshot::channel();
            send.send((req, s))
                .await
                .map_err(|_| one_err::OneErr::new("no fallback cmd task"))?;
            r.await
                .map_err(|_| one_err::OneErr::new("no fallback cmd task"))?
        }
    }
}
