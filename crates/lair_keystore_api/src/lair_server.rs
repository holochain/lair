//! host a lair keystore

use crate::lair_core::*;
use crate::LairResult2 as LairResult;
use futures::future::{BoxFuture, FutureExt};
use futures::stream::StreamExt;
use ghost_actor::dependencies::tracing;
use parking_lot::RwLock;
use std::future::Future;
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
        /// It is much more secure to unlock a lair keystore server
        /// interactively, to mitigate a MitM capturing the passphrase.
        fn unlock(
            &self,
            passphrase: sodoken::BufRead,
        ) -> BoxFuture<'static, LairResult<()>>;

        /// accept an incoming connection, servicing the lair protocol.
        fn accept(
            &self,
            send: RawSend,
            recv: RawRecv,
        ) -> BoxFuture<'static, LairResult<()>>;
    }
}
use traits::*;

/// host a lair keystore
#[derive(Clone)]
pub struct LairServer(pub Arc<dyn AsLairServer>);

impl LairServer {
    /// It is much more secure to unlock a lair keystore server
    /// interactively, to mitigate a MitM capturing the passphrase.
    pub fn unlock(
        &self,
        passphrase: sodoken::BufRead,
    ) -> impl Future<Output = LairResult<()>> + 'static + Send {
        AsLairServer::unlock(&*self.0, passphrase)
    }

    /// accept an incoming connection, servicing the lair protocol.
    pub fn accept<S, R>(
        &self,
        send: RawSend,
        recv: RawRecv,
    ) -> impl Future<Output = LairResult<()>> + 'static + Send
    where
        S: tokio::io::AsyncWrite + 'static + Send + Unpin,
        R: tokio::io::AsyncRead + 'static + Send + Unpin,
    {
        AsLairServer::accept(&*self.0, Box::new(send), Box::new(recv))
    }
}

/// spawn a tokio task managing a lair server with given store factory.
pub async fn spawn_lair_server_task<C>(
    config: C,
    store_factory: crate::lair_core::LairStoreFactory,
) -> LairResult<LairServer>
where
    C: Into<LairServerConfig> + 'static + Send,
{
    let inner = SrvPendingInner {
        config: config.into(),
        store_factory,
    };

    let inner = SrvInnerEnum::Pending(inner);
    let inner = Arc::new(RwLock::new(inner));

    Ok(LairServer(Arc::new(Srv(inner))))
}

// -- private -- //

struct SrvPendingInner {
    config: LairServerConfig,
    #[allow(dead_code)]
    store_factory: crate::lair_core::LairStoreFactory,
}

#[allow(dead_code)]
struct SrvRunningInner {
    config: LairServerConfig,
    store: crate::lair_core::LairStore,
    context_key: sodoken::BufReadSized<32>,
    sign_pk: Ed25519PubKey,
    sign_sk: sodoken::BufReadSized<64>,
}

enum SrvInnerEnum {
    Pending(SrvPendingInner),
    #[allow(dead_code)]
    Running(SrvRunningInner),
}

struct Srv(Arc<RwLock<SrvInnerEnum>>);

fn priv_srv_unlock(
    inner: Arc<RwLock<SrvInnerEnum>>,
    passphrase: sodoken::BufRead,
) -> BoxFuture<'static, LairResult<()>> {
    let (config, store_factory) = match &*inner.read() {
        SrvInnerEnum::Running(p) => (p.config.clone(), None),
        SrvInnerEnum::Pending(p) => {
            (p.config.clone(), Some(p.store_factory.clone()))
        }
    };

    async move {
        let salt = sodoken::BufReadSized::from(
            config.runtime_secrets_salt.cloned_inner(),
        );
        let ops_limit = config.runtime_secrets_ops_limit;
        let mem_limit = config.runtime_secrets_mem_limit;

        let pre_secret = <sodoken::BufWriteSized<32>>::new_mem_locked()?;
        sodoken::hash::argon2id::hash(
            pre_secret.clone(),
            passphrase,
            salt,
            ops_limit,
            mem_limit,
        )
        .await?;

        let ctx_secret = <sodoken::BufWriteSized<32>>::new_mem_locked()?;
        sodoken::kdf::derive_from_key(
            ctx_secret.clone(),
            42,
            *b"CtxSecKy",
            pre_secret.clone(),
        )?;

        let sig_secret = <sodoken::BufWriteSized<32>>::new_mem_locked()?;
        sodoken::kdf::derive_from_key(
            sig_secret.clone(),
            142,
            *b"SigSecKy",
            pre_secret,
        )?;

        let context_key = config
            .runtime_secrets_context_key
            .decrypt(ctx_secret.to_read_sized())
            .await?;
        let sign_seed = config
            .runtime_secrets_sign_seed
            .decrypt(sig_secret.to_read_sized())
            .await?;

        let sign_pk = <sodoken::BufWriteSized<32>>::new_no_lock();
        let sign_sk = <sodoken::BufWriteSized<64>>::new_mem_locked()?;
        sodoken::sign::seed_keypair(
            sign_pk.clone(),
            sign_sk.clone(),
            sign_seed.clone(),
        )
        .await?;

        // TODO - double check the sign_pk matches the `?k=Yada` on conUrl

        // check if another connection snuck in and unlocked us already
        if let SrvInnerEnum::Running(_) = &*inner.read() {
            return Ok(());
        }

        if let Some(store_factory) = store_factory {
            let store =
                store_factory.connect_to_store(context_key.clone()).await?;

            let mut lock = inner.write();
            // check if another connection snuck in and unlocked us already
            if let SrvInnerEnum::Running(_) = &*lock {
                return Ok(());
            }
            *lock = SrvInnerEnum::Running(SrvRunningInner {
                config,
                store,
                context_key,
                sign_pk: sign_pk.try_unwrap_sized().unwrap().into(),
                sign_sk: sign_sk.to_read_sized(),
            });
        }
        Ok(())
    }
    .boxed()
}

fn priv_srv_accept(
    inner: Arc<RwLock<SrvInnerEnum>>,
    send: RawSend,
    recv: RawRecv,
) -> BoxFuture<'static, LairResult<()>> {
    async move {
        let (send, recv) =
            crate::sodium_secretstream::new_s3_pair::<LairApiEnum, _, _>(
                send, recv, true,
            )
            .await?;
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

                let msg_id = incoming.msg_id();

                if let Err(e) =
                    priv_dispatch_incoming(inner, send, incoming).await
                {
                    if let Err(e) = send
                        .send(LairApiEnum::ResError(LairApiResError {
                            msg_id,
                            error: e,
                        }))
                        .await
                    {
                        tracing::warn!("error sending error response: {:?}", e);
                    }
                }
            })
            .await;
            panic!("lair listening socket loop ended!");
        });
        Ok(())
    }
    .boxed()
}

fn priv_dispatch_incoming<'a>(
    inner: &'a Arc<RwLock<SrvInnerEnum>>,
    send: &'a crate::sodium_secretstream::S3Sender<LairApiEnum>,
    incoming: LairApiEnum,
) -> impl Future<Output = LairResult<()>> + 'a + Send {
    async move {
        match incoming {
            LairApiEnum::ReqHello(req) => {
                priv_req_hello(inner, send, req).await
            }
            LairApiEnum::ReqUnlock(req) => {
                priv_req_unlock(inner, send, req).await
            }
            LairApiEnum::ReqListEntries(req) => {
                priv_req_list_entries(inner, send, req).await
            }
            LairApiEnum::ReqNewSeed(req) => {
                priv_req_new_seed(inner, send, req).await
            }
            LairApiEnum::ResError(_)
            | LairApiEnum::ResHello(_)
            | LairApiEnum::ResUnlock(_)
            | LairApiEnum::ResListEntries(_)
            | LairApiEnum::ResNewSeed(_) => {
                Err(format!("invalid request: {:?}", incoming).into())
            }
        }
    }
}

fn priv_req_hello<'a>(
    _inner: &'a Arc<RwLock<SrvInnerEnum>>,
    _send: &'a crate::sodium_secretstream::S3Sender<LairApiEnum>,
    _req: LairApiReqHello,
) -> impl Future<Output = LairResult<()>> + 'a + Send {
    async move { unimplemented!() }
}

fn priv_req_unlock<'a>(
    _inner: &'a Arc<RwLock<SrvInnerEnum>>,
    _send: &'a crate::sodium_secretstream::S3Sender<LairApiEnum>,
    _req: LairApiReqUnlock,
) -> impl Future<Output = LairResult<()>> + 'a + Send {
    async move { unimplemented!() }
}

fn priv_req_list_entries<'a>(
    _inner: &'a Arc<RwLock<SrvInnerEnum>>,
    _send: &'a crate::sodium_secretstream::S3Sender<LairApiEnum>,
    _req: LairApiReqListEntries,
) -> impl Future<Output = LairResult<()>> + 'a + Send {
    async move { unimplemented!() }
}

fn priv_req_new_seed<'a>(
    _inner: &'a Arc<RwLock<SrvInnerEnum>>,
    _send: &'a crate::sodium_secretstream::S3Sender<LairApiEnum>,
    _req: LairApiReqNewSeed,
) -> impl Future<Output = LairResult<()>> + 'a + Send {
    async move { unimplemented!() }
}

impl AsLairServer for Srv {
    fn unlock(
        &self,
        passphrase: sodoken::BufRead,
    ) -> BoxFuture<'static, LairResult<()>> {
        priv_srv_unlock(self.0.clone(), passphrase)
    }

    fn accept(
        &self,
        send: RawSend,
        recv: RawRecv,
    ) -> BoxFuture<'static, LairResult<()>> {
        priv_srv_accept(self.0.clone(), send, recv)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_lair_server() {
        let passphrase = sodoken::BufRead::from(&b"passphrase"[..]);

        let config = LairServerConfigInner::new("/tmp", passphrase.clone())
            .await
            .unwrap();
        println!("CONFIG: {}", config);

        let store = crate::mem_store::create_mem_store_factory();

        let srv = spawn_lair_server_task(config, store).await.unwrap();

        srv.unlock(passphrase).await.unwrap();
    }
}
