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
        send: S,
        recv: R,
    ) -> impl Future<Output = LairResult<()>> + 'static + Send
    where
        S: tokio::io::AsyncWrite + 'static + Send + Unpin,
        R: tokio::io::AsyncRead + 'static + Send + Unpin,
    {
        AsLairServer::accept(&*self.0, Box::new(send), Box::new(recv))
    }
}

/// spawn a tokio task managing a lair server with given store factory.
pub fn spawn_lair_server_task<C>(
    config: C,
    server_name: Arc<str>,
    server_version: Arc<str>,
    store_factory: LairStoreFactory,
) -> impl Future<Output = LairResult<LairServer>> + 'static + Send
where
    C: Into<LairServerConfig> + 'static + Send,
{
    async move {
        let inner = SrvPendingInner {
            config: config.into(),
            server_name,
            server_version,
            store_factory,
        };

        let inner = SrvInnerEnum::Pending(inner);
        let inner = Arc::new(RwLock::new(inner));

        Ok(LairServer(Arc::new(Srv(inner))))
    }
}

// -- private -- //

struct SrvPendingInner {
    config: LairServerConfig,
    server_name: Arc<str>,
    server_version: Arc<str>,
    store_factory: LairStoreFactory,
}

struct SrvRunningInner {
    config: LairServerConfig,
    server_name: Arc<str>,
    server_version: Arc<str>,
    store: LairStore,
    // TODO - do we need this??
    #[allow(dead_code)]
    context_key: sodoken::BufReadSized<32>,
    sign_pk: Ed25519PubKey,
    sign_sk: sodoken::BufReadSized<64>,
}

enum SrvInnerEnum {
    Pending(SrvPendingInner),
    Running(SrvRunningInner),
}

struct Srv(Arc<RwLock<SrvInnerEnum>>);

fn priv_srv_unlock(
    inner: Arc<RwLock<SrvInnerEnum>>,
    passphrase: sodoken::BufRead,
) -> BoxFuture<'static, LairResult<()>> {
    let (config, server_name, server_version, store_factory) =
        match &*inner.read() {
            SrvInnerEnum::Running(p) => (
                p.config.clone(),
                p.server_name.clone(),
                p.server_version.clone(),
                None,
            ),
            SrvInnerEnum::Pending(p) => (
                p.config.clone(),
                p.server_name.clone(),
                p.server_version.clone(),
                Some(p.store_factory.clone()),
            ),
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
                server_name,
                server_version,
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

        let enc_ctx_key = <sodoken::BufWriteSized<32>>::new_mem_locked()?;
        sodoken::kdf::derive_from_key(
            enc_ctx_key.clone(),
            42,
            *b"ToCliCxK",
            send.get_enc_ctx_key(),
        )?;
        let enc_ctx_key = enc_ctx_key.to_read_sized();

        let dec_ctx_key = <sodoken::BufWriteSized<32>>::new_mem_locked()?;
        sodoken::kdf::derive_from_key(
            dec_ctx_key.clone(),
            142,
            *b"ToSrvCxK",
            send.get_dec_ctx_key(),
        )?;
        let dec_ctx_key = dec_ctx_key.to_read_sized();

        // even if our core inner state is unlocked, we still need
        // every connection to go through the process, so this is
        // the connection-level unlock state.
        let unlocked = Arc::new(atomic::AtomicBool::new(false));

        tokio::task::spawn(async move {
            let inner = &inner;
            let send = &send;
            let enc_ctx_key = &enc_ctx_key;
            let dec_ctx_key = &dec_ctx_key;
            let unlocked = &unlocked;
            recv.for_each_concurrent(4096, move |incoming| async move {
                //println!("SRV_RECV: {:?}", incoming);

                let incoming = match incoming {
                    Err(e) => {
                        tracing::warn!("incoming channel error: {:?}", e);
                        return;
                    }
                    Ok(incoming) => incoming,
                };

                let msg_id = incoming.msg_id();

                if let Err(e) = priv_dispatch_incoming(
                    inner,
                    send,
                    enc_ctx_key,
                    dec_ctx_key,
                    unlocked,
                    incoming,
                )
                .await
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
            let _ = send.shutdown().await;
            tracing::warn!("lair connection recv loop ended");
        });
        Ok(())
    }
    .boxed()
}

fn priv_dispatch_incoming<'a>(
    inner: &'a Arc<RwLock<SrvInnerEnum>>,
    send: &'a crate::sodium_secretstream::S3Sender<LairApiEnum>,
    _enc_ctx_key: &'a sodoken::BufReadSized<32>,
    dec_ctx_key: &'a sodoken::BufReadSized<32>,
    unlocked: &'a Arc<atomic::AtomicBool>,
    incoming: LairApiEnum,
) -> impl Future<Output = LairResult<()>> + 'a + Send {
    async move {
        match incoming {
            LairApiEnum::ReqHello(req) => {
                priv_req_hello(inner, send, req).await
            }
            LairApiEnum::ReqUnlock(req) => {
                priv_req_unlock(inner, send, dec_ctx_key, unlocked, req).await
            }
            LairApiEnum::ReqListEntries(req) => {
                priv_req_list_entries(inner, send, unlocked, req).await
            }
            LairApiEnum::ReqNewSeed(req) => {
                priv_req_new_seed(inner, send, dec_ctx_key, unlocked, req).await
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
    inner: &'a Arc<RwLock<SrvInnerEnum>>,
    send: &'a crate::sodium_secretstream::S3Sender<LairApiEnum>,
    req: LairApiReqHello,
) -> impl Future<Output = LairResult<()>> + 'a + Send {
    async move {
        // DON'T check connection 'unlocked' here,
        // we want to be able to verify the server,
        // before we unlock the individual connection.

        let (sign_pk, sign_sk, server_name, server_version) =
            match &*inner.read() {
                SrvInnerEnum::Running(p) => (
                    p.sign_pk.clone(),
                    p.sign_sk.clone(),
                    p.server_name.clone(),
                    p.server_version.clone(),
                ),
                SrvInnerEnum::Pending(_) => {
                    return Err("KeystoreLocked".into());
                }
            };

        let hello_sig = sodoken::BufWriteSized::new_no_lock();
        sodoken::sign::detached(
            hello_sig.clone(),
            req.nonce.cloned_inner(),
            sign_sk,
        )
        .await?;
        let hello_sig = hello_sig.try_unwrap_sized().unwrap().into();

        send.send(
            LairApiResHello {
                msg_id: req.msg_id,
                name: server_name,
                version: server_version,
                server_pub_key: sign_pk,
                hello_sig,
            }
            .into_api_enum(),
        )
        .await?;

        Ok(())
    }
}

fn priv_req_unlock<'a>(
    inner: &'a Arc<RwLock<SrvInnerEnum>>,
    send: &'a crate::sodium_secretstream::S3Sender<LairApiEnum>,
    dec_ctx_key: &'a sodoken::BufReadSized<32>,
    unlocked: &'a Arc<atomic::AtomicBool>,
    req: LairApiReqUnlock,
) -> impl Future<Output = LairResult<()>> + 'a + Send {
    async move {
        let passphrase = req.passphrase.decrypt(dec_ctx_key.clone()).await?;

        // performe the internal state-level unlock process
        priv_srv_unlock(inner.clone(), passphrase).await?;

        // if that was successfull, we can also set the connection level
        // unlock state to unlocked
        unlocked.store(true, atomic::Ordering::Relaxed);

        // return the success
        send.send(LairApiResUnlock { msg_id: req.msg_id }.into_api_enum())
            .await?;

        Ok(())
    }
}

fn priv_req_list_entries<'a>(
    inner: &'a Arc<RwLock<SrvInnerEnum>>,
    send: &'a crate::sodium_secretstream::S3Sender<LairApiEnum>,
    unlocked: &'a Arc<atomic::AtomicBool>,
    req: LairApiReqListEntries,
) -> impl Future<Output = LairResult<()>> + 'a + Send {
    async move {
        if !unlocked.load(atomic::Ordering::Relaxed) {
            return Err("KeystoreLocked".into());
        }

        let store = match &*inner.read() {
            SrvInnerEnum::Running(p) => (p.store.clone()),
            SrvInnerEnum::Pending(_) => {
                return Err("KeystoreLocked".into());
            }
        };
        let entry_list = store.list_entries().await?;
        send.send(
            LairApiResListEntries {
                msg_id: req.msg_id,
                entry_list,
            }
            .into_api_enum(),
        )
        .await?;
        Ok(())
    }
}

fn priv_req_new_seed<'a>(
    inner: &'a Arc<RwLock<SrvInnerEnum>>,
    send: &'a crate::sodium_secretstream::S3Sender<LairApiEnum>,
    dec_ctx_key: &'a sodoken::BufReadSized<32>,
    unlocked: &'a Arc<atomic::AtomicBool>,
    req: LairApiReqNewSeed,
) -> impl Future<Output = LairResult<()>> + 'a + Send {
    async move {
        if !unlocked.load(atomic::Ordering::Relaxed) {
            return Err("KeystoreLocked".into());
        }

        let store = match &*inner.read() {
            SrvInnerEnum::Running(p) => (p.store.clone()),
            SrvInnerEnum::Pending(_) => {
                return Err("KeystoreLocked".into());
            }
        };

        let seed_info = match req.deep_lock_passphrase {
            Some(secret) => {
                let deep_lock_passphrase =
                    secret.passphrase.decrypt(dec_ctx_key.clone()).await?;
                store
                    .new_deep_locked_seed(
                        req.tag.clone(),
                        secret.ops_limit,
                        secret.mem_limit,
                        deep_lock_passphrase,
                    )
                    .await?
            }
            None => store.new_seed(req.tag.clone()).await?,
        };

        send.send(
            LairApiResNewSeed {
                msg_id: req.msg_id,
                tag: req.tag.clone(),
                seed_info,
            }
            .into_api_enum(),
        )
        .await?;

        Ok(())
    }
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
