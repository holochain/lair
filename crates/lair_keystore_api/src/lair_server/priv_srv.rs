use super::*;

pub(crate) struct SrvPendingInner {
    pub(crate) config: LairServerConfig,
    pub(crate) server_name: Arc<str>,
    pub(crate) server_version: Arc<str>,
    pub(crate) store_factory: LairStoreFactory,
}

#[derive(Clone)]
pub(crate) struct FullLairEntry {
    pub(crate) entry: LairEntry,
    pub(crate) ed_sk: Option<sodoken::BufReadSized<64>>,
    pub(crate) x_sk: Option<sodoken::BufReadSized<32>>,
}

pub(crate) struct SrvRunningInner {
    pub(crate) config: LairServerConfig,
    pub(crate) server_name: Arc<str>,
    pub(crate) server_version: Arc<str>,
    pub(crate) store: LairStore,
    pub(crate) sign_pk: Ed25519PubKey,
    pub(crate) sign_sk: sodoken::BufReadSized<64>,
    pub(crate) entries_by_tag: lru::LruCache<Arc<str>, FullLairEntry>,
    pub(crate) entries_by_ed: lru::LruCache<Ed25519PubKey, FullLairEntry>,
    #[allow(dead_code)]
    pub(crate) entries_by_x: lru::LruCache<X25519PubKey, FullLairEntry>,
}

pub(crate) enum SrvInnerEnum {
    Pending(Box<SrvPendingInner>),
    Running(Box<SrvRunningInner>),
}

pub(crate) struct Srv(pub(crate) Arc<RwLock<SrvInnerEnum>>);

pub(crate) fn priv_srv_unlock(
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
        // read salt from config
        let salt = sodoken::BufReadSized::from(
            config.runtime_secrets_salt.cloned_inner(),
        );

        // read limits from config
        let ops_limit = config.runtime_secrets_ops_limit;
        let mem_limit = config.runtime_secrets_mem_limit;

        // calculate pre_secret from argon2id passphrase hash
        let pre_secret = <sodoken::BufWriteSized<32>>::new_mem_locked()?;
        sodoken::hash::argon2id::hash(
            pre_secret.clone(),
            passphrase,
            salt,
            ops_limit,
            mem_limit,
        )
        .await?;

        // derive ctx (db) decryption secret
        let ctx_secret = <sodoken::BufWriteSized<32>>::new_mem_locked()?;
        sodoken::kdf::derive_from_key(
            ctx_secret.clone(),
            42,
            *b"CtxSecKy",
            pre_secret.clone(),
        )?;

        // derive signature decryption secret
        let sig_secret = <sodoken::BufWriteSized<32>>::new_mem_locked()?;
        sodoken::kdf::derive_from_key(
            sig_secret.clone(),
            142,
            *b"SigSecKy",
            pre_secret,
        )?;

        // decrypt the context (database) key
        let context_key = config
            .runtime_secrets_context_key
            .decrypt(ctx_secret.to_read_sized())
            .await?;

        // decrypt the signature seed
        let sign_seed = config
            .runtime_secrets_sign_seed
            .decrypt(sig_secret.to_read_sized())
            .await?;

        // derive the signature keypair from the signature seed
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
            // generate a lair_store instance using the database key
            let store =
                store_factory.connect_to_store(context_key.clone()).await?;

            let mut lock = inner.write();

            // check if another connection snuck in and unlocked us already
            if let SrvInnerEnum::Running(_) = &*lock {
                return Ok(());
            }

            // otherwise, we can initialize ourselves as running
            *lock = SrvInnerEnum::Running(Box::new(SrvRunningInner {
                config,
                server_name,
                server_version,
                store,
                sign_pk: sign_pk.try_unwrap_sized().unwrap().into(),
                sign_sk: sign_sk.to_read_sized(),
                // worst case, if all these caches evict different entries
                // we could end up storing 384 entries at once...
                // the entries themselves are Arc<>'s so putting them
                // in multiple caches doesn't increase memory overhead much.
                entries_by_tag: lru::LruCache::new(128),
                entries_by_ed: lru::LruCache::new(128),
                entries_by_x: lru::LruCache::new(128),
            }));
        }

        Ok(())
    }
    .boxed()
}

pub(crate) fn priv_srv_accept(
    inner: Arc<RwLock<SrvInnerEnum>>,
    send: RawSend,
    recv: RawRecv,
) -> BoxFuture<'static, LairResult<()>> {
    async move {
        // initialize encryption on the async io channel
        let (send, recv) =
            crate::sodium_secretstream::new_s3_pair::<LairApiEnum, _, _>(
                send, recv, true,
            )
            .await?;

        // derive our encryption (to client) secret
        let enc_ctx_key = <sodoken::BufWriteSized<32>>::new_mem_locked()?;
        sodoken::kdf::derive_from_key(
            enc_ctx_key.clone(),
            42,
            *b"ToCliCxK",
            send.get_enc_ctx_key(),
        )?;
        let enc_ctx_key = enc_ctx_key.to_read_sized();

        // derive our decryption (from client) secret
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

        // spawn a task for reading incoming messages from the client
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

                // dispatch the message to the appropriate api handler
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
                    // if we get an error - send the error back to the client
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

            // when our loop ends, shutdown the sending side too
            let _ = send.shutdown().await;

            tracing::warn!("lair connection recv loop ended");
        });

        Ok(())
    }
    .boxed()
}

pub(crate) fn priv_dispatch_incoming<'a>(
    inner: &'a Arc<RwLock<SrvInnerEnum>>,
    send: &'a crate::sodium_secretstream::S3Sender<LairApiEnum>,
    enc_ctx_key: &'a sodoken::BufReadSized<32>,
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
            LairApiEnum::ReqGetEntry(req) => {
                priv_req_get_entry(inner, send, unlocked, req).await
            }
            LairApiEnum::ReqListEntries(req) => {
                priv_req_list_entries(inner, send, unlocked, req).await
            }
            LairApiEnum::ReqNewSeed(req) => {
                priv_req_new_seed(inner, send, dec_ctx_key, unlocked, req).await
            }
            LairApiEnum::ReqSignByPubKey(req) => {
                priv_req_sign_by_pub_key(
                    inner,
                    send,
                    dec_ctx_key,
                    unlocked,
                    req,
                )
                .await
            }
            LairApiEnum::ReqNewWkaTlsCert(req) => {
                priv_req_new_wka_tls_cert(inner, send, unlocked, req).await
            }
            LairApiEnum::ReqGetWkaTlsCertPrivKey(req) => {
                priv_req_get_wka_tls_cert_priv_key(
                    inner,
                    send,
                    enc_ctx_key,
                    unlocked,
                    req,
                )
                .await
            }
            LairApiEnum::ResError(_)
            | LairApiEnum::ResHello(_)
            | LairApiEnum::ResUnlock(_)
            | LairApiEnum::ResGetEntry(_)
            | LairApiEnum::ResListEntries(_)
            | LairApiEnum::ResNewSeed(_)
            | LairApiEnum::ResSignByPubKey(_)
            | LairApiEnum::ResNewWkaTlsCert(_)
            | LairApiEnum::ResGetWkaTlsCertPrivKey(_) => {
                Err(format!("invalid request: {:?}", incoming).into())
            }
        }
    }
}

pub(crate) fn priv_get_store(
    inner: &Arc<RwLock<SrvInnerEnum>>,
    unlocked: &Arc<atomic::AtomicBool>,
) -> LairResult<LairStore> {
    if !unlocked.load(atomic::Ordering::Relaxed) {
        return Err("KeystoreLocked".into());
    }

    let store = match &*inner.read() {
        SrvInnerEnum::Running(p) => (p.store.clone()),
        SrvInnerEnum::Pending(_) => {
            return Err("KeystoreLocked".into());
        }
    };

    Ok(store)
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

    fn store(&self) -> BoxFuture<'static, LairResult<LairStore>> {
        let store = match &*self.0.read() {
            SrvInnerEnum::Running(p) => p.store.clone(),
            SrvInnerEnum::Pending(_) => {
                return async move { Err("server locked, no store".into()) }
                    .boxed();
            }
        };
        async move { Ok(store) }.boxed()
    }
}
