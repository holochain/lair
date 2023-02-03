use super::*;

/// A [`LairEntry`], including some precomputed values if the entry corresponds to a non-deep-locked seed.
#[derive(Clone)]
pub(crate) struct FullLairEntry {
    /// The entry, containing a seed or cert.
    pub(crate) entry: LairEntry,
    /// Copied from the entry's seed. If false, an error will be produced when attempting to export this seed
    pub(crate) exportable: bool,
    /// If the entry is for a non-deep-locked seed, this is Some clone of it.
    pub(crate) seed: Option<sodoken::BufReadSized<32>>,
    /// If the entry is for a non-deep-locked seed, this is the signing private key derived from the seed
    pub(crate) ed_sk: Option<sodoken::BufReadSized<64>>,
    /// If the entry is for a non-deep-locked seed, this is the decryption private key derived from the seed
    pub(crate) x_sk: Option<sodoken::BufReadSized<32>>,
}

pub(crate) struct SrvInner {
    pub(crate) config: LairServerConfig,
    pub(crate) server_name: Arc<str>,
    pub(crate) server_version: Arc<str>,
    pub(crate) store: LairStore,
    pub(crate) id_pk: sodoken::BufReadSized<32>,
    pub(crate) id_sk: sodoken::BufReadSized<32>,
    pub(crate) entries_by_tag: lru::LruCache<Arc<str>, FullLairEntry>,
    pub(crate) entries_by_ed: lru::LruCache<Ed25519PubKey, FullLairEntry>,
    #[allow(dead_code)]
    pub(crate) entries_by_x: lru::LruCache<X25519PubKey, FullLairEntry>,
    pub(crate) fallback_cmd: Option<FallbackCmd>,
}

pub(crate) struct Srv(pub(crate) Arc<RwLock<SrvInner>>);

impl Srv {
    pub(crate) fn new(
        config: LairServerConfig,
        server_name: Arc<str>,
        server_version: Arc<str>,
        store_factory: LairStoreFactory,
        passphrase: sodoken::BufRead,
    ) -> impl Future<Output = LairResult<Self>> + 'static + Send {
        async move {
            // pre-hash the passphrase
            let pw_hash = <sodoken::BufWriteSized<64>>::new_mem_locked()?;
            sodoken::hash::blake2b::hash(pw_hash.clone(), passphrase).await?;

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
                pw_hash,
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
            let id_secret = <sodoken::BufWriteSized<32>>::new_mem_locked()?;
            sodoken::kdf::derive_from_key(
                id_secret.clone(),
                142,
                *b"IdnSecKy",
                pre_secret,
            )?;

            // decrypt the context (database) key
            let context_key = config
                .runtime_secrets_context_key
                .decrypt(ctx_secret.to_read_sized())
                .await?;

            // decrypt the signature seed
            let id_seed = config
                .runtime_secrets_id_seed
                .decrypt(id_secret.to_read_sized())
                .await?;

            // derive the signature keypair from the signature seed
            let id_pk = <sodoken::BufWriteSized<32>>::new_no_lock();
            let id_sk = <sodoken::BufWriteSized<32>>::new_mem_locked()?;
            use sodoken::crypto_box::curve25519xchacha20poly1305::*;
            seed_keypair(id_pk.clone(), id_sk.clone(), id_seed.clone()).await?;

            // generate a lair_store instance using the database key
            let store =
                store_factory.connect_to_store(context_key.clone()).await?;

            // if a fallback signer is specified, launch it
            let fallback_cmd = match &config.signature_fallback {
                LairServerSignatureFallback::Command { .. } => {
                    Some(FallbackCmd::new(&config).await?)
                }
                _ => None,
            };

            Ok(Self(Arc::new(RwLock::new(SrvInner {
                config,
                server_name,
                server_version,
                store,
                id_pk: id_pk.try_unwrap_sized().unwrap().into(),
                id_sk: id_sk.to_read_sized(),
                // worst case, if all these caches evict different entries
                // we could end up storing 384 entries at once...
                // the entries themselves are Arc<>'s so putting them
                // in multiple caches doesn't increase memory overhead much.
                entries_by_tag: lru::LruCache::new(
                    std::num::NonZeroUsize::new(128).unwrap(),
                ),
                entries_by_ed: lru::LruCache::new(
                    std::num::NonZeroUsize::new(128).unwrap(),
                ),
                entries_by_x: lru::LruCache::new(
                    std::num::NonZeroUsize::new(128).unwrap(),
                ),
                fallback_cmd,
            }))))
        }
    }
}

pub(crate) fn priv_srv_accept(
    inner: Arc<RwLock<SrvInner>>,
    send: RawSend,
    recv: RawRecv,
) -> BoxFuture<'static, LairResult<()>> {
    async move {
        let (id_pk, id_sk) = {
            let lock = inner.read();
            (lock.id_pk.clone(), lock.id_sk.clone())
        };

        // initialize encryption on the async io channel
        let (send, recv) =
            crate::sodium_secretstream::new_s3_server::<LairApiEnum, _, _>(
                send, recv, id_pk, id_sk,
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
    inner: &'a Arc<RwLock<SrvInner>>,
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
            LairApiEnum::ReqExportSeedByTag(req) => {
                priv_req_export_seed_by_tag(inner, send, unlocked, req).await
            }
            LairApiEnum::ReqImportSeed(req) => {
                priv_req_import_seed(inner, send, dec_ctx_key, unlocked, req)
                    .await
            }
            LairApiEnum::ReqSignByPubKey(req) => {
                priv_req_sign_by_pub_key(inner, send, dec_ctx_key, unlocked, req).await
            }
            LairApiEnum::ReqCryptoBoxXSalsaByPubKey(req) => {
                priv_req_crypto_box_xsalsa_by_pub_key(
                    inner, send, unlocked, req,
                )
                .await
            }
            LairApiEnum::ReqCryptoBoxXSalsaOpenByPubKey(req) => {
                priv_req_crypto_box_xsalsa_open_by_pub_key(
                    inner, send, unlocked, req,
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
            LairApiEnum::ReqSecretBoxXSalsaByTag(req) => {
                priv_req_secret_box_xsalsa_by_tag(inner, send, unlocked, req)
                    .await
            }
            LairApiEnum::ReqSecretBoxXSalsaOpenByTag(req) => {
                priv_req_secret_box_xsalsa_open_by_tag(
                    inner, send, unlocked, req,
                )
                .await
            }
            LairApiEnum::ResError(_)
            | LairApiEnum::ResHello(_)
            | LairApiEnum::ResUnlock(_)
            | LairApiEnum::ResGetEntry(_)
            | LairApiEnum::ResListEntries(_)
            | LairApiEnum::ResNewSeed(_)
            | LairApiEnum::ResExportSeedByTag(_)
            | LairApiEnum::ResImportSeed(_)
            | LairApiEnum::ResSignByPubKey(_)
            | LairApiEnum::ResCryptoBoxXSalsaByPubKey(_)
            | LairApiEnum::ResCryptoBoxXSalsaOpenByPubKey(_)
            | LairApiEnum::ResNewWkaTlsCert(_)
            | LairApiEnum::ResGetWkaTlsCertPrivKey(_)
            | LairApiEnum::ResSecretBoxXSalsaByTag(_)
            | LairApiEnum::ResSecretBoxXSalsaOpenByTag(_) => {
                Err(format!("invalid request: {:?}", incoming).into())
            }
        }
    }
}

pub(crate) fn priv_get_store(
    inner: &Arc<RwLock<SrvInner>>,
    unlocked: &Arc<atomic::AtomicBool>,
) -> LairResult<LairStore> {
    if !unlocked.load(atomic::Ordering::Relaxed) {
        return Err("KeystoreLocked".into());
    }

    Ok(inner.read().store.clone())
}

impl AsLairServer for Srv {
    fn accept(
        &self,
        send: RawSend,
        recv: RawRecv,
    ) -> BoxFuture<'static, LairResult<()>> {
        priv_srv_accept(self.0.clone(), send, recv)
    }

    fn store(&self) -> BoxFuture<'static, LairResult<LairStore>> {
        let store = self.0.read().store.clone();
        async move { Ok(store) }.boxed()
    }
}
