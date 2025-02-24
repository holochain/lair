use super::*;
use one_err::OneErr;
use std::sync::Mutex;

/// A [`LairEntry`], including some precomputed values if the entry corresponds to a non-deep-locked seed.
#[derive(Clone)]
pub(crate) struct FullLairEntry {
    /// The entry, containing a seed or cert.
    pub(crate) entry: LairEntry,
    /// Copied from the entry's seed. If false, an error will be produced when attempting to export this seed
    pub(crate) exportable: bool,
    /// If the entry is for a non-deep-locked seed, this is Some clone of it.
    pub(crate) seed: Option<SharedSizedLockedArray<32>>,
    /// If the entry is for a non-deep-locked seed, this is the signing private key derived from the seed
    pub(crate) ed_sk: Option<SharedSizedLockedArray<64>>,
    /// If the entry is for a non-deep-locked seed, this is the decryption private key derived from the seed
    pub(crate) x_sk: Option<SharedSizedLockedArray<32>>,
}

pub(crate) struct SrvInner {
    pub(crate) config: LairServerConfig,
    pub(crate) server_name: Arc<str>,
    pub(crate) server_version: Arc<str>,
    pub(crate) store: LairStore,
    pub(crate) id_pk: Arc<[u8; sodoken::crypto_box::XSALSA_PUBLICKEYBYTES]>,
    pub(crate) id_sk:
        SharedSizedLockedArray<{ sodoken::crypto_box::XSALSA_SECRETKEYBYTES }>,
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
        passphrase: SharedLockedArray,
    ) -> impl Future<Output = LairResult<Self>> + 'static + Send {
        async move {
            // pre-hash the passphrase
            let mut pw_hash = sodoken::SizedLockedArray::<64>::new()?;
            sodoken::blake2b::blake2b_hash(
                &mut *pw_hash.lock(),
                &passphrase.lock().unwrap().lock(),
                None,
            )?;
            let pw_hash = Arc::new(Mutex::new(pw_hash));

            // read salt from config
            let salt = config.runtime_secrets_salt.cloned_inner();

            // read limits from config
            let ops_limit = config.runtime_secrets_ops_limit;
            let mem_limit = config.runtime_secrets_mem_limit;

            // calculate pre_secret from argon2id passphrase hash

            let mut pre_secret =
                tokio::task::spawn_blocking(move || -> LairResult<_> {
                    let mut pre_secret =
                        sodoken::SizedLockedArray::<32>::new()?;

                    sodoken::argon2::blocking_argon2id(
                        &mut *pre_secret.lock(),
                        pw_hash.lock().unwrap().lock().as_slice(),
                        &salt,
                        ops_limit,
                        mem_limit,
                    )?;

                    Ok(pre_secret)
                })
                .await
                .map_err(OneErr::new)??;

            // derive ctx (db) decryption secret
            let mut ctx_secret = sodoken::SizedLockedArray::<32>::new()?;
            sodoken::kdf::derive_from_key(
                &mut *ctx_secret.lock(),
                42,
                b"CtxSecKy",
                &pre_secret.lock(),
            )?;

            // derive signature decryption secret
            let mut id_secret = sodoken::SizedLockedArray::<32>::new()?;
            sodoken::kdf::derive_from_key(
                &mut *id_secret.lock(),
                142,
                b"IdnSecKy",
                &pre_secret.lock(),
            )?;

            // decrypt the context (database) key
            let context_key = config
                .runtime_secrets_context_key
                .decrypt(Arc::new(Mutex::new(ctx_secret)))
                .await?;

            // decrypt the signature seed
            let mut id_seed = config
                .runtime_secrets_id_seed
                .decrypt(Arc::new(Mutex::new(id_secret)))
                .await?;

            // derive the signature keypair from the signature seed
            let mut id_pk = [0; sodoken::crypto_box::XSALSA_PUBLICKEYBYTES];
            let mut id_sk = sodoken::SizedLockedArray::<
                { sodoken::crypto_box::XSALSA_SECRETKEYBYTES },
            >::new()?;
            sodoken::crypto_box::xsalsa_seed_keypair(
                &mut id_pk,
                &mut id_sk.lock(),
                &id_seed.lock(),
            )?;

            // generate a lair_store instance using the database key
            let store = store_factory.connect_to_store(context_key).await?;

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
                id_pk: id_pk.into(),
                id_sk: Arc::new(Mutex::new(id_sk)),
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
            let lock = inner.read().unwrap();
            (lock.id_pk.clone(), lock.id_sk.clone())
        };

        // initialize encryption on the async io channel
        let (send, recv) =
            sodium_secretstream::new_s3_server::<LairApiEnum, _, _>(
                send, recv, id_pk, id_sk,
            )
            .await?;

        // derive our encryption (to client) secret
        let send_enc_ctx_key = send.get_enc_ctx_key();
        let mut enc_ctx_key = sodoken::SizedLockedArray::<32>::new()?;
        sodoken::kdf::derive_from_key(
            &mut *enc_ctx_key.lock(),
            42,
            b"ToCliCxK",
            &send_enc_ctx_key.lock().unwrap().lock(),
        )?;

        // derive our decryption (from client) secret
        let send_dec_ctx_key = send.get_dec_ctx_key();
        let mut dec_ctx_key = sodoken::SizedLockedArray::<32>::new()?;
        sodoken::kdf::derive_from_key(
            &mut *dec_ctx_key.lock(),
            142,
            b"ToSrvCxK",
            &send_dec_ctx_key.lock().unwrap().lock(),
        )?;

        // even if our core inner state is unlocked, we still need
        // every connection to go through the process, so this is
        // the connection-level unlock state.
        let unlocked = Arc::new(atomic::AtomicBool::new(false));

        // spawn a task for reading incoming messages from the client
        tokio::task::spawn(async move {
            let inner = &inner;
            let send = &send;
            let enc_ctx_key = Arc::new(Mutex::new(enc_ctx_key));
            let dec_ctx_key = Arc::new(Mutex::new(dec_ctx_key));
            let unlocked = &unlocked;
            recv.for_each_concurrent(4096, move |incoming| {
                let enc_ctx_key = enc_ctx_key.clone();
                let dec_ctx_key = dec_ctx_key.clone();
                async move {
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
                            tracing::warn!(
                                "error sending error response: {:?}",
                                e
                            );
                        }
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
    send: &'a sodium_secretstream::S3Sender<LairApiEnum>,
    enc_ctx_key: SharedSizedLockedArray<32>,
    dec_ctx_key: SharedSizedLockedArray<32>,
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
            LairApiEnum::ReqDeriveSeed(req) => {
                priv_req_derive_seed(inner, send, dec_ctx_key, unlocked, req)
                    .await
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
            LairApiEnum::ReqCryptoBoxXSalsaBySignPubKey(req) => {
                priv_req_crypto_box_xsalsa_by_sign_pub_key(
                    inner, send, unlocked, req,
                )
                .await
            }
            LairApiEnum::ReqCryptoBoxXSalsaOpenBySignPubKey(req) => {
                priv_req_crypto_box_xsalsa_open_by_sign_pub_key(
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
            | LairApiEnum::ResDeriveSeed(_)
            | LairApiEnum::ResSignByPubKey(_)
            | LairApiEnum::ResCryptoBoxXSalsaByPubKey(_)
            | LairApiEnum::ResCryptoBoxXSalsaOpenByPubKey(_)
            | LairApiEnum::ResCryptoBoxXSalsaBySignPubKey(_)
            | LairApiEnum::ResCryptoBoxXSalsaOpenBySignPubKey(_)
            | LairApiEnum::ResNewWkaTlsCert(_)
            | LairApiEnum::ResGetWkaTlsCertPrivKey(_)
            | LairApiEnum::ResSecretBoxXSalsaByTag(_)
            | LairApiEnum::ResSecretBoxXSalsaOpenByTag(_) => {
                Err(format!("invalid request: {incoming:?}").into())
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

    Ok(inner.read().unwrap().store.clone())
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
        let store = self.0.read().unwrap().store.clone();
        async move { Ok(store) }.boxed()
    }
}
