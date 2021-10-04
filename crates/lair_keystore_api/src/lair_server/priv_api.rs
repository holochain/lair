use super::*;

pub(crate) fn priv_req_hello<'a>(
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

        // sign the incoming nonce
        let hello_sig = sodoken::BufWriteSized::new_no_lock();
        sodoken::sign::detached(
            hello_sig.clone(),
            req.nonce.cloned_inner(),
            sign_sk,
        )
        .await?;
        let hello_sig = hello_sig.try_unwrap_sized().unwrap().into();

        // send our hello response
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

pub(crate) fn priv_req_unlock<'a>(
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

pub(crate) fn priv_req_get_entry<'a>(
    inner: &'a Arc<RwLock<SrvInnerEnum>>,
    send: &'a crate::sodium_secretstream::S3Sender<LairApiEnum>,
    unlocked: &'a Arc<atomic::AtomicBool>,
    req: LairApiReqGetEntry,
) -> impl Future<Output = LairResult<()>> + 'a + Send {
    async move {
        if !unlocked.load(atomic::Ordering::Relaxed) {
            return Err("KeystoreLocked".into());
        }

        // get the entry
        let (full_entry, _) =
            priv_get_full_entry_by_tag(inner, req.tag).await?;

        // convert the entry to LairEntryInfo
        let entry_info = match &*full_entry.entry {
            LairEntryInner::Seed { tag, seed_info, .. } => {
                LairEntryInfo::Seed {
                    tag: tag.clone(),
                    seed_info: seed_info.clone(),
                }
            }
            LairEntryInner::DeepLockedSeed { tag, seed_info, .. } => {
                LairEntryInfo::DeepLockedSeed {
                    tag: tag.clone(),
                    seed_info: seed_info.clone(),
                }
            }
            LairEntryInner::WkaTlsCert { tag, cert_info, .. } => {
                LairEntryInfo::WkaTlsCert {
                    tag: tag.clone(),
                    cert_info: cert_info.clone(),
                }
            }
        };

        // send the response
        send.send(
            LairApiResGetEntry {
                msg_id: req.msg_id,
                entry_info,
            }
            .into_api_enum(),
        )
        .await?;

        Ok(())
    }
}

pub(crate) fn priv_req_list_entries<'a>(
    inner: &'a Arc<RwLock<SrvInnerEnum>>,
    send: &'a crate::sodium_secretstream::S3Sender<LairApiEnum>,
    unlocked: &'a Arc<atomic::AtomicBool>,
    req: LairApiReqListEntries,
) -> impl Future<Output = LairResult<()>> + 'a + Send {
    async move {
        let store = priv_get_store(inner, unlocked)?;

        // list entries
        let entry_list = store.list_entries().await?;

        // send the response
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

pub(crate) fn priv_req_new_seed<'a>(
    inner: &'a Arc<RwLock<SrvInnerEnum>>,
    send: &'a crate::sodium_secretstream::S3Sender<LairApiEnum>,
    dec_ctx_key: &'a sodoken::BufReadSized<32>,
    unlocked: &'a Arc<atomic::AtomicBool>,
    req: LairApiReqNewSeed,
) -> impl Future<Output = LairResult<()>> + 'a + Send {
    async move {
        let store = priv_get_store(inner, unlocked)?;

        let seed_info = match req.deep_lock_passphrase {
            Some(secret) => {
                // if deep locked, decrypt the deep lock passphrase
                let deep_lock_passphrase =
                    secret.passphrase.decrypt(dec_ctx_key.clone()).await?;

                // create a new deep locked seed
                store
                    .new_deep_locked_seed(
                        req.tag.clone(),
                        secret.ops_limit,
                        secret.mem_limit,
                        deep_lock_passphrase,
                    )
                    .await?
            }
            // create a new seed
            None => store.new_seed(req.tag.clone()).await?,
        };

        // send the response
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

pub(crate) fn priv_req_sign_by_pub_key<'a>(
    inner: &'a Arc<RwLock<SrvInnerEnum>>,
    send: &'a crate::sodium_secretstream::S3Sender<LairApiEnum>,
    _dec_ctx_key: &'a sodoken::BufReadSized<32>,
    unlocked: &'a Arc<atomic::AtomicBool>,
    req: LairApiReqSignByPubKey,
) -> impl Future<Output = LairResult<()>> + 'a + Send {
    async move {
        if !unlocked.load(atomic::Ordering::Relaxed) {
            return Err("KeystoreLocked".into());
        }

        // get cached full entry
        let (full_entry, _) =
            priv_get_full_entry_by_ed_pub_key(inner, req.pub_key).await?;

        // sign the data
        let signature = if let Some(ed_sk) = full_entry.ed_sk {
            let signature = sodoken::BufWriteSized::new_no_lock();
            sodoken::sign::detached(signature.clone(), req.data, ed_sk).await?;
            signature.try_unwrap_sized().unwrap().into()
        } else {
            return Err("deep_seed signing not yet implemented".into());
        };

        // send the response
        send.send(
            LairApiResSignByPubKey {
                msg_id: req.msg_id,
                signature,
            }
            .into_api_enum(),
        )
        .await?;

        Ok(())
    }
}

pub(crate) fn priv_req_new_wka_tls_cert<'a>(
    inner: &'a Arc<RwLock<SrvInnerEnum>>,
    send: &'a crate::sodium_secretstream::S3Sender<LairApiEnum>,
    unlocked: &'a Arc<atomic::AtomicBool>,
    req: LairApiReqNewWkaTlsCert,
) -> impl Future<Output = LairResult<()>> + 'a + Send {
    async move {
        let store = priv_get_store(inner, unlocked)?;

        // create a e new
        let cert_info = store.new_wka_tls_cert(req.tag.clone()).await?;

        send.send(
            LairApiResNewWkaTlsCert {
                msg_id: req.msg_id,
                tag: req.tag.clone(),
                cert_info,
            }
            .into_api_enum(),
        )
        .await?;

        Ok(())
    }
}

pub(crate) fn priv_gen_and_register_entry<'a>(
    inner: &'a Arc<RwLock<SrvInnerEnum>>,
    store: &'a LairStore,
    entry: LairEntry,
) -> impl Future<Output = LairResult<FullLairEntry>> + 'a + Send {
    async move {
        let (ed_pk, ed_sk, x_pk, x_sk) = match &*entry {
            // only cache non-deep-locked seeds
            LairEntryInner::Seed { seed, .. } => {
                // read the seed
                let seed = seed.decrypt(store.get_bidi_ctx_key()).await?;

                // get the signature keypair
                let ed_pk = sodoken::BufWriteSized::new_no_lock();
                let ed_sk = sodoken::BufWriteSized::new_mem_locked()?;
                sodoken::sign::seed_keypair(
                    ed_pk.clone(),
                    ed_sk.clone(),
                    seed.clone(),
                )
                .await?;

                // get the encryption keypair
                let x_pk = sodoken::BufWriteSized::new_no_lock();
                let x_sk = sodoken::BufWriteSized::new_mem_locked()?;
                sodoken::sealed_box::curve25519xchacha20poly1305::seed_keypair(
                    x_pk.clone(),
                    x_sk.clone(),
                    seed,
                )
                .await?;

                (
                    Some(ed_pk.try_unwrap_sized().unwrap().into()),
                    Some(ed_sk.to_read_sized()),
                    Some(x_pk.try_unwrap_sized().unwrap().into()),
                    Some(x_sk.to_read_sized()),
                )
            }
            _ => (None, None, None, None),
        };

        let full_entry = FullLairEntry { entry, ed_sk, x_sk };

        match &mut *inner.write() {
            SrvInnerEnum::Running(p) => {
                // add full entry to our LRU caches
                p.entries_by_tag
                    .put(full_entry.entry.tag(), full_entry.clone());
                if let Some(ed_pk) = ed_pk {
                    p.entries_by_ed.put(ed_pk, full_entry.clone());
                }
                if let Some(x_pk) = x_pk {
                    p.entries_by_x.put(x_pk, full_entry.clone());
                }
            }
            SrvInnerEnum::Pending(_) => {
                return Err("KeystoreLocked".into());
            }
        }

        Ok(full_entry)
    }
}

#[allow(clippy::needless_lifetimes)] // this helps me define the future bounds
pub(crate) fn priv_get_full_entry_by_tag<'a>(
    inner: &'a Arc<RwLock<SrvInnerEnum>>,
    tag: Arc<str>,
) -> impl Future<Output = LairResult<(FullLairEntry, LairStore)>> + 'a + Send {
    async move {
        let store = match &mut *inner.write() {
            SrvInnerEnum::Running(p) => {
                let store = p.store.clone();
                if let Some(full_entry) = p.entries_by_tag.get(&tag) {
                    return Ok((full_entry.clone(), store));
                }
                store
            }
            SrvInnerEnum::Pending(_) => {
                return Err("KeystoreLocked".into());
            }
        };

        // get the entry
        let entry = store.get_entry_by_tag(tag).await?;

        let full_entry =
            priv_gen_and_register_entry(inner, &store, entry).await?;

        Ok((full_entry, store))
    }
}

#[allow(clippy::needless_lifetimes)] // this helps me define the future bounds
pub(crate) fn priv_get_full_entry_by_ed_pub_key<'a>(
    inner: &'a Arc<RwLock<SrvInnerEnum>>,
    ed_pub_key: Ed25519PubKey,
) -> impl Future<Output = LairResult<(FullLairEntry, LairStore)>> + 'a + Send {
    async move {
        let store = match &mut *inner.write() {
            SrvInnerEnum::Running(p) => {
                let store = p.store.clone();
                if let Some(full_entry) = p.entries_by_ed.get(&ed_pub_key) {
                    return Ok((full_entry.clone(), store));
                }
                store
            }
            SrvInnerEnum::Pending(_) => {
                return Err("KeystoreLocked".into());
            }
        };

        // get the entry
        let entry = store.get_entry_by_ed25519_pub_key(ed_pub_key).await?;

        let full_entry =
            priv_gen_and_register_entry(inner, &store, entry).await?;

        Ok((full_entry, store))
    }
}

pub(crate) fn priv_req_get_wka_tls_cert_priv_key<'a>(
    inner: &'a Arc<RwLock<SrvInnerEnum>>,
    send: &'a crate::sodium_secretstream::S3Sender<LairApiEnum>,
    enc_ctx_key: &'a sodoken::BufReadSized<32>,
    unlocked: &'a Arc<atomic::AtomicBool>,
    req: LairApiReqGetWkaTlsCertPrivKey,
) -> impl Future<Output = LairResult<()>> + 'a + Send {
    async move {
        if !unlocked.load(atomic::Ordering::Relaxed) {
            return Err("KeystoreLocked".into());
        }

        // get the entry
        let (full_entry, store) =
            priv_get_full_entry_by_tag(inner, req.tag).await?;

        // make sure the entry is the correct type
        let priv_key = match &*full_entry.entry {
            LairEntryInner::WkaTlsCert { priv_key, .. } => priv_key.clone(),
            _ => return Err("invalid entry type".into()),
        };

        // decrypt the priv_key using our DB CONTEXT KEY
        let priv_key = priv_key.decrypt(store.get_bidi_ctx_key()).await?;

        // encrypt the priv_key using our CONNECTION CONTEXT KEY
        let priv_key =
            SecretData::encrypt(enc_ctx_key.clone(), priv_key).await?;

        send.send(
            LairApiResGetWkaTlsCertPrivKey {
                msg_id: req.msg_id,
                priv_key,
            }
            .into_api_enum(),
        )
        .await?;

        Ok(())
    }
}
