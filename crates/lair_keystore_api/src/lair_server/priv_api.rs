use super::*;

pub(crate) fn priv_req_hello<'a>(
    inner: &'a Arc<RwLock<SrvInner>>,
    send: &'a crate::sodium_secretstream::S3Sender<LairApiEnum>,
    req: LairApiReqHello,
) -> impl Future<Output = LairResult<()>> + 'a + Send {
    async move {
        // DON'T check connection 'unlocked' here,
        // we want to be able to verify the server,
        // before we unlock the individual connection.

        let (id_pk, server_name, server_version) = {
            let lock = inner.read();
            (
                lock.id_pk.clone(),
                lock.server_name.clone(),
                lock.server_version.clone(),
            )
        };

        let server_pub_key = (*id_pk.read_lock_sized()).into();

        // send our hello response
        send.send(
            LairApiResHello {
                msg_id: req.msg_id,
                name: server_name,
                version: server_version,
                server_pub_key,
            }
            .into_api_enum(),
        )
        .await?;

        Ok(())
    }
}

pub(crate) fn priv_req_unlock<'a>(
    inner: &'a Arc<RwLock<SrvInner>>,
    send: &'a crate::sodium_secretstream::S3Sender<LairApiEnum>,
    dec_ctx_key: &'a sodoken::BufReadSized<32>,
    unlocked: &'a Arc<atomic::AtomicBool>,
    req: LairApiReqUnlock,
) -> impl Future<Output = LairResult<()>> + 'a + Send {
    async move {
        let passphrase = req.passphrase.decrypt(dec_ctx_key.clone()).await?;

        let (config, id_pk) = {
            let lock = inner.read();
            (lock.config.clone(), lock.id_pk.clone())
        };

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

        // derive signature decryption secret
        let id_secret = <sodoken::BufWriteSized<32>>::new_mem_locked()?;
        sodoken::kdf::derive_from_key(
            id_secret.clone(),
            142,
            *b"IdnSecKy",
            pre_secret,
        )?;

        // decrypt the signature seed
        let id_seed = config
            .runtime_secrets_id_seed
            .decrypt(id_secret.to_read_sized())
            .await?;

        // derive the signature keypair from the signature seed
        let d_id_pk = <sodoken::BufWriteSized<32>>::new_no_lock();
        let d_id_sk = <sodoken::BufWriteSized<32>>::new_mem_locked()?;
        use sodoken::crypto_box::curve25519xchacha20poly1305::*;
        seed_keypair(d_id_pk.clone(), d_id_sk, id_seed).await?;

        if *id_pk.read_lock() != *d_id_pk.read_lock() {
            return Err("InvalidPassphrase".into());
        }

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
    inner: &'a Arc<RwLock<SrvInner>>,
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
    inner: &'a Arc<RwLock<SrvInner>>,
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
    inner: &'a Arc<RwLock<SrvInner>>,
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
    inner: &'a Arc<RwLock<SrvInner>>,
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
        let res =
            match priv_get_full_entry_by_ed_pub_key(inner, req.pub_key.clone())
                .await
            {
                Ok((full_entry, _)) => {
                    // sign the data
                    let signature = if let Some(ed_sk) = full_entry.ed_sk {
                        let signature = sodoken::BufWriteSized::new_no_lock();
                        sodoken::sign::detached(
                            signature.clone(),
                            req.data,
                            ed_sk,
                        )
                        .await?;
                        signature.try_unwrap_sized().unwrap().into()
                    } else {
                        return Err(
                            "deep_seed signing not yet implemented".into()
                        );
                    };

                    LairApiResSignByPubKey {
                        msg_id: req.msg_id,
                        signature,
                    }
                }
                Err(e) => {
                    // we don't have this key, let's see if we should invoke
                    // a signature fallback command
                    let fallback_cmd = inner.read().fallback_cmd.clone();
                    if let Some(fallback_cmd) = fallback_cmd {
                        fallback_cmd.sign_by_pub_key(req).await?
                    } else {
                        return Err(e);
                    }
                }
            };

        // send the response
        send.send(res.into_api_enum()).await?;

        Ok(())
    }
}

pub(crate) fn priv_req_new_wka_tls_cert<'a>(
    inner: &'a Arc<RwLock<SrvInner>>,
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
    inner: &'a Arc<RwLock<SrvInner>>,
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
                sodoken::crypto_box::curve25519xchacha20poly1305::seed_keypair(
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

        let mut lock = inner.write();

        // add full entry to our LRU caches
        lock.entries_by_tag
            .put(full_entry.entry.tag(), full_entry.clone());
        if let Some(ed_pk) = ed_pk {
            lock.entries_by_ed.put(ed_pk, full_entry.clone());
        }
        if let Some(x_pk) = x_pk {
            lock.entries_by_x.put(x_pk, full_entry.clone());
        }

        Ok(full_entry)
    }
}

#[allow(clippy::needless_lifetimes)] // this helps me define the future bounds
pub(crate) fn priv_get_full_entry_by_tag<'a>(
    inner: &'a Arc<RwLock<SrvInner>>,
    tag: Arc<str>,
) -> impl Future<Output = LairResult<(FullLairEntry, LairStore)>> + 'a + Send {
    async move {
        let store = {
            let mut lock = inner.write();
            let store = lock.store.clone();
            if let Some(full_entry) = lock.entries_by_tag.get(&tag) {
                return Ok((full_entry.clone(), store));
            }
            store
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
    inner: &'a Arc<RwLock<SrvInner>>,
    ed_pub_key: Ed25519PubKey,
) -> impl Future<Output = LairResult<(FullLairEntry, LairStore)>> + 'a + Send {
    async move {
        let store = {
            let mut lock = inner.write();
            let store = lock.store.clone();
            if let Some(full_entry) = lock.entries_by_ed.get(&ed_pub_key) {
                return Ok((full_entry.clone(), store));
            }
            store
        };

        // get the entry
        let entry = store.get_entry_by_ed25519_pub_key(ed_pub_key).await?;

        let full_entry =
            priv_gen_and_register_entry(inner, &store, entry).await?;

        Ok((full_entry, store))
    }
}

pub(crate) fn priv_req_get_wka_tls_cert_priv_key<'a>(
    inner: &'a Arc<RwLock<SrvInner>>,
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
