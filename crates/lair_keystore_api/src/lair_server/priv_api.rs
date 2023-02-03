use hc_seed_bundle::dependencies::sodoken::BufReadSized;

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
                        req.exportable,
                    )
                    .await?
            }
            // create a new seed
            None => store.new_seed(req.tag.clone(), req.exportable).await?,
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

pub(crate) fn priv_req_export_seed_by_tag<'a>(
    inner: &'a Arc<RwLock<SrvInner>>,
    send: &'a crate::sodium_secretstream::S3Sender<LairApiEnum>,
    unlocked: &'a Arc<atomic::AtomicBool>,
    req: LairApiReqExportSeedByTag,
) -> impl Future<Output = LairResult<()>> + 'a + Send {
    async move {
        if !unlocked.load(atomic::Ordering::Relaxed) {
            return Err("KeystoreLocked".into());
        }

        // get cached full entry
        let (seed_entry, _) =
            priv_get_full_entry_by_tag(inner, req.tag.clone()).await?;

        // get cached full entry
        let (enc_entry, _) =
            priv_get_full_entry_by_x_pub_key(inner, req.sender_pub_key.clone())
                .await?;

        let nonce = sodoken::BufWriteSized::new_no_lock();
        sodoken::random::bytes_buf(nonce.clone()).await?;

        use sodoken::crypto_box::curve25519xsalsa20poly1305::*;
        let cipher = if let Some(x_sk) = enc_entry.x_sk {
            if let Some(seed) = seed_entry.seed {
                if !seed_entry.exportable {
                    return Err("seed is not exportable".into());
                }

                easy(
                    nonce.clone(),
                    seed,
                    req.recipient_pub_key.cloned_inner(),
                    x_sk,
                )
                .await?
            } else {
                return Err("deep_seed crypto_box not yet implemented".into());
            }
        } else {
            return Err("deep_seed crypto_box not yet implemented".into());
        };

        send.send(
            LairApiResExportSeedByTag {
                msg_id: req.msg_id,
                nonce: nonce.try_unwrap_sized().unwrap(),
                cipher: cipher.try_unwrap().unwrap().into(),
            }
            .into_api_enum(),
        )
        .await?;

        Ok(())
    }
}

pub(crate) fn priv_req_import_seed<'a>(
    inner: &'a Arc<RwLock<SrvInner>>,
    send: &'a crate::sodium_secretstream::S3Sender<LairApiEnum>,
    dec_ctx_key: &'a sodoken::BufReadSized<32>,
    unlocked: &'a Arc<atomic::AtomicBool>,
    req: LairApiReqImportSeed,
) -> impl Future<Output = LairResult<()>> + 'a + Send {
    async move {
        let store = priv_get_store(inner, unlocked)?;

        if !unlocked.load(atomic::Ordering::Relaxed) {
            return Err("KeystoreLocked".into());
        }

        // get cached full entry
        let (full_entry, _) = priv_get_full_entry_by_x_pub_key(
            inner,
            req.recipient_pub_key.clone(),
        )
        .await?;

        use sodoken::crypto_box::curve25519xsalsa20poly1305::*;

        if req.cipher.len() != 32 + MACBYTES {
            return Err("Bad Seed Length".into());
        }

        let seed = sodoken::BufWriteSized::new_mem_locked()?;

        if let Some(x_sk) = full_entry.x_sk {
            open_easy(
                req.nonce,
                seed.clone(),
                req.cipher,
                req.sender_pub_key.cloned_inner(),
                x_sk,
            )
            .await?;
        } else {
            return Err("deep_seed crypto_box not yet implemented".into());
        }

        let seed = seed.to_read_sized();

        let seed_info = match req.deep_lock_passphrase {
            Some(secret) => {
                // if deep locked, decrypt the deep lock passphrase
                let deep_lock_passphrase =
                    secret.passphrase.decrypt(dec_ctx_key.clone()).await?;

                // create a new deep locked seed
                store
                    .insert_deep_locked_seed(
                        seed,
                        req.tag.clone(),
                        secret.ops_limit,
                        secret.mem_limit,
                        deep_lock_passphrase,
                        req.exportable,
                    )
                    .await?
            }
            // create a new seed
            None => {
                store
                    .insert_seed(seed, req.tag.clone(), req.exportable)
                    .await?
            }
        };

        send.send(
            LairApiResImportSeed {
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
    dec_ctx_key: &'a sodoken::BufReadSized<32>,
    unlocked: &'a Arc<atomic::AtomicBool>,
    req: LairApiReqSignByPubKey,
) -> impl Future<Output = LairResult<()>> + 'a + Send {
    async move {
        if !unlocked.load(atomic::Ordering::Relaxed) {
            return Err("KeystoreLocked".into());
        }

        // get cached full entry
        let res = match priv_get_full_entry_by_ed_pub_key(
            inner,
            req.pub_key.clone(),
        )
        .await
        {
            Ok((full_entry, _)) => {
                let signature = sodoken::BufWriteSized::new_no_lock();

                // get the signing private key
                let ed_sk = match (&*full_entry.entry, full_entry.ed_sk, req.deep_lock_passphrase) {
                    (LairEntryInner::Seed { .. }, Some(ed_sk), _) => { ed_sk }
                    (
                        LairEntryInner::DeepLockedSeed {
                            tag: _,
                            seed_info: _,
                            salt,
                            ops_limit,
                            mem_limit,
                            seed,
                        },
                        _,
                        Some(passphrase)
                    ) => {
                        // generate the deep lock key from the passphrase
                        let passphrase = passphrase.decrypt(dec_ctx_key.clone()).await?;

                        let deep_key = <sodoken::BufWriteSized<32>>::new_mem_locked()?;
                        sodoken::hash::argon2id::hash(
                            deep_key.clone(),
                            passphrase,
                            BufReadSized::from(salt.clone().cloned_inner()),
                            *ops_limit,
                            *mem_limit,
                        )
                        .await?;
                        let seed = seed.decrypt(deep_key.into()).await?;
                        let (_, ed_sk) = derive_ed(&seed).await?;
                        ed_sk
                    }
                    _ => return Err("The entry for this key is not a seed which can produce a signature".into())
                };

                sodoken::sign::detached(signature.clone(), req.data, ed_sk)
                    .await?;
                let signature = signature.try_unwrap_sized().unwrap().into();

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

pub(crate) fn priv_req_crypto_box_xsalsa_by_pub_key<'a>(
    inner: &'a Arc<RwLock<SrvInner>>,
    send: &'a crate::sodium_secretstream::S3Sender<LairApiEnum>,
    unlocked: &'a Arc<atomic::AtomicBool>,
    req: LairApiReqCryptoBoxXSalsaByPubKey,
) -> impl Future<Output = LairResult<()>> + 'a + Send {
    async move {
        if !unlocked.load(atomic::Ordering::Relaxed) {
            return Err("KeystoreLocked".into());
        }

        // get cached full entry
        let (full_entry, _) =
            priv_get_full_entry_by_x_pub_key(inner, req.sender_pub_key.clone())
                .await?;

        let nonce = sodoken::BufWriteSized::new_no_lock();
        sodoken::random::bytes_buf(nonce.clone()).await?;

        use sodoken::crypto_box::curve25519xsalsa20poly1305::*;
        let cipher = if let Some(x_sk) = full_entry.x_sk {
            easy(
                nonce.clone(),
                req.data,
                req.recipient_pub_key.cloned_inner(),
                x_sk,
            )
            .await?
        } else {
            return Err("deep_seed crypto_box not yet implemented".into());
        };

        send.send(
            LairApiResCryptoBoxXSalsaByPubKey {
                msg_id: req.msg_id,
                nonce: nonce.try_unwrap_sized().unwrap(),
                cipher: cipher.try_unwrap().unwrap().into(),
            }
            .into_api_enum(),
        )
        .await?;

        Ok(())
    }
}

pub(crate) fn priv_req_crypto_box_xsalsa_open_by_pub_key<'a>(
    inner: &'a Arc<RwLock<SrvInner>>,
    send: &'a crate::sodium_secretstream::S3Sender<LairApiEnum>,
    unlocked: &'a Arc<atomic::AtomicBool>,
    req: LairApiReqCryptoBoxXSalsaOpenByPubKey,
) -> impl Future<Output = LairResult<()>> + 'a + Send {
    async move {
        if !unlocked.load(atomic::Ordering::Relaxed) {
            return Err("KeystoreLocked".into());
        }

        // get cached full entry
        let (full_entry, _) = priv_get_full_entry_by_x_pub_key(
            inner,
            req.recipient_pub_key.clone(),
        )
        .await?;

        use sodoken::crypto_box::curve25519xsalsa20poly1305::*;

        if req.cipher.len() < MACBYTES {
            return Err("InvalidCipherLength".into());
        }

        let message =
            sodoken::BufWrite::new_no_lock(req.cipher.len() - MACBYTES);

        if let Some(x_sk) = full_entry.x_sk {
            open_easy(
                req.nonce,
                message.clone(),
                req.cipher,
                req.sender_pub_key.cloned_inner(),
                x_sk,
            )
            .await?;
        } else {
            return Err("deep_seed crypto_box not yet implemented".into());
        }

        send.send(
            LairApiResCryptoBoxXSalsaOpenByPubKey {
                msg_id: req.msg_id,
                message: message.try_unwrap().unwrap().into(),
            }
            .into_api_enum(),
        )
        .await?;

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

pub(crate) async fn derive_ed(
    seed: &BufReadSized<32>,
) -> LairResult<(Ed25519PubKey, BufReadSized<64>)> {
    // get the signature keypair
    let ed_pk = sodoken::BufWriteSized::new_no_lock();
    let ed_sk = sodoken::BufWriteSized::new_mem_locked()?;
    sodoken::sign::seed_keypair(ed_pk.clone(), ed_sk.clone(), seed.clone())
        .await?;

    let ed_pk: Ed25519PubKey = ed_pk.try_unwrap_sized().unwrap().into();
    let ed_sk = ed_sk.to_read_sized();

    Ok((ed_pk, ed_sk))
}

pub(crate) async fn derive_x(
    seed: &BufReadSized<32>,
) -> LairResult<(X25519PubKey, BufReadSized<32>)> {
    // get the encryption keypair
    let x_pk = sodoken::BufWriteSized::new_no_lock();
    let x_sk = sodoken::BufWriteSized::new_mem_locked()?;
    sodoken::crypto_box::curve25519xchacha20poly1305::seed_keypair(
        x_pk.clone(),
        x_sk.clone(),
        seed.clone(),
    )
    .await?;

    let x_pk: X25519PubKey = x_pk.try_unwrap_sized().unwrap().into();
    let x_sk = x_sk.to_read_sized();

    Ok((x_pk, x_sk))
}

pub(crate) fn priv_gen_and_register_entry<'a>(
    inner: &'a Arc<RwLock<SrvInner>>,
    store: &'a LairStore,
    entry: LairEntry,
) -> impl Future<Output = LairResult<FullLairEntry>> + 'a + Send {
    async move {
        let (seed, exportable, ed_pk, ed_sk, x_pk, x_sk) = match &*entry {
            // only cache non-deep-locked seeds
            LairEntryInner::Seed {
                seed_info, seed, ..
            } => {
                // read the seed
                let seed = seed.decrypt(store.get_bidi_ctx_key()).await?;
                let (ed_pk, ed_sk) = derive_ed(&seed).await?;
                let (x_pk, x_sk) = derive_x(&seed).await?;

                if ed_pk != seed_info.ed25519_pub_key {
                    return Err(
                        "Ed25519 pub key generated from seed does not match"
                            .into(),
                    );
                }
                if x_pk != seed_info.x25519_pub_key {
                    return Err(
                        "X25519 pub key generated from seed does not match"
                            .into(),
                    );
                }
                (
                    Some(seed),
                    seed_info.exportable,
                    Some(seed_info.ed25519_pub_key.clone()),
                    Some(ed_sk),
                    Some(seed_info.x25519_pub_key.clone()),
                    Some(x_sk),
                )
            }
            _ => (None, false, None, None, None, None),
        };

        let full_entry = FullLairEntry {
            seed,
            exportable,
            entry,
            ed_sk,
            x_sk,
        };

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

#[allow(clippy::needless_lifetimes)] // this helps me define the future bounds
pub(crate) fn priv_get_full_entry_by_x_pub_key<'a>(
    inner: &'a Arc<RwLock<SrvInner>>,
    x_pub_key: X25519PubKey,
) -> impl Future<Output = LairResult<(FullLairEntry, LairStore)>> + 'a + Send {
    async move {
        let store = {
            let mut lock = inner.write();
            let store = lock.store.clone();
            if let Some(full_entry) = lock.entries_by_x.get(&x_pub_key) {
                return Ok((full_entry.clone(), store));
            }
            store
        };

        // get the entry
        let entry = store.get_entry_by_x25519_pub_key(x_pub_key).await?;

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

pub(crate) fn priv_req_secret_box_xsalsa_by_tag<'a>(
    inner: &'a Arc<RwLock<SrvInner>>,
    send: &'a crate::sodium_secretstream::S3Sender<LairApiEnum>,
    unlocked: &'a Arc<atomic::AtomicBool>,
    req: LairApiReqSecretBoxXSalsaByTag,
) -> impl Future<Output = LairResult<()>> + 'a + Send {
    async move {
        if !unlocked.load(atomic::Ordering::Relaxed) {
            return Err("KeystoreLocked".into());
        }

        // get cached full entry
        let (full_entry, _) =
            priv_get_full_entry_by_tag(inner, req.tag.clone()).await?;

        let nonce = sodoken::BufWriteSized::new_no_lock();
        sodoken::random::bytes_buf(nonce.clone()).await?;

        use sodoken::secretbox::xsalsa20poly1305::*;
        let cipher = if let Some(seed) = full_entry.seed {
            easy(nonce.clone(), req.data, seed).await?
        } else {
            return Err("deep_seed secretbox not yet implemented".into());
        };

        send.send(
            LairApiResSecretBoxXSalsaByTag {
                msg_id: req.msg_id,
                nonce: nonce.try_unwrap_sized().unwrap(),
                cipher: cipher.try_unwrap().unwrap().into(),
            }
            .into_api_enum(),
        )
        .await?;

        Ok(())
    }
}

pub(crate) fn priv_req_secret_box_xsalsa_open_by_tag<'a>(
    inner: &'a Arc<RwLock<SrvInner>>,
    send: &'a crate::sodium_secretstream::S3Sender<LairApiEnum>,
    unlocked: &'a Arc<atomic::AtomicBool>,
    req: LairApiReqSecretBoxXSalsaOpenByTag,
) -> impl Future<Output = LairResult<()>> + 'a + Send {
    async move {
        if !unlocked.load(atomic::Ordering::Relaxed) {
            return Err("KeystoreLocked".into());
        }

        // get cached full entry
        let (full_entry, _) =
            priv_get_full_entry_by_tag(inner, req.tag.clone()).await?;

        use sodoken::secretbox::xsalsa20poly1305::*;

        if req.cipher.len() < MACBYTES {
            return Err("InvalidCipherLength".into());
        }

        let message =
            sodoken::BufWrite::new_no_lock(req.cipher.len() - MACBYTES);

        if let Some(seed) = full_entry.seed {
            open_easy(req.nonce, message.clone(), req.cipher, seed).await?;
        } else {
            return Err("deep_seed secretbox not yet implemented".into());
        }

        send.send(
            LairApiResSecretBoxXSalsaOpenByTag {
                msg_id: req.msg_id,
                message: message.try_unwrap().unwrap().into(),
            }
            .into_api_enum(),
        )
        .await?;

        Ok(())
    }
}
