use super::*;
use crate::types::SharedSizedLockedArray;
use one_err::OneErr;
use std::convert::TryInto;
use std::sync::Mutex;

pub(crate) fn priv_req_hello<'a>(
    inner: &'a Arc<RwLock<SrvInner>>,
    send: &'a sodium_secretstream::S3Sender<LairApiEnum>,
    req: LairApiReqHello,
) -> impl Future<Output = LairResult<()>> + 'a + Send {
    async move {
        // DON'T check connection 'unlocked' here,
        // we want to be able to verify the server,
        // before we unlock the individual connection.

        let (id_pk, server_name, server_version) = {
            let lock = inner.read().unwrap();
            (
                lock.id_pk.clone(),
                lock.server_name.clone(),
                lock.server_version.clone(),
            )
        };

        // send our hello response
        send.send(
            LairApiResHello {
                msg_id: req.msg_id,
                name: server_name,
                version: server_version,
                server_pub_key: id_pk.into(),
            }
            .into_api_enum(),
        )
        .await?;

        Ok(())
    }
}

pub(crate) fn priv_req_unlock<'a>(
    inner: &'a Arc<RwLock<SrvInner>>,
    send: &'a sodium_secretstream::S3Sender<LairApiEnum>,
    dec_ctx_key: SharedSizedLockedArray<32>,
    unlocked: &'a Arc<atomic::AtomicBool>,
    req: LairApiReqUnlock,
) -> impl Future<Output = LairResult<()>> + 'a + Send {
    async move {
        let mut passphrase = req.passphrase.decrypt(dec_ctx_key).await?;

        let (config, id_pk) = {
            let lock = inner.read().unwrap();
            (lock.config.clone(), lock.id_pk.clone())
        };

        // read salt from config
        let salt = config.runtime_secrets_salt.cloned_inner();

        // read limits from config
        let ops_limit = config.runtime_secrets_ops_limit;
        let mem_limit = config.runtime_secrets_mem_limit;

        // calculate pre_secret from argon2id passphrase hash
        let mut pre_secret =
            tokio::task::spawn_blocking(move || -> LairResult<_> {
                let mut pre_secret = sodoken::SizedLockedArray::<32>::new()?;
                sodoken::argon2::blocking_argon2id(
                    &mut *pre_secret.lock(),
                    passphrase.lock().as_slice(),
                    &salt,
                    ops_limit,
                    mem_limit,
                )?;

                Ok(pre_secret)
            })
            .await
            .map_err(OneErr::new)??;

        // derive signature decryption secret
        let mut id_secret = sodoken::SizedLockedArray::<32>::new()?;
        sodoken::kdf::derive_from_key(
            &mut *id_secret.lock(),
            142,
            b"IdnSecKy",
            &pre_secret.lock(),
        )?;
        let id_secret = Arc::new(Mutex::new(id_secret));

        // decrypt the signature seed
        let mut id_seed =
            config.runtime_secrets_id_seed.decrypt(id_secret).await?;

        // derive the signature keypair from the signature seed
        let mut d_id_pk = [0; sodoken::crypto_box::XSALSA_PUBLICKEYBYTES];
        let mut d_id_sk = sodoken::SizedLockedArray::<
            { sodoken::crypto_box::XSALSA_SECRETKEYBYTES },
        >::new()?;
        sodoken::crypto_box::xsalsa_seed_keypair(
            &mut d_id_pk,
            &mut d_id_sk.lock(),
            &id_seed.lock(),
        )?;

        if *id_pk.as_slice() != *d_id_pk.as_slice() {
            return Err("InvalidPassphrase".into());
        }

        // if that was successful, we can also set the connection level
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
    send: &'a sodium_secretstream::S3Sender<LairApiEnum>,
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
    send: &'a sodium_secretstream::S3Sender<LairApiEnum>,
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
    send: &'a sodium_secretstream::S3Sender<LairApiEnum>,
    dec_ctx_key: SharedSizedLockedArray<32>,
    unlocked: &'a Arc<atomic::AtomicBool>,
    req: LairApiReqNewSeed,
) -> impl Future<Output = LairResult<()>> + 'a + Send {
    async move {
        let store = priv_get_store(inner, unlocked)?;

        let seed_info = match req.deep_lock_passphrase {
            Some(secret) => {
                // if deep locked, decrypt the deep lock passphrase
                let deep_lock_passphrase =
                    secret.passphrase.decrypt(dec_ctx_key).await?;

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
pub(crate) fn priv_req_derive_seed<'a>(
    inner: &'a Arc<RwLock<SrvInner>>,
    send: &'a sodium_secretstream::S3Sender<LairApiEnum>,
    dec_ctx_key: SharedSizedLockedArray<32>,
    unlocked: &'a Arc<atomic::AtomicBool>,
    req: LairApiReqDeriveSeed,
) -> impl Future<Output = LairResult<()>> + 'a + Send {
    async move {
        let store = priv_get_store(inner, unlocked)?;

        let entry = store.get_entry_by_tag(req.src_tag.clone()).await?;

        let (src_seed, src_seed_info) = match (&*entry, req.src_deep_lock_passphrase) {
            (LairEntryInner::Seed { seed, seed_info, .. }, None) => {
                let seed = seed.decrypt(store.get_bidi_ctx_key()).await?;
                (seed, seed_info)
            }

            (
                LairEntryInner::DeepLockedSeed {
                    seed,
                    seed_info,
                    salt,
                    ..
                },
                Some(secret),
            ) => {
                let deep_key = deep_unlock_key_from_passphrase(
                    secret,
                    dec_ctx_key.clone(),
                    salt.clone().cloned_inner(),
                )
                .await?;
                let seed = seed.decrypt(Arc::new(Mutex::new(deep_key))).await?;
                (seed, seed_info)
            },

            (LairEntryInner::WkaTlsCert { .. }, _) => return Err("The tag provided is for a Cert, which cannot be derived. You must specify the tag for a Seed.".into()),
            (LairEntryInner::Seed { .. }, Some(_)) => return Err("A passphrase was provided for a seed which is not deep-locked. Make the request without a `src_passphrase`.".into()),
            (LairEntryInner::DeepLockedSeed { .. }, None) => return Err("A `src_passphrase` is needed to unlock the source seed which is deep-locked.".into()),
        };

        let derivation_path = req.derivation_path.clone();
        let mut parent = src_seed;

        for index in derivation_path.iter() {
            let mut derived = sodoken::SizedLockedArray::<32>::new()?;
            sodoken::kdf::derive_from_key(
                &mut *derived.lock(),
                *index as u64,
                b"SeedBndl",
                &parent.lock(),
            )?;
            parent = derived;
        }

        let dst_seed = Arc::new(Mutex::new(parent));
        let dst_dlp = req.dst_deep_lock_passphrase;

        let dst_seed_info = match dst_dlp {
            Some(secret) => {
                // if deep locked, decrypt the deep lock passphrase
                let deep_lock_passphrase =
                    secret.passphrase.decrypt(dec_ctx_key.clone()).await?;

                store
                    .insert_deep_locked_seed(
                        dst_seed,
                        req.dst_tag.clone(),
                        secret.ops_limit,
                        secret.mem_limit,
                        deep_lock_passphrase,
                        src_seed_info.exportable,
                    )
                    .await?
            }
            // create a new seed
            None => {
                store
                    .insert_seed(
                        dst_seed,
                        req.dst_tag.clone(),
                        src_seed_info.exportable,
                    )
                    .await?
            }
        };
        // send the response
        send.send(
            LairApiResDeriveSeed {
                msg_id: req.msg_id,
                // tag: req.tag.clone(),
                seed_info: dst_seed_info,
            }
            .into_api_enum(),
        )
        .await?;

        Ok(())
    }
}

pub(crate) fn priv_req_export_seed_by_tag<'a>(
    inner: &'a Arc<RwLock<SrvInner>>,
    send: &'a sodium_secretstream::S3Sender<LairApiEnum>,
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

        let msg_id = req.msg_id.clone();

        let (nonce, cipher) = if let Some(x_sk) = enc_entry.x_sk {
            if let Some(seed) = seed_entry.seed {
                if !seed_entry.exportable {
                    return Err("seed is not exportable".into());
                }

                let mut nonce = [0; sodoken::crypto_box::XSALSA_NONCEBYTES];
                sodoken::random::randombytes_buf(&mut nonce)?;

                let mut seed_guard = seed.lock().unwrap();
                let seed_guard = seed_guard.lock();

                let mut cipher = vec![
                    0;
                    seed_guard.len()
                        + sodoken::crypto_box::XSALSA_MACBYTES
                ];
                sodoken::crypto_box::xsalsa_easy(
                    cipher.as_mut_slice(),
                    seed_guard.as_slice(),
                    &nonce,
                    &req.recipient_pub_key.cloned_inner(),
                    &x_sk.lock().unwrap().lock(),
                )?;

                (nonce, cipher)
            } else {
                return Err("deep_seed crypto_box not yet implemented".into());
            }
        } else {
            return Err("deep_seed crypto_box not yet implemented".into());
        };

        send.send(
            LairApiResExportSeedByTag {
                msg_id,
                nonce,
                cipher: cipher.into(),
            }
            .into_api_enum(),
        )
        .await?;

        Ok(())
    }
}

pub(crate) fn priv_req_import_seed<'a>(
    inner: &'a Arc<RwLock<SrvInner>>,
    send: &'a sodium_secretstream::S3Sender<LairApiEnum>,
    dec_ctx_key: SharedSizedLockedArray<32>,
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

        if req.cipher.len() != 32 + sodoken::crypto_box::XSALSA_MACBYTES {
            return Err("Bad Seed Length".into());
        }

        let msg_id = req.msg_id.clone();
        let tag = req.tag.clone();
        let exportable = req.exportable;
        let deep_lock_passphrase = req.deep_lock_passphrase.clone();

        let seed = if let Some(x_sk) = full_entry.x_sk {
            let mut seed = sodoken::SizedLockedArray::<32>::new()?;

            sodoken::crypto_box::xsalsa_open_easy(
                &mut *seed.lock(),
                &req.cipher,
                &req.nonce,
                &req.sender_pub_key.cloned_inner(),
                &x_sk.lock().unwrap().lock(),
            )?;

            seed
        } else {
            return Err("deep_seed crypto_box not yet implemented".into());
        };

        let seed = Arc::new(Mutex::new(seed));

        let seed_info = match deep_lock_passphrase {
            Some(secret) => {
                // if deep locked, decrypt the deep lock passphrase
                let deep_lock_passphrase =
                    secret.passphrase.decrypt(dec_ctx_key).await?;

                // create a new deep locked seed
                store
                    .insert_deep_locked_seed(
                        seed,
                        tag.clone(),
                        secret.ops_limit,
                        secret.mem_limit,
                        deep_lock_passphrase,
                        exportable,
                    )
                    .await?
            }
            // create a new seed
            None => store.insert_seed(seed, tag.clone(), exportable).await?,
        };

        send.send(
            LairApiResImportSeed {
                msg_id,
                tag,
                seed_info,
            }
            .into_api_enum(),
        )
        .await?;

        Ok(())
    }
}

async fn deep_unlock_key_from_passphrase(
    dlp: DeepLockPassphrase,
    dec_ctx_key: SharedSizedLockedArray<32>,
    salt: Arc<[u8; 16]>,
) -> LairResult<sodoken::SizedLockedArray<32>> {
    // generate the deep lock key from the passphrase
    let mut passphrase = dlp.passphrase.decrypt(dec_ctx_key).await?;

    let deep_key = tokio::task::spawn_blocking(move || -> LairResult<_> {
        let mut deep_key = sodoken::SizedLockedArray::<32>::new()?;
        sodoken::argon2::blocking_argon2id(
            &mut *deep_key.lock(),
            passphrase.lock().as_slice(),
            &salt,
            dlp.ops_limit,
            dlp.mem_limit,
        )?;

        Ok(deep_key)
    })
    .await
    .map_err(OneErr::new)??;

    Ok(deep_key)
}

pub(crate) fn priv_req_sign_by_pub_key<'a>(
    inner: &'a Arc<RwLock<SrvInner>>,
    send: &'a sodium_secretstream::S3Sender<LairApiEnum>,
    dec_ctx_key: SharedSizedLockedArray<32>,
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
                // get the signing private key
                let ed_sk = match (&*full_entry.entry, full_entry.ed_sk, req.deep_lock_passphrase.clone()) {
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
                        let deep_key = deep_unlock_key_from_passphrase(DeepLockPassphrase { ops_limit: *ops_limit, mem_limit: *mem_limit, passphrase }, dec_ctx_key, salt.clone().cloned_inner()).await?;
                        let seed = Arc::new(Mutex::new(seed.decrypt(Arc::new(Mutex::new(deep_key))).await?));
                        let (_, ed_sk) = derive_ed(seed).await?;
                        Arc::new(Mutex::new(ed_sk))
                    }
                    _ => return Err("The entry for this key is not a seed which can produce a signature".into())
                };

                let msg_id = req.msg_id.clone();

                let mut signature = [0; sodoken::sign::SIGNATUREBYTES];

                sodoken::sign::sign_detached(
                    &mut signature,
                    &req.data,
                    &ed_sk.lock().unwrap().lock(),
                )?;

                LairApiResSignByPubKey {
                    msg_id,
                    signature: signature.into(),
                }
            }
            Err(e) => {
                // we don't have this key, let's see if we should invoke
                // a signature fallback command
                let fallback_cmd = inner.read().unwrap().fallback_cmd.clone();
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
    send: &'a sodium_secretstream::S3Sender<LairApiEnum>,
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

        let msg_id = req.msg_id.clone();

        let (nonce, cipher) = if let Some(x_sk) = full_entry.x_sk {
            let mut nonce = [0; sodoken::crypto_box::XSALSA_NONCEBYTES];
            sodoken::random::randombytes_buf(&mut nonce)?;

            let mut cipher =
                vec![0; req.data.len() + sodoken::crypto_box::XSALSA_MACBYTES];
            sodoken::crypto_box::xsalsa_easy(
                &mut cipher,
                &req.data,
                &nonce,
                &req.recipient_pub_key.cloned_inner(),
                &x_sk.lock().unwrap().lock(),
            )?;

            (nonce, cipher)
        } else {
            return Err("deep_seed crypto_box not yet implemented".into());
        };

        send.send(
            LairApiResCryptoBoxXSalsaByPubKey {
                msg_id,
                nonce,
                cipher: cipher.into(),
            }
            .into_api_enum(),
        )
        .await?;

        Ok(())
    }
}

pub(crate) fn priv_req_crypto_box_xsalsa_open_by_pub_key<'a>(
    inner: &'a Arc<RwLock<SrvInner>>,
    send: &'a sodium_secretstream::S3Sender<LairApiEnum>,
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

        if req.cipher.len() < sodoken::crypto_box::XSALSA_MACBYTES {
            return Err("InvalidCipherLength".into());
        }

        let msg_id = req.msg_id.clone();

        let message = if let Some(x_sk) = full_entry.x_sk {
            let mut message = vec![
                0;
                req.cipher.len()
                    - sodoken::crypto_box::XSALSA_MACBYTES
            ];
            sodoken::crypto_box::xsalsa_open_easy(
                &mut message,
                &req.cipher,
                &req.nonce,
                &req.sender_pub_key.cloned_inner(),
                &x_sk.lock().unwrap().lock(),
            )?;

            message
        } else {
            return Err("deep_seed crypto_box not yet implemented".into());
        };

        send.send(
            LairApiResCryptoBoxXSalsaOpenByPubKey {
                msg_id,
                message: message.into(),
            }
            .into_api_enum(),
        )
        .await?;

        Ok(())
    }
}

pub(crate) fn priv_req_crypto_box_xsalsa_by_sign_pub_key<'a>(
    inner: &'a Arc<RwLock<SrvInner>>,
    send: &'a sodium_secretstream::S3Sender<LairApiEnum>,
    unlocked: &'a Arc<atomic::AtomicBool>,
    req: LairApiReqCryptoBoxXSalsaBySignPubKey,
) -> impl Future<Output = LairResult<()>> + 'a + Send {
    async move {
        if !unlocked.load(atomic::Ordering::Relaxed) {
            return Err("KeystoreLocked".into());
        }

        // get cached full entry
        let (full_entry, _) = priv_get_full_entry_by_ed_pub_key(
            inner,
            req.sender_pub_key.clone(),
        )
        .await?;

        let msg_id = req.msg_id.clone();

        let (nonce, cipher) = if let Some(ed_sk) = full_entry.ed_sk {
            let mut x_pk = vec![0; req.recipient_pub_key.len()];
            sodoken::sign::pk_to_curve25519(
                x_pk.as_mut_slice().try_into().unwrap(),
                &req.recipient_pub_key.cloned_inner(),
            )?;
            let mut x_sk = sodoken::SizedLockedArray::<32>::new()?;
            sodoken::sign::sk_to_curve25519(
                &mut x_sk.lock(),
                &ed_sk.lock().unwrap().lock(),
            )?;

            let mut nonce = [0; sodoken::crypto_box::XSALSA_NONCEBYTES];
            sodoken::random::randombytes_buf(&mut nonce)?;

            let mut cipher =
                vec![0; req.data.len() + sodoken::crypto_box::XSALSA_MACBYTES];
            sodoken::crypto_box::xsalsa_easy(
                cipher.as_mut_slice(),
                &req.data,
                &nonce,
                x_pk.as_slice().try_into().unwrap(),
                &x_sk.lock(),
            )?;

            (nonce, cipher)
        } else {
            return Err("deep_seed crypto_box not yet implemented".into());
        };

        send.send(
            LairApiResCryptoBoxXSalsaBySignPubKey {
                msg_id,
                nonce,
                cipher: cipher.into(),
            }
            .into_api_enum(),
        )
        .await?;

        Ok(())
    }
}

pub(crate) fn priv_req_crypto_box_xsalsa_open_by_sign_pub_key<'a>(
    inner: &'a Arc<RwLock<SrvInner>>,
    send: &'a sodium_secretstream::S3Sender<LairApiEnum>,
    unlocked: &'a Arc<atomic::AtomicBool>,
    req: LairApiReqCryptoBoxXSalsaOpenBySignPubKey,
) -> impl Future<Output = LairResult<()>> + 'a + Send {
    async move {
        if !unlocked.load(atomic::Ordering::Relaxed) {
            return Err("KeystoreLocked".into());
        }

        // get cached full entry
        let (full_entry, _) = priv_get_full_entry_by_ed_pub_key(
            inner,
            req.recipient_pub_key.clone(),
        )
        .await?;

        if req.cipher.len() < sodoken::crypto_box::XSALSA_MACBYTES {
            return Err("InvalidCipherLength".into());
        }

        let msg_id = req.msg_id.clone();

        let message = if let Some(ed_sk) = full_entry.ed_sk {
            let mut x_pk = vec![0; req.sender_pub_key.len()];
            sodoken::sign::pk_to_curve25519(
                x_pk.as_mut_slice().try_into().unwrap(),
                &req.sender_pub_key.cloned_inner(),
            )?;
            let mut x_sk = sodoken::SizedLockedArray::<
                { sodoken::crypto_box::XSALSA_SECRETKEYBYTES },
            >::new()?;
            sodoken::sign::sk_to_curve25519(
                &mut x_sk.lock(),
                &ed_sk.lock().unwrap().lock(),
            )?;

            let mut message = vec![
                0;
                req.cipher.len()
                    - sodoken::crypto_box::XSALSA_MACBYTES
            ];
            sodoken::crypto_box::xsalsa_open_easy(
                &mut message,
                &req.cipher,
                &req.nonce,
                x_pk.as_slice().try_into().unwrap(),
                &x_sk.lock(),
            )?;

            message
        } else {
            return Err("deep_seed crypto_box not yet implemented".into());
        };

        send.send(
            LairApiResCryptoBoxXSalsaOpenBySignPubKey {
                msg_id,
                message: message.into(),
            }
            .into_api_enum(),
        )
        .await?;

        Ok(())
    }
}

pub(crate) fn priv_req_new_wka_tls_cert<'a>(
    inner: &'a Arc<RwLock<SrvInner>>,
    send: &'a sodium_secretstream::S3Sender<LairApiEnum>,
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
    seed: SharedSizedLockedArray<32>,
) -> LairResult<(Ed25519PubKey, sodoken::SizedLockedArray<64>)> {
    // get the signature keypair
    let mut ed_pk = [0; sodoken::sign::PUBLICKEYBYTES];
    let mut ed_sk =
        sodoken::SizedLockedArray::<{ sodoken::sign::SECRETKEYBYTES }>::new()?;

    sodoken::sign::seed_keypair(
        &mut ed_pk,
        &mut ed_sk.lock(),
        &seed.lock().unwrap().lock(),
    )?;

    Ok((ed_pk.into(), ed_sk))
}

pub(crate) async fn derive_x(
    seed: SharedSizedLockedArray<32>,
) -> LairResult<(X25519PubKey, sodoken::SizedLockedArray<32>)> {
    // get the encryption keypair
    let mut x_pk = [0; sodoken::crypto_box::XSALSA_PUBLICKEYBYTES];
    let mut x_sk = sodoken::SizedLockedArray::<
        { sodoken::crypto_box::XSALSA_SECRETKEYBYTES },
    >::new()?;

    // we're using the chacha sodium keypair api here, but the
    // keypairs are valid also for salsa.
    sodoken::crypto_box::xsalsa_seed_keypair(
        &mut x_pk,
        &mut x_sk.lock(),
        &seed.lock().unwrap().lock(),
    )?;

    Ok((x_pk.into(), x_sk))
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
                let seed = Arc::new(Mutex::new(
                    seed.decrypt(store.get_bidi_ctx_key()).await?,
                ));
                let (ed_pk, ed_sk) = derive_ed(seed.clone()).await?;
                let (x_pk, x_sk) = derive_x(seed.clone()).await?;

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
                    Some(Arc::new(Mutex::new(ed_sk))),
                    Some(seed_info.x25519_pub_key.clone()),
                    Some(Arc::new(Mutex::new(x_sk))),
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

        let mut lock = inner.write().unwrap();

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
            let mut lock = inner.write().unwrap();
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
            let mut lock = inner.write().unwrap();
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
            let mut lock = inner.write().unwrap();
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
    send: &'a sodium_secretstream::S3Sender<LairApiEnum>,
    enc_ctx_key: SharedSizedLockedArray<32>,
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
        let priv_key = Arc::new(Mutex::new(
            priv_key.decrypt(store.get_bidi_ctx_key()).await?,
        ));

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

        let msg_id = req.msg_id.clone();

        let (nonce, cipher) = if let Some(seed) = full_entry.seed {
            let mut nonce = [0; sodoken::secretbox::XSALSA_NONCEBYTES];
            sodoken::random::randombytes_buf(&mut nonce)?;

            let mut cipher =
                vec![0; req.data.len() + sodoken::secretbox::XSALSA_MACBYTES];
            sodoken::secretbox::xsalsa_easy(
                &mut cipher,
                &nonce,
                &req.data,
                &seed.lock().unwrap().lock(),
            )?;

            (nonce, cipher)
        } else {
            return Err("deep_seed secretbox not yet implemented".into());
        };

        send.send(
            LairApiResSecretBoxXSalsaByTag {
                msg_id,
                nonce,
                cipher: cipher.into(),
            }
            .into_api_enum(),
        )
        .await?;

        Ok(())
    }
}

pub(crate) fn priv_req_secret_box_xsalsa_open_by_tag<'a>(
    inner: &'a Arc<RwLock<SrvInner>>,
    send: &'a sodium_secretstream::S3Sender<LairApiEnum>,
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

        if req.cipher.len() < sodoken::secretbox::XSALSA_MACBYTES {
            return Err("InvalidCipherLength".into());
        }

        let msg_id = req.msg_id.clone();

        let message = if let Some(seed) = full_entry.seed {
            let mut message =
                vec![0; req.cipher.len() - sodoken::secretbox::XSALSA_MACBYTES];
            sodoken::secretbox::xsalsa_open_easy(
                &mut message,
                &req.cipher,
                &req.nonce,
                &seed.lock().unwrap().lock(),
            )?;

            message
        } else {
            return Err("deep_seed secretbox not yet implemented".into());
        };

        send.send(
            LairApiResSecretBoxXSalsaOpenByTag {
                msg_id,
                message: message.into(),
            }
            .into_api_enum(),
        )
        .await?;

        Ok(())
    }
}
