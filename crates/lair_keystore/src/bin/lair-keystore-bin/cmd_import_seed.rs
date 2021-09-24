use super::*;

pub(crate) async fn exec(
    config: LairServerConfig,
    opt: OptImportSeed,
) -> LairResult<()> {
    // we need to capture the pid_file to run a seed bundle import
    // i.e. we cannot do this while a server is running.
    {
        let config = config.clone();
        // TODO - make pid_check async friendly
        tokio::task::spawn_blocking(move || {
            lair_keystore_lib::pid_check::pid_check(&config)
        })
        .await
        .map_err(one_err::OneErr::new)??;
    }

    let (store_pass, bundle_pass, deep_pass) = if opt.piped {
        let multi = read_piped_passphrase().await?;
        let multi = multi.read_lock();

        // careful not to move any bytes out of protected memory
        // convert to utf8 so we can use the rust split.
        let multi =
            std::str::from_utf8(&*multi).map_err(one_err::OneErr::new)?;
        let mut pass_list = multi
            .split('\n')
            .filter_map(|s| {
                let s = s.trim();
                let s = s.as_bytes();
                if s.is_empty() {
                    None
                } else {
                    let n = sodoken::BufWrite::new_mem_locked(s.len())
                        .expect("failed to allocate locked BufWrite");
                    {
                        let mut n = n.write_lock();
                        n.copy_from_slice(s);
                    }
                    Some(n.to_read())
                }
            })
            .collect::<Vec<_>>();

        if opt.deep_lock {
            if pass_list.len() != 3 {
                return Err("expected 3 newline delimited passphrases".into());
            }
            (
                pass_list.remove(0),
                pass_list.remove(0),
                Some(pass_list.remove(0)),
            )
        } else {
            if pass_list.len() != 2 {
                return Err("expected 2 newline delimited passphrases".into());
            }
            (pass_list.remove(0), pass_list.remove(0), None)
        }
    } else {
        (
            read_interactive_passphrase("\n# store passphrase> ").await?,
            read_interactive_passphrase("\n# bundle passphrase> ").await?,
            if opt.deep_lock {
                Some(
                    read_interactive_passphrase("\n# deep-lock passphrase> ")
                        .await?,
                )
            } else {
                None
            },
        )
    };

    let bundle_bytes =
        base64::decode_config(&opt.seed_bundle_base64, base64::URL_SAFE_NO_PAD)
            .map_err(one_err::OneErr::new)?;
    let cipher_list =
        hc_seed_bundle::UnlockedSeedBundle::from_locked(&bundle_bytes).await?;

    let mut bundle = None;
    for cipher in cipher_list {
        use hc_seed_bundle::LockedSeedCipher::*;
        match cipher {
            PwHash(pw_hash) => {
                match pw_hash.unlock(bundle_pass.clone()).await {
                    Ok(b) => {
                        bundle = Some(b);
                        break;
                    }
                    _ => continue,
                }
            }
            _ => continue,
        }
    }

    let bundle = bundle
        .ok_or_else(|| one_err::OneErr::from("could not unlock seed bundle"))?;

    let seed = bundle.get_seed();

    // derive the ed25519 signature keypair from this seed
    let ed_pk = sodoken::BufWriteSized::new_no_lock();
    let ed_sk = sodoken::BufWriteSized::new_mem_locked()?;
    sodoken::sign::seed_keypair(ed_pk.clone(), ed_sk, seed.clone()).await?;

    // derive the x25519 encryption keypair from this seed
    let x_pk = sodoken::BufWriteSized::new_no_lock();
    let x_sk = sodoken::BufWriteSized::new_mem_locked()?;
    sodoken::sealed_box::curve25519xchacha20poly1305::seed_keypair(
        x_pk.clone(),
        x_sk,
        seed.clone(),
    )
    .await?;

    // populate our seed info with the derived public keys
    let seed_info = SeedInfo {
        ed25519_pub_key: ed_pk.try_unwrap_sized().unwrap().into(),
        x25519_pub_key: x_pk.try_unwrap_sized().unwrap().into(),
    };

    let store_factory =
        lair_keystore_lib::store_sqlite::create_sql_pool_factory(
            &config.store_file,
        );

    let srv_hnd = lair_keystore_api::ipc_keystore::IpcKeystoreServer::new(
        config,
        store_factory,
    )
    .await?;

    srv_hnd.unlock(store_pass).await?;

    let store = srv_hnd.store().await?;

    let entry = if let Some(deep_pass) = deep_pass {
        // generate the salt for the pwhash deep locking
        let salt = <sodoken::BufWriteSized<16>>::new_no_lock();
        sodoken::random::bytes_buf(salt.clone()).await?;

        let limits = hc_seed_bundle::PwHashLimits::Moderate;
        let ops_limit = limits.as_ops_limit();
        let mem_limit = limits.as_mem_limit();

        // generate the deep lock key from the passphrase
        let key = <sodoken::BufWriteSized<32>>::new_mem_locked()?;
        sodoken::hash::argon2id::hash(
            key.clone(),
            deep_pass,
            salt.clone(),
            ops_limit,
            mem_limit,
        )
        .await?;

        // encrypt the seed with the deep lock key
        let seed = SecretDataSized::encrypt(key.to_read_sized(), seed).await?;

        // construct the entry for the keystore
        LairEntryInner::DeepLockedSeed {
            tag: opt.tag.as_str().into(),
            seed_info: seed_info.clone(),
            salt: salt.try_unwrap_sized().unwrap().into(),
            ops_limit,
            mem_limit,
            seed,
        }
    } else {
        let key = store.get_bidi_ctx_key();
        let seed = SecretDataSized::encrypt(key, seed).await?;

        LairEntryInner::Seed {
            tag: opt.tag.as_str().into(),
            seed_info: seed_info.clone(),
            seed,
        }
    };

    store.0.write_entry(Arc::new(entry)).await?;

    println!("# imported seed {} {:?}", opt.tag, seed_info);

    Ok(())
}
