use super::*;

pub(crate) async fn exec(
    config: LairServerConfig,
    opt: OptServer,
) -> LairResult<()> {
    // first make sure we can acquire a pid_file for the given location
    {
        let config = config.clone();
        // TODO - make pid_check async friendly
        tokio::task::spawn_blocking(move || {
            lair_keystore_lib::pid_check::pid_check(&config)
        })
        .await
        .map_err(one_err::OneErr::new)??;
    }

    // sanity check that store_file's parent is a directory
    if !tokio::fs::metadata(
        config.store_file.parent().expect("invalid store_file dir"),
    )
    .await?
    .is_dir()
    {
        return Err("invalid store file directory".into());
    }

    // sanity check that store file either doesn't exist or is a file
    match tokio::fs::metadata(&config.store_file).await {
        // it's ok if the store file doesn't exist yet
        Err(_) => (),
        Ok(m) => {
            // if it exists, it must be a file
            if !m.is_file() {
                return Err("store file is not a file".into());
            }
        }
    }

    // if we are interactive, get the passphrase before starting the server
    let passphrase = if opt.interactive {
        let mut pass_tmp = tokio::task::spawn_blocking(|| {
            LairResult::Ok(
                rpassword::read_password_from_tty(Some("\n# passphrase> "))
                    .map_err(one_err::OneErr::new)?
                    .into_bytes(),
            )
        })
        .await
        .map_err(one_err::OneErr::new)??;

        match sodoken::BufWrite::new_mem_locked(pass_tmp.len()) {
            Err(e) => {
                pass_tmp.fill(0);
                return Err(e);
            }
            Ok(p) => {
                {
                    let mut lock = p.write_lock();
                    lock.copy_from_slice(&pass_tmp);
                    pass_tmp.fill(0);
                }
                Some(p.to_read())
            }
        }
    } else {
        None
    };

    // construct our sqlite store factory
    let store_factory =
        lair_keystore_lib::store_sqlite::create_sql_pool_factory(
            &config.store_file,
        );

    // spawn the server
    let srv_hnd = lair_keystore_api::ipc_keystore::IpcKeystoreServer::new(
        config,
        store_factory,
    )
    .await?;

    if let Some(passphrase) = passphrase {
        srv_hnd.unlock(passphrase).await?;
        println!("# lair-keystore unlocked #");
    }

    println!(
        "# lair-keystore connection_url # {} #",
        srv_hnd.get_config().connection_url
    );
    println!("# lair-keystore running #");

    // if we made it this far, the server is running...
    // we want it to run forever, so this future never resolves:
    futures::future::pending().await
}
