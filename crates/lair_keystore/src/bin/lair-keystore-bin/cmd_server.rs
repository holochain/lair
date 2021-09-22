use super::*;

pub(crate) async fn exec(
    config: LairServerConfig,
    opt: OptServer,
) -> LairResult<()> {
    // construct the server so that pid-check etc happens first
    let server =
        lair_keystore_lib::server::StandaloneServer::new(config).await?;

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

    if let Some(passphrase) = passphrase {
        server.run_unlocked(passphrase).await?;
    } else {
        server.run_locked().await?;
    }

    // if we made it this far, the server is running...
    // we want it to run forever, so this future never resolves:
    futures::future::pending().await
}
