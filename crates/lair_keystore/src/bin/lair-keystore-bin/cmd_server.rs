use super::*;

pub(crate) async fn exec(
    config: LairServerConfig,
    opt: OptServer,
) -> LairResult<()> {
    if opt.piped && opt.locked {
        return Err(
            "-p / --piped and -l / --locked are mutually exclusive".into()
        );
    }

    // construct the server so that pid-check etc happens first
    let mut server =
        lair_keystore_lib::server::StandaloneServer::new(config).await?;

    let passphrase = if opt.piped {
        Some(read_piped_passphrase().await?)
    } else if opt.locked {
        None
    } else {
        Some(read_interactive_passphrase("\n# passphrase> ").await?)
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
