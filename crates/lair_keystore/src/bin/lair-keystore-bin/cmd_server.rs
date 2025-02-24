use super::*;
use std::sync::Mutex;

pub(crate) async fn exec(
    config: LairServerConfig,
    opt: OptServer,
) -> LairResult<()> {
    // construct the server so that pid-check etc happens first
    let mut server =
        lair_keystore::server::StandaloneServer::new(config).await?;

    let passphrase = if opt.piped {
        read_piped_passphrase().await?
    } else {
        read_interactive_passphrase("\n# passphrase> ").await?
    };

    let passphrase = Arc::new(Mutex::new(passphrase));

    server.run(passphrase).await?;

    // if we made it this far, the server is running...
    // we want it to run forever, so this future never resolves:
    futures::future::pending().await
}
