//! standalone binary server
//! - you probably only want to use this directly if you're writing tests

use lair_keystore_api::prelude::*;

/// standalone binary server
/// - you probably only want to use this directly if you're writing tests
pub struct StandaloneServer {
    config: LairServerConfig,
}

impl StandaloneServer {
    /// Construct a new standalone server. Note, pid-check is acquired here.
    pub async fn new(config: LairServerConfig) -> LairResult<Self> {
        // first make sure we can acquire a pid_file for the given location
        {
            let config = config.clone();
            // TODO - make pid_check async friendly
            tokio::task::spawn_blocking(move || {
                crate::pid_check::pid_check(&config)
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

        Ok(Self { config })
    }

    /// Run the server unlocked "interactively" right away with supplied pw.
    pub async fn run_unlocked<P>(self, passphrase: P) -> LairResult<()>
    where
        P: Into<sodoken::BufRead> + 'static + Send,
    {
        let passphrase = passphrase.into();
        self.priv_run(Some(passphrase)).await
    }

    /// Run the server in initially "locked" mode.
    /// Note, this is not very secure.
    pub async fn run_locked(self) -> LairResult<()> {
        self.priv_run(None).await
    }

    async fn priv_run(
        self,
        passphrase: Option<sodoken::BufRead>,
    ) -> LairResult<()> {
        // construct our sqlite store factory
        let store_factory = crate::store_sqlite::create_sql_pool_factory(
            &self.config.store_file,
        );

        // spawn the server
        let srv_hnd = lair_keystore_api::ipc_keystore::IpcKeystoreServer::new(
            self.config.clone(),
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

        Ok(())
    }
}
