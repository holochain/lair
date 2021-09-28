//! standalone binary server
//! - you probably only want to use this directly if you're writing tests

use lair_keystore_api::ipc_keystore::IpcKeystoreServer;
use lair_keystore_api::prelude::*;
use std::future::Future;

/// standalone binary server
/// - you probably only want to use this directly if you're writing tests
pub struct StandaloneServer {
    config: LairServerConfig,
    srv_hnd: Option<IpcKeystoreServer>,
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

        Ok(Self {
            config,
            srv_hnd: None,
        })
    }

    /// Run the server.
    pub async fn run<P>(&mut self, passphrase: P) -> LairResult<()>
    where
        P: Into<sodoken::BufRead> + 'static + Send,
    {
        let passphrase = passphrase.into();

        // construct our sqlite store factory
        let store_factory = crate::store_sqlite::create_sql_pool_factory(
            &self.config.store_file,
        );

        // spawn the server
        let srv_hnd = IpcKeystoreServer::new(
            self.config.clone(),
            store_factory,
            passphrase,
        )
        .await?;

        println!(
            "# lair-keystore connection_url # {} #",
            srv_hnd.get_config().connection_url
        );
        println!("# lair-keystore running #");

        self.srv_hnd = Some(srv_hnd);

        Ok(())
    }

    /// get a handle to the LairStore instantiated by this server,
    /// may error if a store has not yet been created.
    pub fn store(
        &self,
    ) -> impl Future<Output = LairResult<LairStore>> + 'static + Send {
        let srv_hnd = self.srv_hnd.clone();
        async move {
            let srv_hnd = srv_hnd.ok_or_else(|| {
                one_err::OneErr::new("server not yet running")
            })?;
            srv_hnd.store().await
        }
    }
}
