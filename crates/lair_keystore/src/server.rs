//! Standalone binary lair server used by the 'lair-keystore' executable.
//! You probably only want to use this directly if you're writing tests.

use crate::*;
use lair_keystore_api::ipc_keystore::IpcKeystoreServer;
use std::future::Future;

/// Standalone binary lair server used by the 'lair-keystore' executable.
/// You probably only want to use this directly if you're writing tests.
pub struct StandaloneServer {
    config: LairServerConfig,
    // held for the life of the server; also cloned into the store factory
    // and every store handle
    _lock: crate::store_lock::StoreLock,
    store_factory: LairStoreFactory,
    srv_hnd: Option<IpcKeystoreServer>,
}

impl StandaloneServer {
    /// Construct a new standalone server. Note, exclusive ownership of the
    /// store file is acquired here.
    pub async fn new(config: LairServerConfig) -> LairResult<Self> {
        // acquire exclusive ownership of the store file and construct the
        // sqlite store factory
        let (lock, store_factory) =
            crate::store_lock::prepare_persistent_store(config.clone()).await?;

        Ok(Self {
            config,
            _lock: lock,
            store_factory,
            srv_hnd: None,
        })
    }

    /// Run the server.
    pub async fn run(
        &mut self,
        passphrase: SharedLockedArray,
    ) -> LairResult<()> {
        // spawn the server
        let srv_hnd = IpcKeystoreServer::new(
            self.config.clone(),
            self.store_factory.clone(),
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
