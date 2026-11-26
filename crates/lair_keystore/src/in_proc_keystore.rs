//! A persistent in-process lair keystore backed by the canonical sqlite
//! store, without requiring an ipc socket or a separate process.

use crate::*;
use std::future::Future;

/// An in-process keystore backed by the canonical sqlite store.
///
/// Unlike the factory-taking
/// [lair_keystore_api::in_proc_keystore::InProcKeystore::new], this
/// constructor acquires exclusive ownership of the configured store file,
/// so it is safe to use with the persistent sqlite store.
#[derive(Clone)]
pub struct InProcKeystore {
    // held for the life of the server; also cloned into the store factory
    // and every store handle
    _lock: crate::store_lock::StoreLock,
    inner: lair_keystore_api::in_proc_keystore::InProcKeystore,
}

impl InProcKeystore {
    /// Construct a new persistent in-process keystore instance.
    /// The internal server will already be "interactively" unlocked.
    pub fn new(
        config: LairServerConfig,
        passphrase: SharedLockedArray,
    ) -> impl Future<Output = LairResult<Self>> + 'static + Send {
        async move {
            // acquire exclusive ownership of the store file and construct
            // the sqlite store factory
            let (lock, store_factory) =
                crate::store_lock::prepare_persistent_store(config.clone())
                    .await?;

            // set up our server handler
            let inner =
                lair_keystore_api::in_proc_keystore::InProcKeystore::new(
                    config,
                    store_factory,
                    passphrase,
                )
                .await?;

            // keep the exclusive store ownership on the server handle,
            // mirroring `crate::server::StandaloneServer`
            Ok(Self { _lock: lock, inner })
        }
    }

    /// Get a handle to the LairStore instantiated by this server,
    /// may error if a store has not yet been created.
    pub fn store(
        &self,
    ) -> impl Future<Output = LairResult<LairStore>> + 'static + Send {
        self.inner.store()
    }

    /// Get the config used by the LairServer held by this InProcKeystore.
    pub fn get_config(&self) -> LairServerConfig {
        self.inner.get_config()
    }

    /// Get a new LairClient connection to this InProcKeystore server.
    /// This new connection will already have verified the server identity
    /// via "hello" request as well as unlocked the connection.
    pub fn new_client(
        &self,
    ) -> impl Future<Output = LairResult<LairClient>> + 'static + Send {
        self.inner.new_client()
    }
}
