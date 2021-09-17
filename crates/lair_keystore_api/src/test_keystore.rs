//! a test keystore that runs in-memory and in-process

use crate::lair_client::LairClient;
use crate::lair_core::*;
use crate::LairResult2 as LairResult;
use std::future::Future;
use std::sync::Arc;

/// a test keystore that runs in-memory and in-process
#[derive(Clone)]
pub struct TestKeystore {
    config: LairServerConfig,
    srv_hnd: crate::lair_server::LairServer,
}

impl TestKeystore {
    /// Construct a new TestKeystore instance.
    /// The internal server will NOT have been unlocked interactively,
    /// if you wish to unlock from the server-side, call TestKeystore::unlock().
    /// Respects hc_seed_bundle::PwHashLimits.
    pub fn new<P>(
        passphrase: P,
    ) -> impl Future<Output = LairResult<Self>> + 'static + Send
    where
        P: Into<sodoken::BufRead> + 'static + Send,
    {
        let limits = hc_seed_bundle::PwHashLimits::current();
        async move {
            let store_factory = crate::mem_store::create_mem_store_factory();

            let config = Arc::new(
                limits
                    .with_exec(|| {
                        LairServerConfigInner::new("/", passphrase.into())
                    })
                    .await?,
            );

            let srv_hnd = crate::lair_server::spawn_lair_server_task(
                config.clone(),
                store_factory,
            )
            .await?;

            Ok(Self { config, srv_hnd })
        }
    }

    /// Get the config used by the LairServer held by this TestKeystore.
    pub fn get_config(&self) -> LairServerConfig {
        self.config.clone()
    }

    /// Unlock the LairServer held by this TestKeystore instance.
    pub fn unlock<P>(
        &self,
        passphrase: P,
    ) -> impl Future<Output = LairResult<()>> + 'static + Send
    where
        P: Into<sodoken::BufRead> + 'static + Send,
    {
        self.srv_hnd.unlock(passphrase.into())
    }

    /// Get a new LairClient connection to this TestKeystore server.
    /// This new connection will NOT have unlocked itself, or checked 'Hello'.
    pub fn new_connection(
        &self,
    ) -> impl Future<Output = LairResult<LairClient>> + 'static + Send {
        let srv_hnd = self.srv_hnd.clone();
        async move {
            // create a new duplex to simulate networking code
            let (srv, cli) = tokio::io::duplex(4096);

            // split into read/write halves
            let (srv_recv, srv_send) = tokio::io::split(srv);
            let (cli_recv, cli_send) = tokio::io::split(cli);

            // get the server accept future
            let srv_fut = srv_hnd.accept(srv_send, srv_recv);

            // get the client wrap future
            let cli_fut =
                crate::lair_client::wrap_raw_lair_client(cli_send, cli_recv);

            let (_, cli_hnd) =
                futures::future::try_join(srv_fut, cli_fut).await?;

            Ok(cli_hnd)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_keystore_happy_path() {
        // set up a passphrase
        let passphrase = sodoken::BufRead::from(&b"passphrase"[..]);

        // create a test keystore
        let keystore = hc_seed_bundle::PwHashLimits::Interactive
            .with_exec(|| TestKeystore::new(passphrase.clone()))
            .await
            .unwrap();

        let config = keystore.get_config();
        println!("{}", config);

        // unlock the test keystore from the server side
        keystore.unlock(passphrase.clone()).await.unwrap();

        // create a client connection to the keystore
        let client = keystore.new_connection().await.unwrap();

        // attempt a hello request
        assert!(client
            .hello(config.get_server_pub_key().unwrap())
            .await
            .is_ok());

        // attempt to unlock the connection
        assert!(client.unlock(passphrase).await.is_ok());

        // create a new seed
        let seed_info_ref =
            client.new_seed("test-tag".into(), None).await.unwrap();

        // list keystore contents
        let mut entry_list = client.list_entries().await.unwrap();

        assert_eq!(1, entry_list.len());
        match entry_list.remove(0) {
            LairEntryInfo::Seed { tag, seed_info } => {
                assert_eq!("test-tag", &*tag);
                assert_eq!(seed_info, seed_info_ref);
            }
            oth => panic!("unexpected: {:?}", oth),
        }
    }
}
