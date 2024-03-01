//! An in-process keystore that manages the entire lair server life-cycle
//! without needing to call out to an external process.

use crate::*;
use std::future::Future;

/// An in-process keystore that manages the entire lair server life-cycle
/// without needing to call out to an external process.
#[derive(Clone)]
pub struct InProcKeystore {
    config: LairServerConfig,
    passphrase: sodoken::BufRead,
    srv_hnd: crate::lair_server::LairServer,
}

impl InProcKeystore {
    /// Construct a new InProcKeystore instance.
    /// The internal server will already be "interactively" unlocked.
    pub fn new<P>(
        config: LairServerConfig,
        store_factory: LairStoreFactory,
        passphrase: P,
    ) -> impl Future<Output = LairResult<Self>> + 'static + Send
    where
        P: Into<sodoken::BufRead> + 'static + Send,
    {
        async move {
            let passphrase = passphrase.into();

            // set up our server handler
            let srv_hnd = crate::lair_server::spawn_lair_server_task(
                config.clone(),
                "lair-keystore-in-proc".into(),
                crate::LAIR_VER.into(),
                store_factory,
                passphrase.clone(),
            )
            .await?;

            Ok(Self {
                config,
                passphrase,
                srv_hnd,
            })
        }
    }

    /// Get a handle to the LairStore instantiated by this server,
    /// may error if a store has not yet been created.
    pub fn store(
        &self,
    ) -> impl Future<Output = LairResult<LairStore>> + 'static + Send {
        self.srv_hnd.store()
    }

    /// Get the config used by the LairServer held by this InProcKeystore.
    pub fn get_config(&self) -> LairServerConfig {
        self.config.clone()
    }

    /// Get a new LairClient connection to this InProcKeystore server.
    /// This new connection will already have verified the server identity
    /// via "hello" request as well as unlocked the connection.
    pub fn new_client(
        &self,
    ) -> impl Future<Output = LairResult<LairClient>> + 'static + Send {
        let srv_pub_key = self.config.get_server_pub_key();
        let passphrase = self.passphrase.clone();
        let srv_hnd = self.srv_hnd.clone();
        async move {
            let srv_pub_key = srv_pub_key?;

            // note, for now it greatly simplifies the implementation
            // to just have the single server implementation expecting
            // to process async read/write channels. This increases
            // overhead for the in-process implementation, so, someday
            // we could make a shortcut for this use-case.

            // create a new duplex to simulate networking code
            let (srv, cli) = tokio::io::duplex(4096);

            // split into read/write halves
            let (srv_recv, srv_send) = tokio::io::split(srv);
            let (cli_recv, cli_send) = tokio::io::split(cli);

            // get the server accept future
            let srv_fut = srv_hnd.accept(srv_send, srv_recv);

            // get the client wrap future
            let cli_fut =
                crate::lair_client::async_io::new_async_io_lair_client(
                    cli_send,
                    cli_recv,
                    srv_pub_key.cloned_inner().into(),
                );

            // await both futures at the same time so they can
            // exchange information
            let (_, cli_hnd) =
                futures::future::try_join(srv_fut, cli_fut).await?;

            // verify server identity
            cli_hnd.hello(srv_pub_key).await?;

            // unlock the connection
            cli_hnd.unlock(passphrase).await?;

            Ok(cli_hnd)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test(flavor = "multi_thread")]
    async fn in_proc_happy_path() {
        // set up a passphrase
        let passphrase = sodoken::BufRead::from(&b"passphrase"[..]);

        // create the config for the test server
        // the path is immaterial since we'll be using an in-memory store
        let config = Arc::new(
            hc_seed_bundle::PwHashLimits::Interactive
                .with_exec(|| {
                    LairServerConfigInner::new("/", passphrase.clone())
                })
                .await
                .unwrap(),
        );

        // create an in-process keystore with an in-memory store
        let keystore = InProcKeystore::new(
            config,
            crate::mem_store::create_mem_store_factory(),
            passphrase.clone(),
        )
        .await
        .unwrap();

        let config = keystore.get_config();
        println!("{config}");

        // create a client connection to the keystore
        let client = keystore.new_client().await.unwrap();

        // create a new seed
        let seed_info_ref = client
            .new_seed("test-tag".into(), None, false)
            .await
            .unwrap();

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

        let tag = "test-tag-deep";
        let passphrase = sodoken::BufRead::from(&b"deep"[..]);

        // create a new deep-locked seed
        let seed_info_ref_deep = hc_seed_bundle::PwHashLimits::Interactive
            .with_exec(|| {
                client.new_seed(tag.into(), Some(passphrase.clone()), false)
            })
            .await
            .unwrap();

        println!("{:#?}", client.list_entries().await.unwrap());

        let seed_info_ref2 = client
            .new_seed("test-tag-2".into(), None, false)
            .await
            .unwrap();

        let (nonce, cipher) = client
            .crypto_box_xsalsa_by_pub_key(
                seed_info_ref.x25519_pub_key.clone(),
                seed_info_ref2.x25519_pub_key.clone(),
                None,
                b"hello"[..].into(),
            )
            .await
            .unwrap();

        let msg = client
            .crypto_box_xsalsa_open_by_pub_key(
                seed_info_ref.x25519_pub_key,
                seed_info_ref2.x25519_pub_key,
                None,
                nonce,
                cipher,
            )
            .await
            .unwrap();

        assert_eq!(b"hello", &*msg);

        let (nonce, cipher) = client
            .crypto_box_xsalsa_by_sign_pub_key(
                seed_info_ref.ed25519_pub_key.clone(),
                seed_info_ref2.ed25519_pub_key.clone(),
                None,
                b"world"[..].into(),
            )
            .await
            .unwrap();

        let msg = client
            .crypto_box_xsalsa_open_by_sign_pub_key(
                seed_info_ref.ed25519_pub_key,
                seed_info_ref2.ed25519_pub_key,
                None,
                nonce,
                cipher,
            )
            .await
            .unwrap();

        assert_eq!(b"world", &*msg);

        let data = Arc::new([1, 2, 3_u8]);
        let signature = client
            .sign_by_pub_key(
                seed_info_ref_deep.ed25519_pub_key.clone(),
                Some(passphrase),
                data.clone(),
            )
            .await
            .unwrap();
        assert!(seed_info_ref_deep
            .ed25519_pub_key
            .verify_detached(signature, sodoken::BufRead::from(&data[..]))
            .await
            .unwrap());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn in_proc_derive_seed_happy_path() {
        // set up a passphrase
        let passphrase1 = sodoken::BufRead::from(&b"passphrase1"[..]);
        let passphrase2 = sodoken::BufRead::from(&b"passphrase2"[..]);

        // create the config for the test server
        // the path is immaterial since we'll be using an in-memory store
        let config = Arc::new(
            hc_seed_bundle::PwHashLimits::Minimum
                .with_exec(|| {
                    LairServerConfigInner::new("/", passphrase1.clone())
                })
                .await
                .unwrap(),
        );

        // create an in-process keystore with an in-memory store
        let keystore = InProcKeystore::new(
            config,
            crate::mem_store::create_mem_store_factory(),
            passphrase1.clone(),
        )
        .await
        .unwrap();

        // create a client connection to the keystore
        let client = keystore.new_client().await.unwrap();

        // create a new seed
        let _ = client.new_seed("seed-0".into(), None, false).await.unwrap();

        // create a new seed
        let _ = client
            .new_seed("deepseed-0".into(), Some(passphrase1.clone()), false)
            .await
            .unwrap();

        client
            .derive_seed(
                "seed-0".into(),
                None,
                "deepseed-1".into(),
                Some(passphrase2),
                Box::new([1, 1]),
            )
            .await
            .unwrap();

        client
            .derive_seed(
                "deepseed-0".into(),
                Some(passphrase1),
                "seed-1".into(),
                None,
                Box::new([1, 2, 3, 5, 8]),
            )
            .await
            .unwrap();

        let seed = client.get_entry("seed-1".into()).await.unwrap();
        let deepseed = client.get_entry("deepseed-1".into()).await.unwrap();

        assert!(matches!(seed, LairEntryInfo::Seed { .. }));
        assert!(matches!(deepseed, LairEntryInfo::DeepLockedSeed { .. }));
    }
}
