//! client / server keystore items for dealing with ipc keystores,
//! both unix domain sockets and windows named pipes.

use crate::*;
use futures::stream::StreamExt;
use std::future::Future;

mod raw_ipc;

/// server keystore item for dealing with ipc keystores,
/// both unix domain sockets and windows named pipes.
#[derive(Clone)]
pub struct IpcKeystoreServer {
    config: LairServerConfig,
    srv_hnd: crate::lair_server::LairServer,
}

impl IpcKeystoreServer {
    /// Construct a new IpcKeystoreServer instance.
    pub fn new<P>(
        config: LairServerConfig,
        store_factory: LairStoreFactory,
        passphrase: P,
    ) -> impl Future<Output = LairResult<Self>> + 'static + Send
    where
        P: Into<sodoken::BufRead> + 'static + Send,
    {
        async move {
            let con_recv = raw_ipc::ipc_bind(config.clone()).await?;

            // set up our server handler
            let srv_hnd = crate::lair_server::spawn_lair_server_task(
                config.clone(),
                "lair-keystore-ipc".into(),
                crate::LAIR_VER.into(),
                store_factory,
                passphrase.into(),
            )
            .await?;

            {
                // set up a tokio task for accepting incoming connections
                let srv_hnd = srv_hnd.clone();
                tokio::task::spawn(async move {
                    let srv_hnd = &srv_hnd;
                    con_recv.for_each_concurrent(4096, |incoming| async move {
                        let (send, recv) = match incoming {
                            Err(e) => {
                                tracing::error!("Error accepting incoming ipc connection: {:?}", e);
                                return;
                            }
                            Ok(r) => r,
                        };
                        if let Err(e) = srv_hnd.accept(send, recv).await {
                            tracing::error!("Error accepting incoming ipc connection: {:?}", e);
                        }
                    }).await;

                    tracing::error!(
                        "IpcKeystoreServer ipc_raw con recv loop ended!"
                    );
                });
            }

            Ok(Self { config, srv_hnd })
        }
    }

    /// get a handle to the LairStore instantiated by this server,
    /// may error if a store has not yet been created.
    pub fn store(
        &self,
    ) -> impl Future<Output = LairResult<LairStore>> + 'static + Send {
        self.srv_hnd.store()
    }

    /// Get the config used by the LairServer held by this IpcKeystoreServer.
    pub fn get_config(&self) -> LairServerConfig {
        self.config.clone()
    }
}

/// Client connection options for customizing how to connect to an ipc server.
pub struct IpcKeystoreClientOptions {
    /// the ipc url ('unix://' or 'named-pipe:\\.\pipe\[yada]') to connect to
    pub connection_url: url::Url,
    /// the passphrase to use to connect
    pub passphrase: sodoken::BufRead,
    /// Require the client and server to have exactly matching
    /// client / server versions.
    pub exact_client_server_version_match: bool,
}

/// Connect to an IpcKeystoreServer instance via
/// unix domain socket on linux/macOs or named pipe on windows.
/// This constructor will first validate server authenticity,
/// then unlock the connection with the supplied passphrase.
pub fn ipc_keystore_connect<P>(
    connection_url: url::Url,
    passphrase: P,
) -> impl Future<Output = LairResult<LairClient>> + 'static + Send
where
    P: Into<sodoken::BufRead> + 'static + Send,
{
    let passphrase = passphrase.into();
    ipc_keystore_connect_options(IpcKeystoreClientOptions {
        connection_url,
        passphrase,
        exact_client_server_version_match: false,
    })
}

/// Connect to an IpcKeystoreServer instance via
/// unix domain socket on linux/macOs or named pipe on windows.
pub fn ipc_keystore_connect_options(
    opts: IpcKeystoreClientOptions,
) -> impl Future<Output = LairResult<LairClient>> + 'static + Send {
    async move {
        let server_pub_key =
            get_server_pub_key_from_connection_url(&opts.connection_url)?;

        // establish the raw ipc connection
        let (send, recv) =
            raw_ipc::ipc_connect(opts.connection_url.clone()).await?;

        // wrap this connection up as a LairClient
        let cli_hnd = crate::lair_client::async_io::new_async_io_lair_client(
            send,
            recv,
            server_pub_key.cloned_inner().into(),
        )
        .await?;

        // verify the server and unlock the connection
        let ver = cli_hnd.hello(server_pub_key).await?;
        priv_check_hello_ver(&opts, &ver)?;
        cli_hnd.unlock(opts.passphrase).await?;

        Ok(cli_hnd)
    }
}

fn priv_check_hello_ver(
    opts: &IpcKeystoreClientOptions,
    server_version: &str,
) -> LairResult<()> {
    if opts.exact_client_server_version_match
        && server_version != crate::LAIR_VER
    {
        return Err(format!(
            "Invalid lair server version, this client requires '{}', but got '{}'.",
            crate::LAIR_VER,
            server_version,
        ).into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test(flavor = "multi_thread")]
    async fn ipc_happy_path() {
        let tmp_dir = tempdir::TempDir::new("lair_ipc_keystore_test").unwrap();

        // set up a passphrase
        let passphrase = sodoken::BufRead::from(&b"passphrase"[..]);

        // create the config for the test server
        let config = Arc::new(
            hc_seed_bundle::PwHashLimits::Minimum
                .with_exec(|| {
                    LairServerConfigInner::new(
                        tmp_dir.path(),
                        passphrase.clone(),
                    )
                })
                .await
                .unwrap(),
        );

        // create an in-process keystore with an in-memory store
        let keystore = IpcKeystoreServer::new(
            config,
            crate::mem_store::create_mem_store_factory(),
            passphrase.clone(),
        )
        .await
        .unwrap();

        let config = keystore.get_config();
        println!("{}", config);

        // create a client connection
        let client =
            ipc_keystore_connect(config.connection_url.clone(), passphrase)
                .await
                .unwrap();

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

        let entry = client.get_entry("test-tag".into()).await.unwrap();

        match entry {
            LairEntryInfo::Seed { tag, seed_info } => {
                assert_eq!("test-tag", &*tag);
                assert_eq!(seed_info, seed_info_ref);
            }
            oth => panic!("unexpected: {:?}", oth),
        }

        let sig = client
            .sign_by_pub_key(
                seed_info_ref.ed25519_pub_key.clone(),
                None,
                b"hello".to_vec().into(),
            )
            .await
            .unwrap();
        assert!(seed_info_ref
            .ed25519_pub_key
            .verify_detached(sig, &b"hello"[..])
            .await
            .unwrap());

        // create a new deep-locked seed
        let _seed_info_ref_deep = hc_seed_bundle::PwHashLimits::Minimum
            .with_exec(|| {
                client.new_seed(
                    "test-tag-deep".into(),
                    Some(sodoken::BufRead::from(&b"deep"[..])),
                )
            })
            .await
            .unwrap();

        // create a new tls certificate
        let cert_info =
            client.new_wka_tls_cert("test-cert".into()).await.unwrap();
        println!("{:#?}", cert_info);

        let priv_key = client
            .get_wka_tls_cert_priv_key("test-cert".into())
            .await
            .unwrap();
        println!("got priv key: {} bytes", priv_key.len());

        println!("{:#?}", client.list_entries().await.unwrap());
    }
}
