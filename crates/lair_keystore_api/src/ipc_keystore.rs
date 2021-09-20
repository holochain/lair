//! client / server keystore items for dealing with ipc keystores,
//! both unix domain sockets and windows named pipes.

use crate::lair_client::LairClient;
use crate::lair_core::*;
use crate::LairResult2 as LairResult;
use futures::stream::StreamExt;
use ghost_actor::dependencies::tracing;
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
    /// The internal server will initially be LOCKED.
    /// You must call 'unlock' if you wish to "interactively" unlock.
    pub fn new(
        config: LairServerConfig,
        store_factory: LairStoreFactory,
    ) -> impl Future<Output = LairResult<Self>> + 'static + Send {
        async move {
            let con_recv = raw_ipc::ipc_bind(config.clone()).await?;

            let srv_hnd = crate::lair_server::spawn_lair_server_task(
                config.clone(),
                "lair-keystore-ipc".into(),
                crate::LAIR_VER.into(),
                store_factory,
            )
            .await?;

            {
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

    /// "interactively" unlock this keystore from the server side.
    /// This is the preferred way to unlock a keystore... if unlocked
    /// through the client api, the client has no way to know if this
    /// server is authentic before potentially passing the passphrase
    /// to a third party attacker (MitM).
    pub fn unlock<P>(
        &self,
        passphrase: P,
    ) -> impl Future<Output = LairResult<()>> + 'static + Send
    where
        P: Into<sodoken::BufRead> + 'static + Send,
    {
        self.srv_hnd.unlock(passphrase.into())
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
    /// If it is not possible to unlock the server "interactively" on
    /// the server side... we can unlock it from the client side without
    /// validating the server's authenticity...
    /// If the server is NOT authentic, we will get an error, but we
    /// also will have supplied our passphrase to an attacker.
    pub danger_unlock_without_server_validate: bool,
}

/// client keystore item for dealing with ipc keystores,
/// both unix domain sockets and windows named pipes.
#[derive(Clone)]
pub struct IpcKeystoreClient {}

impl IpcKeystoreClient {
    /// Connect to an IpcKeystoreServer instance via
    /// unix domain socket on linux/macOs or named pipe on windows.
    /// This constructor will first validate server authenticity,
    /// then unlock the connection with the supplied passphrase.
    pub fn connect<P>(
        connection_url: url::Url,
        passphrase: P,
    ) -> impl Future<Output = LairResult<LairClient>> + 'static + Send
    where
        P: Into<sodoken::BufRead> + 'static + Send,
    {
        let passphrase = passphrase.into();
        Self::connect_options(IpcKeystoreClientOptions {
            connection_url,
            passphrase,
            exact_client_server_version_match: false,
            danger_unlock_without_server_validate: false,
        })
    }

    /// Connect to an IpcKeystoreServer instance via
    /// unix domain socket on linux/macOs or named pipe on windows.
    pub fn connect_options(
        opts: IpcKeystoreClientOptions,
    ) -> impl Future<Output = LairResult<LairClient>> + 'static + Send {
        async move {
            let server_pub_key =
                get_server_pub_key_from_connection_url(&opts.connection_url)?;
            let (send, recv) =
                raw_ipc::ipc_connect(opts.connection_url.clone()).await?;
            let cli_hnd =
                crate::lair_client::wrap_raw_lair_client(send, recv).await?;
            if opts.danger_unlock_without_server_validate {
                // even if they tell us to do this backwards,
                // let's at least try to do it correctly to start
                match cli_hnd.hello(server_pub_key.clone()).await {
                    Ok(ver) => {
                        priv_check_hello_ver(&opts, &ver)?;
                        // hey, it worked, unlock and proceed
                        cli_hnd.unlock(opts.passphrase.clone()).await?;
                    }
                    Err(e) if e.str_kind() == "KestoreLocked" => {
                        // lame, the server really is not unlocked...
                        // unlock, but some attacker may get our passphrase
                        cli_hnd.unlock(opts.passphrase.clone()).await?;
                        // now do the verification, and hope it was
                        // the correct server
                        let ver = cli_hnd.hello(server_pub_key).await?;
                        priv_check_hello_ver(&opts, &ver)?;
                    }
                    Err(e) => return Err(e),
                }
            } else {
                let ver = cli_hnd.hello(server_pub_key).await?;
                priv_check_hello_ver(&opts, &ver)?;
                cli_hnd.unlock(opts.passphrase).await?;
            }

            Ok(cli_hnd)
        }
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
        // the path is immaterial since we'll be using an in-memory store
        let config = Arc::new(
            hc_seed_bundle::PwHashLimits::Interactive
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
        )
        .await
        .unwrap();

        let config = keystore.get_config();
        println!("{}", config);

        // unlock the keystore "interactively" from the server side
        keystore.unlock(passphrase.clone()).await.unwrap();

        // create a client connection
        let client = IpcKeystoreClient::connect(
            config.connection_url.clone(),
            passphrase,
        )
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

        // create a new deep-locked seed
        let _seed_info_ref_deep = hc_seed_bundle::PwHashLimits::Interactive
            .with_exec(|| {
                client.new_seed(
                    "test-tag-deep".into(),
                    Some(sodoken::BufRead::from(&b"deep"[..])),
                )
            })
            .await
            .unwrap();

        println!("{:#?}", client.list_entries().await.unwrap());

        tmp_dir.close().unwrap();
    }
}
