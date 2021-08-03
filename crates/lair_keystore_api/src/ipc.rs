//! Ipc spawn functions.

use crate::actor::*;
use crate::internal::util::*;
use crate::*;

mod spawn_client_ipc;

/// Spawn a client Ipc connection.
pub async fn spawn_client_ipc(
    config: Arc<Config>,
) -> LairResult<(
    ghost_actor::GhostSender<LairClientApi>,
    LairClientEventReceiver,
)> {
    let (evt_send, evt_recv) = futures::channel::mpsc::channel(4096);

    let api_send = spawn_client_ipc::spawn_client_ipc(config, evt_send).await?;

    Ok((api_send, evt_recv))
}

/// Incoming Connection Receiver.
pub type IncomingIpcConnectionReceiver =
    futures::channel::mpsc::Receiver<LairClientEventSenderType>;

mod spawn_bind_server_ipc;

pub use crate::internal::ipc::Passphrase;

/// Callback for validating unlock passphrase.
pub type UnlockCb = Arc<
    dyn Fn(Passphrase) -> futures::future::BoxFuture<'static, LairResult<()>>
        + 'static
        + Send
        + Sync,
>;

/// Bind a server Ipc connection.
pub async fn spawn_bind_server_ipc<S>(
    config: Arc<Config>,
    api_sender: S,
    unlock_cb: UnlockCb,
) -> LairResult<()>
where
    S: ghost_actor::GhostChannelSender<LairClientApi>,
{
    spawn_bind_server_ipc::spawn_bind_server_ipc(config, api_sender, unlock_cb)
        .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal::crypto_box;
    use crate::internal::sign_ed25519;
    use crate::internal::wire::tests::TestVal;
    use crate::internal::x25519;
    use futures::{future::FutureExt, stream::StreamExt};
    use ghost_actor::GhostControlSender;

    fn init_tracing() {
        let _ = subscriber::set_global_default(
            tracing_subscriber::FmtSubscriber::builder()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::from_default_env(),
                )
                .compact()
                .finish(),
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_high_level_ipc() -> LairResult<()> {
        init_tracing();

        let tmpdir = tempfile::tempdir().unwrap();
        let config = Config::builder().set_root_path(tmpdir.path()).build();

        struct TestServer;
        impl ghost_actor::GhostControlHandler for TestServer {}
        impl ghost_actor::GhostHandler<LairClientApi> for TestServer {}
        impl LairClientApiHandler for TestServer {
            fn handle_lair_get_server_info(
                &mut self,
            ) -> LairClientApiHandlerResult<LairServerInfo> {
                Ok(async move { Ok(TestVal::test_val()) }.boxed().into())
            }
            fn handle_lair_get_last_entry_index(
                &mut self,
            ) -> LairClientApiHandlerResult<KeystoreIndex> {
                Ok(async move { Ok(TestVal::test_val()) }.boxed().into())
            }
            fn handle_lair_get_entry_type(
                &mut self,
                _keystore_index: KeystoreIndex,
            ) -> LairClientApiHandlerResult<LairEntryType> {
                Ok(async move { Ok(TestVal::test_val()) }.boxed().into())
            }
            fn handle_tls_cert_new_self_signed_from_entropy(
                &mut self,
                _options: TlsCertOptions,
            ) -> LairClientApiHandlerResult<(KeystoreIndex, CertSni, CertDigest)>
            {
                Ok(async move {
                    Ok((
                        TestVal::test_val(),
                        TestVal::test_val(),
                        TestVal::test_val(),
                    ))
                }
                .boxed()
                .into())
            }
            fn handle_tls_cert_get(
                &mut self,
                _keystore_index: KeystoreIndex,
            ) -> LairClientApiHandlerResult<(CertSni, CertDigest)> {
                Ok(async move { Ok((
                    TestVal::test_val(),
                    TestVal::test_val(),
                )) }.boxed().into())
            }
            fn handle_tls_cert_get_cert_by_index(
                &mut self,
                _keystore_index: KeystoreIndex,
            ) -> LairClientApiHandlerResult<Cert> {
                Ok(async move { Ok(TestVal::test_val()) }.boxed().into())
            }
            fn handle_tls_cert_get_cert_by_digest(
                &mut self,
                _cert_digest: CertDigest,
            ) -> LairClientApiHandlerResult<Cert> {
                Ok(async move { Ok(TestVal::test_val()) }.boxed().into())
            }
            fn handle_tls_cert_get_cert_by_sni(
                &mut self,
                _cert_sni: CertSni,
            ) -> LairClientApiHandlerResult<Cert> {
                Ok(async move { Ok(TestVal::test_val()) }.boxed().into())
            }
            fn handle_tls_cert_get_priv_key_by_index(
                &mut self,
                _keystore_index: KeystoreIndex,
            ) -> LairClientApiHandlerResult<CertPrivKey> {
                Ok(async move { Ok(TestVal::test_val()) }.boxed().into())
            }
            fn handle_tls_cert_get_priv_key_by_digest(
                &mut self,
                _cert_digest: CertDigest,
            ) -> LairClientApiHandlerResult<CertPrivKey> {
                Ok(async move { Ok(TestVal::test_val()) }.boxed().into())
            }
            fn handle_tls_cert_get_priv_key_by_sni(
                &mut self,
                _cert_sni: CertSni,
            ) -> LairClientApiHandlerResult<CertPrivKey> {
                Ok(async move { Ok(TestVal::test_val()) }.boxed().into())
            }
            fn handle_sign_ed25519_new_from_entropy(
                &mut self,
            ) -> LairClientApiHandlerResult<(
                KeystoreIndex,
                sign_ed25519::SignEd25519PubKey,
            )> {
                Ok(async move { Ok((
                    TestVal::test_val(),
                    TestVal::test_val(),
                )) }.boxed().into())
            }
            fn handle_sign_ed25519_get(
                &mut self,
                _keystore_index: KeystoreIndex,
            ) -> LairClientApiHandlerResult<sign_ed25519::SignEd25519PubKey>
            {
                Ok(async move { Ok(TestVal::test_val()) }.boxed().into())
            }
            fn handle_sign_ed25519_sign_by_index(
                &mut self,
                _keystore_index: KeystoreIndex,
                _message: Arc<Vec<u8>>,
            ) -> LairClientApiHandlerResult<sign_ed25519::SignEd25519Signature>
            {
                Ok(async move { Ok(TestVal::test_val()) }.boxed().into())
            }
            fn handle_sign_ed25519_sign_by_pub_key(
                &mut self,
                _pub_key: sign_ed25519::SignEd25519PubKey,
                _message: Arc<Vec<u8>>,
            ) -> LairClientApiHandlerResult<sign_ed25519::SignEd25519Signature>
            {
                Ok(async move { Ok(TestVal::test_val()) }.boxed().into())
            }
            fn handle_x25519_new_from_entropy(
                &mut self,
            ) -> LairClientApiHandlerResult<(KeystoreIndex, x25519::X25519PubKey)>
            {
                Ok(async move { Ok((
                    TestVal::test_val(),
                    TestVal::test_val(),
                )) }.boxed().into())
            }
            fn handle_x25519_get(
                &mut self,
                _keystore_index: KeystoreIndex,
            ) -> LairClientApiHandlerResult<x25519::X25519PubKey> {
                Ok(async move { Ok(TestVal::test_val()) }.boxed().into())
            }
            fn handle_crypto_box_by_index(
                &mut self,
                _keystore_index: KeystoreIndex,
                _recipient: x25519::X25519PubKey,
                _data: Arc<crypto_box::CryptoBoxData>,
            ) -> LairClientApiHandlerResult<crypto_box::CryptoBoxEncryptedData>
            {
                Ok(async move { Ok(TestVal::test_val()) }.boxed().into())
            }
            fn handle_crypto_box_by_pub_key(
                &mut self,
                _pub_key: x25519::X25519PubKey,
                _recipient: x25519::X25519PubKey,
                _data: Arc<crypto_box::CryptoBoxData>,
            ) -> LairClientApiHandlerResult<crypto_box::CryptoBoxEncryptedData>
            {
                Ok(async move { Ok(TestVal::test_val()) }.boxed().into())
            }
            fn handle_crypto_box_open_by_index(
                &mut self,
                _keystore_index: KeystoreIndex,
                _recipient: x25519::X25519PubKey,
                _data: Arc<crypto_box::CryptoBoxEncryptedData>,
            ) -> LairClientApiHandlerResult<Option<crypto_box::CryptoBoxData>>
            {
                Ok(async move { Ok(TestVal::test_val()) }.boxed().into())
            }
            fn handle_crypto_box_open_by_pub_key(
                &mut self,
                _pub_key: x25519::X25519PubKey,
                _recipient: x25519::X25519PubKey,
                _data: Arc<crypto_box::CryptoBoxEncryptedData>,
            ) -> LairClientApiHandlerResult<Option<crypto_box::CryptoBoxData>>
            {
                Ok(async move { Ok(TestVal::test_val()) }.boxed().into())
            }
        }

        let builder = ghost_actor::actor_builder::GhostActorBuilder::new();
        let api_sender = builder
            .channel_factory()
            .create_channel::<LairClientApi>()
            .await?;
        err_spawn("test-api-actor", async move {
            builder.spawn(TestServer).await.map_err(LairError::other)
        });

        let notify = Arc::new(tokio::sync::Notify::new());
        let notify_fut = notify.clone();
        let notify_fut = notify_fut.notified();

        let unlock_cb: UnlockCb = Arc::new(move |passphrase| {
            let notify = notify.clone();
            assert_eq!(b"test-val", &*passphrase.read_lock());
            async move {
                notify.notify_waiters();
                Ok(())
            }
            .boxed()
        });

        spawn_bind_server_ipc(config.clone(), api_sender, unlock_cb).await?;

        let (cli_send, mut cli_recv) = spawn_client_ipc(config).await?;

        err_spawn("test-evt-loop", async move {
            while let Some(msg) = cli_recv.next().await {
                match msg {
                    LairClientEvent::RequestUnlockPassphrase {
                        respond,
                        ..
                    } => {
                        respond.respond(Ok(
                            async move { Ok(TestVal::test_val()) }
                                .boxed()
                                .into(),
                        ));
                    }
                }
            }
            Ok(())
        });

        notify_fut.await;

        assert_eq!(
            LairServerInfo::test_val(),
            cli_send.lair_get_server_info().await?
        );
        assert_eq!(
            KeystoreIndex::test_val(),
            cli_send.lair_get_last_entry_index().await?
        );
        assert_eq!(
            LairEntryType::test_val(),
            cli_send.lair_get_entry_type(0.into()).await?
        );
        assert_eq!(
            (
                KeystoreIndex::test_val(),
                CertSni::test_val(),
                CertDigest::test_val(),
            ),
            cli_send
                .tls_cert_new_self_signed_from_entropy(
                    TlsCertOptions::default(),
                )
                .await?,
        );
        assert_eq!(
            (CertSni::test_val(), CertDigest::test_val(),),
            cli_send.tls_cert_get(0.into()).await?,
        );
        assert_eq!(
            Cert::test_val(),
            cli_send.tls_cert_get_cert_by_index(0.into()).await?,
        );
        assert_eq!(
            Cert::test_val(),
            cli_send
                .tls_cert_get_cert_by_digest(CertDigest::test_val())
                .await?,
        );
        assert_eq!(
            Cert::test_val(),
            cli_send
                .tls_cert_get_cert_by_sni(CertSni::test_val())
                .await?,
        );
        assert_eq!(
            CertPrivKey::test_val(),
            cli_send.tls_cert_get_priv_key_by_index(0.into()).await?,
        );
        assert_eq!(
            CertPrivKey::test_val(),
            cli_send
                .tls_cert_get_priv_key_by_digest(CertDigest::test_val())
                .await?,
        );
        assert_eq!(
            CertPrivKey::test_val(),
            cli_send
                .tls_cert_get_priv_key_by_sni(CertSni::test_val())
                .await?,
        );
        assert_eq!(
            (
                KeystoreIndex::test_val(),
                sign_ed25519::SignEd25519PubKey::test_val(),
            ),
            cli_send.sign_ed25519_new_from_entropy().await?,
        );
        assert_eq!(
            sign_ed25519::SignEd25519PubKey::test_val(),
            cli_send.sign_ed25519_get(0.into()).await?,
        );
        assert_eq!(
            sign_ed25519::SignEd25519Signature::test_val(),
            cli_send
                .sign_ed25519_sign_by_index(0.into(), b"".to_vec().into())
                .await?,
        );
        assert_eq!(
            sign_ed25519::SignEd25519Signature::test_val(),
            cli_send
                .sign_ed25519_sign_by_pub_key(
                    sign_ed25519::SignEd25519PubKey::test_val(),
                    b"".to_vec().into()
                )
                .await?,
        );
        assert_eq!(
            (KeystoreIndex::test_val(), x25519::X25519PubKey::test_val(),),
            cli_send.x25519_new_from_entropy().await?,
        );
        assert_eq!(
            x25519::X25519PubKey::test_val(),
            cli_send.x25519_get(0.into()).await?,
        );

        cli_send.ghost_actor_shutdown().await?;
        drop(tmpdir);

        Ok(())
    }
}
