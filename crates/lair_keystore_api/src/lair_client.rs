//! interact with a lair keystore

use crate::lair_core::traits::*;
use crate::lair_core::*;
use crate::LairResult2 as LairResult;
use futures::future::{BoxFuture, FutureExt};
use futures::stream::StreamExt;
use ghost_actor::dependencies::tracing;
use parking_lot::RwLock;
use std::future::Future;
use std::sync::Arc;

/// Traits related to LairClient. Unless you're writing a new
/// implementation, you probably don't need these.
pub mod traits {
    use super::*;

    /// Defines the lair client API.
    pub trait AsLairClient: 'static + Send + Sync {
        /// Return the encryption context key for passphrases, etc.
        fn get_enc_ctx_key(&self) -> sodoken::BufReadSized<32>;

        /// Return the decryption context key for passphrases, etc.
        fn get_dec_ctx_key(&self) -> sodoken::BufReadSized<32>;

        /// Handle a lair client request
        fn request(
            &self,
            request: LairApiEnum,
        ) -> BoxFuture<'static, LairResult<LairApiEnum>>;
    }
}
use traits::*;

/// Concrete lair client struct.
#[derive(Clone)]
pub struct LairClient(pub Arc<dyn AsLairClient>);

fn priv_lair_api_request<R: AsLairRequest>(
    client: &dyn AsLairClient,
    request: R,
) -> impl Future<Output = LairResult<R::Response>> + 'static + Send
where
    one_err::OneErr: std::convert::From<
        <<R as AsLairRequest>::Response as std::convert::TryFrom<
            LairApiEnum,
        >>::Error,
    >,
{
    let request = request.into_api_enum();
    let fut = AsLairClient::request(client, request);
    async move {
        let res = fut.await?;
        match res {
            LairApiEnum::ResError(err) => Err(err.error),
            res => {
                let res: R::Response = std::convert::TryFrom::try_from(res)?;
                Ok(res)
            }
        }
    }
}

impl LairClient {
    /// Return the encryption context key for passphrases, etc.
    pub fn get_enc_ctx_key(&self) -> sodoken::BufReadSized<32> {
        AsLairClient::get_enc_ctx_key(&*self.0)
    }

    /// Return the decryption context key for passphrases, etc.
    pub fn get_dec_ctx_key(&self) -> sodoken::BufReadSized<32> {
        AsLairClient::get_dec_ctx_key(&*self.0)
    }

    /// Handle a generic lair client request.
    pub fn request<R: AsLairRequest>(
        &self,
        request: R,
    ) -> impl Future<Output = LairResult<R::Response>> + 'static + Send
    where
        one_err::OneErr: std::convert::From<
            <<R as AsLairRequest>::Response as std::convert::TryFrom<
                LairApiEnum,
            >>::Error,
        >,
    {
        priv_lair_api_request(&*self.0, request)
    }

    /// Send the hello message to establish server authenticity.
    /// Check with your implementation before invoking this...
    /// it likely handles this for you in its constructor.
    pub fn hello(
        &self,
        nonce: BinData,
    ) -> impl Future<Output = LairResult<LairApiResHello>> + 'static + Send
    {
        let inner = self.0.clone();
        async move {
            let req = LairApiReqHello::new(nonce);
            let res = priv_lair_api_request(&*inner, req).await?;
            Ok(res)
        }
    }

    /// Send the unlock request to unlock / communicate with the server.
    /// (this verifies client authenticity)
    /// Check with your implementation before invoking this...
    /// it likely handles this for you in its constructor.
    pub fn unlock(
        &self,
        passphrase: sodoken::BufRead,
    ) -> impl Future<Output = LairResult<()>> + 'static + Send {
        let inner = self.0.clone();
        async move {
            let key = inner.get_enc_ctx_key();
            let passphrase = SecretData::encrypt(key, passphrase).await?;
            let req = LairApiReqUnlock::new(passphrase);
            let _res = priv_lair_api_request(&*inner, req).await?;
            Ok(())
        }
    }

    /// Request a list of entries from lair.
    pub fn list_entries(
        &self,
    ) -> impl Future<Output = LairResult<Vec<LairEntryInfo>>> + 'static + Send
    {
        let r_fut =
            priv_lair_api_request(&*self.0, LairApiReqListEntries::new());
        async move {
            let r = r_fut.await?;
            Ok(r.entry_list)
        }
    }

    /// Return the EntryInfo for a given tag, or error if no such tag.
    pub fn get_entry(
        &self,
        _tag: Arc<str>,
    ) -> impl Future<Output = LairResult<LairEntryInfo>> + 'static + Send {
        async move { unimplemented!() }
    }

    /// Instruct lair to generate a new seed from cryptographically secure
    /// random data with given tag. If the seed should be deeply locked,
    /// supply the deep_lock_passphrase as well.
    pub fn new_seed(
        &self,
        tag: Arc<str>,
        deep_lock_passphrase: Option<sodoken::BufRead>,
    ) -> impl Future<Output = LairResult<SeedInfo>> + 'static + Send {
        let inner = self.0.clone();
        async move {
            let secret = match deep_lock_passphrase {
                None => None,
                Some(pass) => {
                    let key = inner.get_enc_ctx_key();
                    Some(SecretData::encrypt(key, pass).await?)
                }
            };
            let req = LairApiReqNewSeed::new(tag, secret);
            let res = priv_lair_api_request(&*inner, req).await?;
            Ok(res.seed_info)
        }
    }

    // uhhhh... clippy?? [u32] by itself is not sized... so, yes
    // this *does* have to be Boxed...
    #[allow(clippy::boxed_local)]
    /// Derive a pre-existing key identified by given src_tag, with given
    /// derivation path, storing the final resulting sub-seed with
    /// the given dst_tag.
    pub fn derive_seed(
        &self,
        _src_tag: Arc<str>,
        _src_deep_lock_passphrase: Option<sodoken::BufRead>,
        _dst_tag: Arc<str>,
        _dst_deep_lock_passphrase: Option<sodoken::BufRead>,
        _derivation: Box<[u32]>,
    ) -> impl Future<Output = LairResult<SeedInfo>> + 'static + Send {
        async move { unimplemented!() }
    }

    /// Generate a signature for given data, with the ed25519 keypair
    /// derived from seed identified by the given ed25519 pubkey.
    pub fn sign_by_pub_key(
        &self,
        _pub_key: Ed25519PubKey,
        _deep_lock_passphrase: Option<sodoken::BufRead>,
        _data: Arc<[u8]>,
    ) -> impl Future<Output = LairResult<Ed25519Signature>> + 'static + Send
    {
        async move { unimplemented!() }
    }

    /// Instruct lair to generate a new well-known-authority signed TLS cert.
    /// This is a lot like a self-signed certificate, but slightly easier to
    /// work with in that it allows registering a single well-known-authority
    /// as a certificate authority which will respect multiple certs.
    pub fn new_wka_tls_cert(
        &self,
        _tag: Arc<str>,
    ) -> impl Future<Output = LairResult<CertInfo>> + 'static + Send {
        async move { unimplemented!() }
    }

    /// Fetch the private key associated with a wka_tls_cert entry.
    /// Will error if the entry specified by 'tag' is not a wka_tls_cert.
    pub fn get_wka_tls_cert_priv_key(
        &self,
        _tag: Arc<str>,
    ) -> impl Future<Output = LairResult<sodoken::BufRead>> + 'static + Send
    {
        async move { unimplemented!() }
    }
}

/// wrap up raw async connection handles into a LairClient connection instance.
pub fn wrap_raw_lair_client<S, R>(
    send: S,
    recv: R,
) -> impl Future<Output = LairResult<LairClient>> + 'static + Send
where
    S: tokio::io::AsyncWrite + 'static + Send + Unpin,
    R: tokio::io::AsyncRead + 'static + Send + Unpin,
{
    async move {
        let (send, recv) =
            crate::sodium_secretstream::new_s3_pair::<LairApiEnum, _, _>(
                send, recv, false,
            )
            .await?;

        let enc_ctx_key = <sodoken::BufWriteSized<32>>::new_mem_locked()?;
        sodoken::kdf::derive_from_key(
            enc_ctx_key.clone(),
            142,
            *b"ToSrvCxK",
            send.get_enc_ctx_key(),
        )?;
        let enc_ctx_key = enc_ctx_key.to_read_sized();

        let dec_ctx_key = <sodoken::BufWriteSized<32>>::new_mem_locked()?;
        sodoken::kdf::derive_from_key(
            dec_ctx_key.clone(),
            42,
            *b"ToCliCxK",
            send.get_dec_ctx_key(),
        )?;
        let dec_ctx_key = dec_ctx_key.to_read_sized();

        let inner = CliInner {
            enc_ctx_key: enc_ctx_key.clone(),
            dec_ctx_key: dec_ctx_key.clone(),
            send: send.clone(),
        };

        let inner = Arc::new(RwLock::new(inner));

        {
            let inner = inner.clone();
            tokio::task::spawn(async move {
                let inner = &inner;
                let enc_ctx_key = &enc_ctx_key;
                let dec_ctx_key = &dec_ctx_key;
                let send = &send;
                recv.for_each_concurrent(4096, move |incoming| async move {
                    let incoming = match incoming {
                        Err(e) => {
                            tracing::warn!("incoming channel error: {:?}", e);
                            return;
                        }
                        Ok(incoming) => incoming,
                    };

                    if let Err(e) = priv_dispatch_incoming(
                        inner,
                        enc_ctx_key,
                        dec_ctx_key,
                        incoming,
                    )
                    .await
                    {
                        tracing::warn!("error handling response: {:?}", e);
                    }
                })
                .await;
                let _ = send.shutdown().await;
                tracing::warn!("lair connection recv loop ended");
                // TODO - kill any pending requests - they won't ever get response.
            });
        }

        Ok(LairClient(Arc::new(Cli(inner))))
    }
}

// -- private -- //

struct CliInner {
    enc_ctx_key: sodoken::BufReadSized<32>,
    dec_ctx_key: sodoken::BufReadSized<32>,
    send: crate::sodium_secretstream::S3Sender<LairApiEnum>,
}

struct Cli(Arc<RwLock<CliInner>>);

fn priv_dispatch_incoming<'a>(
    _inner: &'a Arc<RwLock<CliInner>>,
    _enc_ctx_key: &'a sodoken::BufReadSized<32>,
    _dec_ctx_key: &'a sodoken::BufReadSized<32>,
    _incoming: LairApiEnum,
) -> impl Future<Output = LairResult<()>> + 'a + Send {
    async move { unimplemented!() }
}

impl AsLairClient for Cli {
    fn get_enc_ctx_key(&self) -> sodoken::BufReadSized<32> {
        self.0.read().enc_ctx_key.clone()
    }

    fn get_dec_ctx_key(&self) -> sodoken::BufReadSized<32> {
        self.0.read().dec_ctx_key.clone()
    }

    fn request(
        &self,
        request: LairApiEnum,
    ) -> BoxFuture<'static, LairResult<LairApiEnum>> {
        let send = self.0.read().send.clone();
        async move {
            send.send(request).await?;
            unimplemented!()
        }
        .boxed()
    }
}
