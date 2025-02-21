//! Items for connecting and interacting with a lair keystore as a client.

use crate::dependencies::one_err::OneErr;
use crate::lair_api::api_traits::*;
use crate::*;
use client_traits::*;
use futures::future::{BoxFuture, FutureExt};
use futures::stream::StreamExt;
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;

/// Traits related to LairClient. Unless you're writing a new
/// implementation, you probably don't need these.
pub mod client_traits {
    use super::*;

    /// Object-safe lair client trait. Implement this to provide a new
    /// lair client backend implementation.
    pub trait AsLairClient: 'static + Send + Sync {
        /// Return the encryption context key for passphrases, etc.
        fn get_enc_ctx_key(&self) -> SharedSizedLockedArray<32>;

        /// Return the decryption context key for passphrases, etc.
        fn get_dec_ctx_key(&self) -> SharedSizedLockedArray<32>;

        /// Shutdown the client connection.
        fn shutdown(&self) -> BoxFuture<'static, LairResult<()>>;

        /// Handle a lair client request
        fn request(
            &self,
            request: LairApiEnum,
        ) -> BoxFuture<'static, LairResult<LairApiEnum>>;
    }
}

/// A lair keystore client handle. Use this to make requests of the keystore.
#[derive(Clone)]
pub struct LairClient(pub Arc<dyn AsLairClient>);

/// Helper fn that auto matches responses with request type,
/// and converts 'Error' type messages into actual Err results.
fn priv_lair_api_request<R: AsLairRequest>(
    client: &dyn AsLairClient,
    request: R,
) -> impl Future<Output = LairResult<R::Response>> + 'static + Send
where
    OneErr: From<
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
    pub fn get_enc_ctx_key(&self) -> SharedSizedLockedArray<32> {
        AsLairClient::get_enc_ctx_key(&*self.0)
    }

    /// Return the decryption context key for passphrases, etc.
    pub fn get_dec_ctx_key(&self) -> SharedSizedLockedArray<32> {
        AsLairClient::get_dec_ctx_key(&*self.0)
    }

    /// Shutdown the client connection.
    pub fn shutdown(
        &self,
    ) -> impl Future<Output = LairResult<()>> + 'static + Send {
        AsLairClient::shutdown(&*self.0)
    }

    /// Handle a generic lair client request.
    pub fn request<R: AsLairRequest>(
        &self,
        request: R,
    ) -> impl Future<Output = LairResult<R::Response>> + 'static + Send
    where
        OneErr: From<
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
        expected_server_pub_key: BinDataSized<32>,
    ) -> impl Future<Output = LairResult<Arc<str>>> + 'static + Send {
        let inner = self.0.clone();
        async move {
            // build / send the message
            let req = LairApiReqHello::new();
            let res = priv_lair_api_request(&*inner, req).await?;

            // expect the expected server pub key
            if res.server_pub_key != expected_server_pub_key {
                return Err(one_err::OneErr::with_message(
                    "ServerPubKeyMismatch",
                    format!(
                        "expected {} != returned {}",
                        expected_server_pub_key, res.server_pub_key,
                    ),
                ));
            }

            Ok(res.version)
        }
    }

    /// Send the unlock request to unlock / communicate with the server.
    /// (this verifies client authenticity)
    /// Check with your implementation before invoking this...
    /// it likely handles this for you in its constructor.
    pub fn unlock(
        &self,
        passphrase: SharedLockedArray,
    ) -> impl Future<Output = LairResult<()>> + 'static + Send {
        let inner = self.0.clone();
        async move {
            let passphrase =
                encrypt_passphrase(passphrase, inner.get_enc_ctx_key()).await?;
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
        tag: Arc<str>,
    ) -> impl Future<Output = LairResult<LairEntryInfo>> + 'static + Send {
        let inner = self.0.clone();
        async move {
            let req = LairApiReqGetEntry::new(tag);
            let res = priv_lair_api_request(&*inner, req).await?;
            Ok(res.entry_info)
        }
    }

    /// Instruct lair to generate a new seed from cryptographically secure
    /// random data with given tag. If the seed should be deeply locked,
    /// supply the deep_lock_passphrase as well.
    /// Respects hc_seed_bundle::PwHashLimits.
    pub fn new_seed(
        &self,
        tag: Arc<str>,
        deep_lock_passphrase: Option<SharedLockedArray>,
        exportable: bool,
    ) -> impl Future<Output = LairResult<SeedInfo>> + 'static + Send {
        let limits = PwHashLimits::current();
        let inner = self.0.clone();
        async move {
            // if this is to be a deep locked seed / encrypt the passphrase
            let secret = match deep_lock_passphrase {
                None => None,
                Some(pass) => {
                    let passphrase =
                        encrypt_passphrase(pass, inner.get_enc_ctx_key())
                            .await?;
                    Some(DeepLockPassphrase::new(passphrase, limits))
                }
            };
            let req = LairApiReqNewSeed::new(tag, secret, exportable);
            let res = priv_lair_api_request(&*inner, req).await?;
            Ok(res.seed_info)
        }
    }

    /// Export seeds (that are marked "exportable") by using the
    /// x25519xsalsa20poly1305 "crypto_box" algorithm.
    pub fn export_seed_by_tag(
        &self,
        tag: Arc<str>,
        sender_pub_key: X25519PubKey,
        recipient_pub_key: X25519PubKey,
        deep_lock_passphrase: Option<SharedLockedArray>,
    ) -> impl Future<Output = LairResult<([u8; 24], Arc<[u8]>)>> + 'static + Send
    {
        let inner = self.0.clone();
        async move {
            // if this is a deep locked seed, we need to encrypt the passphrase
            let secret = match deep_lock_passphrase {
                None => None,
                Some(pass) => Some(
                    encrypt_passphrase(pass, inner.get_enc_ctx_key()).await?,
                ),
            };
            let req = LairApiReqExportSeedByTag::new(
                tag,
                sender_pub_key,
                recipient_pub_key,
                secret,
            );
            let res = priv_lair_api_request(&*inner, req).await?;
            Ok((res.nonce, res.cipher))
        }
    }

    /// Import a seed encrypted via x25519xsalsa20poly1305 secretbox.
    /// Note it is 100% valid to co-opt this function to allow importing
    /// seeds that have been generated via custom algorithms, but
    /// you take responsibility for those security concerns.
    /// Respects hc_seed_bundle::PwHashLimits.
    #[allow(clippy::too_many_arguments)]
    pub fn import_seed(
        &self,
        sender_pub_key: X25519PubKey,
        recipient_pub_key: X25519PubKey,
        deep_lock_passphrase: Option<SharedLockedArray>,
        nonce: [u8; 24],
        cipher: Arc<[u8]>,
        tag: Arc<str>,
        exportable: bool,
    ) -> impl Future<Output = LairResult<SeedInfo>> + 'static + Send {
        let limits = hc_seed_bundle::PwHashLimits::current();
        let inner = self.0.clone();
        async move {
            // if this is to be a deep locked seed / encrypt the passphrase
            let secret = match deep_lock_passphrase {
                None => None,
                Some(pass) => {
                    let secret =
                        encrypt_passphrase(pass, inner.get_enc_ctx_key())
                            .await?;
                    Some(DeepLockPassphrase::new(secret, limits))
                }
            };
            let req = LairApiReqImportSeed::new(
                sender_pub_key,
                recipient_pub_key,
                secret,
                nonce,
                cipher,
                tag,
                exportable,
            );
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
    /// Respects hc_seed_bundle::PwHashLimits.
    pub fn derive_seed(
        &self,
        src_tag: Arc<str>,
        src_deep_lock_passphrase: Option<SharedLockedArray>,
        dst_tag: Arc<str>,
        dst_deep_lock_passphrase: Option<SharedLockedArray>,
        derivation_path: Box<[u32]>,
    ) -> impl Future<Output = LairResult<SeedInfo>> + 'static + Send {
        let inner = self.0.clone();
        let limits = PwHashLimits::current();

        async move {
            let src_deep_lock_passphrase =
                if let Some(p) = src_deep_lock_passphrase {
                    Some(DeepLockPassphrase::new(
                        encrypt_passphrase(p, inner.get_enc_ctx_key()).await?,
                        limits,
                    ))
                } else {
                    None
                };
            let dst_deep_lock_passphrase =
                if let Some(p) = dst_deep_lock_passphrase {
                    Some(DeepLockPassphrase::new(
                        encrypt_passphrase(p, inner.get_enc_ctx_key()).await?,
                        limits,
                    ))
                } else {
                    None
                };
            let req = LairApiReqDeriveSeed::new(
                src_tag,
                src_deep_lock_passphrase,
                dst_tag,
                dst_deep_lock_passphrase,
                derivation_path,
            );
            let res = priv_lair_api_request(&*inner, req).await?;
            Ok(res.seed_info)
        }
    }

    /// Generate a signature for given data, with the ed25519 keypair
    /// derived from seed identified by the given ed25519 pubkey.
    pub fn sign_by_pub_key(
        &self,
        pub_key: Ed25519PubKey,
        deep_lock_passphrase: Option<SharedLockedArray>,
        data: Arc<[u8]>,
    ) -> impl Future<Output = LairResult<Ed25519Signature>> + 'static + Send
    {
        let inner = self.0.clone();
        async move {
            // if this is a deep locked seed, we need to encrypt the passphrase
            let secret = match deep_lock_passphrase {
                None => None,
                Some(pass) => Some(
                    encrypt_passphrase(pass, inner.get_enc_ctx_key()).await?,
                ),
            };
            let req = LairApiReqSignByPubKey::new(pub_key, secret, data);
            let res = priv_lair_api_request(&*inner, req).await?;
            Ok(res.signature)
        }
    }

    /// Encrypt data for a target recipient using the
    /// x25519xsalsa20poly1305 "crypto_box" algorithm.
    pub fn crypto_box_xsalsa_by_pub_key(
        &self,
        sender_pub_key: X25519PubKey,
        recipient_pub_key: X25519PubKey,
        deep_lock_passphrase: Option<SharedLockedArray>,
        data: Arc<[u8]>,
    ) -> impl Future<Output = LairResult<([u8; 24], Arc<[u8]>)>> + 'static + Send
    {
        let inner = self.0.clone();
        async move {
            // if this is a deep locked seed, we need to encrypt the passphrase
            let secret = match deep_lock_passphrase {
                None => None,
                Some(pass) => Some(
                    encrypt_passphrase(pass, inner.get_enc_ctx_key()).await?,
                ),
            };
            let req = LairApiReqCryptoBoxXSalsaByPubKey::new(
                sender_pub_key,
                recipient_pub_key,
                secret,
                data,
            );
            let res = priv_lair_api_request(&*inner, req).await?;
            Ok((res.nonce, res.cipher))
        }
    }

    /// Decrypt data from a target sender using the
    /// x25519xsalsa20poly1305 "crypto_box_open" algorithm.
    pub fn crypto_box_xsalsa_open_by_pub_key(
        &self,
        sender_pub_key: X25519PubKey,
        recipient_pub_key: X25519PubKey,
        deep_lock_passphrase: Option<SharedLockedArray>,
        nonce: [u8; 24],
        cipher: Arc<[u8]>,
    ) -> impl Future<Output = LairResult<Arc<[u8]>>> + 'static + Send {
        let inner = self.0.clone();
        async move {
            // if this is a deep locked seed, we need to encrypt the passphrase
            let secret = match deep_lock_passphrase {
                None => None,
                Some(pass) => Some(
                    encrypt_passphrase(pass, inner.get_enc_ctx_key()).await?,
                ),
            };
            let req = LairApiReqCryptoBoxXSalsaOpenByPubKey::new(
                sender_pub_key,
                recipient_pub_key,
                secret,
                nonce,
                cipher,
            );
            let res = priv_lair_api_request(&*inner, req).await?;
            Ok(res.message)
        }
    }

    /// Encrypt data for a target recipient using the
    /// x25519xsalsa20poly1305 "crypto_box" algorithm.
    /// WARNING: This function actually translates the ed25519 signing
    /// keys into encryption keys. Please understand the downsides of
    /// doing this before using this function:
    /// <https://doc.libsodium.org/advanced/ed25519-curve25519>
    pub fn crypto_box_xsalsa_by_sign_pub_key(
        &self,
        sender_pub_key: Ed25519PubKey,
        recipient_pub_key: Ed25519PubKey,
        deep_lock_passphrase: Option<SharedLockedArray>,
        data: Arc<[u8]>,
    ) -> impl Future<Output = LairResult<([u8; 24], Arc<[u8]>)>> + 'static + Send
    {
        let inner = self.0.clone();
        async move {
            // if this is a deep locked seed, we need to encrypt the passphrase
            let secret = match deep_lock_passphrase {
                None => None,
                Some(pass) => Some(
                    encrypt_passphrase(pass, inner.get_enc_ctx_key()).await?,
                ),
            };
            let req = LairApiReqCryptoBoxXSalsaBySignPubKey::new(
                sender_pub_key,
                recipient_pub_key,
                secret,
                data,
            );
            let res = priv_lair_api_request(&*inner, req).await?;
            Ok((res.nonce, res.cipher))
        }
    }

    /// Decrypt data from a target sender using the
    /// x25519xsalsa20poly1305 "crypto_box_open" algorithm.
    /// WARNING: This function actually translates the ed25519 signing
    /// keys into encryption keys. Please understand the downsides of
    /// doing this before using this function:
    /// <https://doc.libsodium.org/advanced/ed25519-curve25519>
    pub fn crypto_box_xsalsa_open_by_sign_pub_key(
        &self,
        sender_pub_key: Ed25519PubKey,
        recipient_pub_key: Ed25519PubKey,
        deep_lock_passphrase: Option<SharedLockedArray>,
        nonce: [u8; 24],
        cipher: Arc<[u8]>,
    ) -> impl Future<Output = LairResult<Arc<[u8]>>> + 'static + Send {
        let inner = self.0.clone();
        async move {
            // if this is a deep locked seed, we need to encrypt the passphrase
            let secret = match deep_lock_passphrase {
                None => None,
                Some(pass) => Some(
                    encrypt_passphrase(pass, inner.get_enc_ctx_key()).await?,
                ),
            };
            let req = LairApiReqCryptoBoxXSalsaOpenBySignPubKey::new(
                sender_pub_key,
                recipient_pub_key,
                secret,
                nonce,
                cipher,
            );
            let res = priv_lair_api_request(&*inner, req).await?;
            Ok(res.message)
        }
    }

    /// Instruct lair to generate a new well-known-authority signed TLS cert.
    /// This is a lot like a self-signed certificate, but slightly easier to
    /// work with in that it allows registering a single well-known-authority
    /// as a certificate authority which will respect multiple certs.
    pub fn new_wka_tls_cert(
        &self,
        tag: Arc<str>,
    ) -> impl Future<Output = LairResult<CertInfo>> + 'static + Send {
        let inner = self.0.clone();
        async move {
            let req = LairApiReqNewWkaTlsCert::new(tag);
            let res = priv_lair_api_request(&*inner, req).await?;
            Ok(res.cert_info)
        }
    }

    /// Fetch the private key associated with a wka_tls_cert entry.
    /// Will error if the entry specified by 'tag' is not a wka_tls_cert.
    pub fn get_wka_tls_cert_priv_key(
        &self,
        tag: Arc<str>,
    ) -> impl Future<Output = LairResult<sodoken::LockedArray>> + 'static + Send
    {
        let inner = self.0.clone();
        async move {
            let req = LairApiReqGetWkaTlsCertPrivKey::new(tag);
            let res = priv_lair_api_request(&*inner, req).await?;
            let res = res.priv_key.decrypt(inner.get_dec_ctx_key()).await?;
            Ok(res)
        }
    }

    /// Shared secret encryption using the libsodium
    /// xsalsa20poly1305 "secretbox" algorithm.
    pub fn secretbox_xsalsa_by_tag(
        &self,
        tag: Arc<str>,
        deep_lock_passphrase: Option<SharedLockedArray>,
        data: Arc<[u8]>,
    ) -> impl Future<Output = LairResult<([u8; 24], Arc<[u8]>)>> + 'static + Send
    {
        let inner = self.0.clone();
        async move {
            // if this is a deep locked seed, we need to encrypt the passphrase
            let secret = match deep_lock_passphrase {
                None => None,
                Some(pass) => Some(
                    encrypt_passphrase(pass, inner.get_enc_ctx_key()).await?,
                ),
            };
            let req = LairApiReqSecretBoxXSalsaByTag::new(tag, secret, data);
            let res = priv_lair_api_request(&*inner, req).await?;
            Ok((res.nonce, res.cipher))
        }
    }

    /// Shared secret decryption using the libsodium
    /// xsalsa20poly1305 "secretbox_open" algorithm.
    pub fn secretbox_xsalsa_open_by_tag(
        &self,
        tag: Arc<str>,
        deep_lock_passphrase: Option<SharedLockedArray>,
        nonce: [u8; 24],
        cipher: Arc<[u8]>,
    ) -> impl Future<Output = LairResult<Arc<[u8]>>> + 'static + Send {
        let inner = self.0.clone();
        async move {
            // if this is a deep locked seed, we need to encrypt the passphrase
            let secret = match deep_lock_passphrase {
                None => None,
                Some(pass) => Some(
                    encrypt_passphrase(pass, inner.get_enc_ctx_key()).await?,
                ),
            };
            let req = LairApiReqSecretBoxXSalsaOpenByTag::new(
                tag, secret, nonce, cipher,
            );
            let res = priv_lair_api_request(&*inner, req).await?;
            Ok(res.message)
        }
    }
}

pub mod async_io;

async fn encrypt_passphrase(
    pass: SharedLockedArray,
    key: SharedSizedLockedArray<32>,
) -> LairResult<DeepLockPassphraseBytes> {
    // pre-hash the passphrase
    let pw_hash = tokio::task::spawn_blocking(move || -> LairResult<_> {
        let mut pw_hash = sodoken::SizedLockedArray::<64>::new()?;
        sodoken::blake2b::blake2b_hash(
            &mut *pw_hash.lock(),
            &pass.lock().lock(),
            None,
        )?;

        Ok(pw_hash)
    })
    .await
    .map_err(OneErr::new)??;

    let pw_hash = Arc::new(Mutex::new(pw_hash));

    let secret = SecretDataSized::encrypt(key, pw_hash).await?;
    Ok(secret)
}
