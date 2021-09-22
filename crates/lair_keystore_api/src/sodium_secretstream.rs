#![allow(unused_imports)]
//! libsodium secretstream Async reader / writer wrappers.

use futures::future::{BoxFuture, FutureExt};
use futures::stream::{BoxStream, Stream, StreamExt};
use one_err::*;
use parking_lot::Mutex;
use sodoken::secretstream::xchacha20poly1305 as sss;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;

use crate::LairResult;
use std::future::Future;
use std::sync::Arc;

/// Throw errors on the streams if a single message is > 8 KiB
const MAX_FRAME: usize = 1024 * 8; // 8 KiB

/// Traits related to sodium_secretstreams. Unless you're writing a new
/// stream implementation, you probably don't need these.
pub mod traits {
    use super::*;

    /// SodiumSecretStream - Sender
    pub trait AsS3Sender<T>: 'static + Send + Sync
    where
        T: 'static + serde::Serialize + Send,
    {
        /// Send data to the remote side of this connection.
        fn send(&self, t: T) -> BoxFuture<'static, LairResult<()>>;

        /// Get outgoing encryption context key
        fn get_enc_ctx_key(&self) -> sodoken::BufReadSized<{ sss::KEYBYTES }>;

        /// Get incoming decryption context key
        fn get_dec_ctx_key(&self) -> sodoken::BufReadSized<{ sss::KEYBYTES }>;

        /// Shutdown the channel.
        fn shutdown(&self) -> BoxFuture<'static, LairResult<()>>;
    }

    /// SodiumSecretStream - Receiver
    pub trait AsS3Receiver<T>:
        'static + Send + Stream<Item = LairResult<T>> + Unpin
    where
        T: for<'de> serde::Deserialize<'de>,
    {
    }
}
use traits::*;

/// SodiumSecretStream - Sender
pub struct S3Sender<T>(pub Arc<dyn AsS3Sender<T>>);

impl<T> Clone for S3Sender<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> S3Sender<T>
where
    T: 'static + serde::Serialize + Send,
{
    /// Send data to the remote side of this connection.
    pub fn send(
        &self,
        t: T,
    ) -> impl Future<Output = LairResult<()>> + 'static + Send {
        AsS3Sender::send(&*self.0, t)
    }

    /// Get outgoing encryption context key
    pub fn get_enc_ctx_key(&self) -> sodoken::BufReadSized<{ sss::KEYBYTES }> {
        AsS3Sender::get_enc_ctx_key(&*self.0)
    }

    /// Get incoming decryption context key
    pub fn get_dec_ctx_key(&self) -> sodoken::BufReadSized<{ sss::KEYBYTES }> {
        AsS3Sender::get_dec_ctx_key(&*self.0)
    }

    /// Shutdown the channel.
    pub fn shutdown(
        &self,
    ) -> impl Future<Output = LairResult<()>> + 'static + Send {
        AsS3Sender::shutdown(&*self.0)
    }
}

/// SodiumSecretStream - Receiver
pub struct S3Receiver<T>(pub Box<dyn AsS3Receiver<T>>);

impl<T> Stream for S3Receiver<T>
where
    T: for<'de> serde::Deserialize<'de>,
{
    type Item = LairResult<T>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        Stream::poll_next(std::pin::Pin::new(&mut self.0), cx)
    }
}

/// Create a new S3 send/receive pair.
pub fn new_s3_pair<T, S, R>(
    send: S,
    recv: R,
    is_srv: bool,
) -> impl Future<Output = LairResult<(S3Sender<T>, S3Receiver<T>)>> + 'static + Send
where
    T: 'static + serde::Serialize + for<'de> serde::Deserialize<'de> + Send,
    S: 'static + tokio::io::AsyncWrite + Send + Unpin,
    R: 'static + tokio::io::AsyncRead + Send + Unpin,
{
    async move {
        // box these up into trait objects so we can easily refer to their types.
        let mut send: PrivRawSend = Box::new(send);
        let mut recv: PrivRawRecv = Box::new(recv);

        // perform a key exchange with the remote.
        let (tx, rx) = priv_kx(&mut send, &mut recv, is_srv).await?;

        // perform a secretstream init handshake with the remote.
        let (enc, dec) =
            priv_init_ss(&mut send, tx.clone(), &mut recv, rx.clone()).await?;

        // initialize framing so we know when we've got complete messages.
        let (send, recv) = priv_framed(send, recv);

        // wrap the streams with cryptography.
        let (send, recv) = priv_crypt(send, enc, recv, dec);

        // bundle up our output sender type.
        let send: PrivSend<T> = PrivSend::new(send, tx, rx);
        let send: S3Sender<T> = S3Sender(Arc::new(send));

        // bundle up our output receiver type.
        let recv: PrivRecv<T> = PrivRecv::new(recv);
        let recv: S3Receiver<T> = S3Receiver(Box::new(recv));

        Ok((send, recv))
    }
}

// -- private -- //

/// trait object type for AsyncWrite instance.
type PrivRawSend = Box<dyn tokio::io::AsyncWrite + 'static + Send + Unpin>;

/// trait object type for AsyncRead instance.
type PrivRawRecv = Box<dyn tokio::io::AsyncRead + 'static + Send + Unpin>;

mod framed;
use framed::*;

mod crypt;
use crypt::*;

mod inner;
use inner::*;

/// perform key exchange to generate secret rx key and secret tx key.
fn priv_kx<'a>(
    send: &'a mut PrivRawSend,
    recv: &'a mut PrivRawRecv,
    is_srv: bool,
) -> impl Future<
    Output = LairResult<(
        sodoken::BufReadSized<{ sss::KEYBYTES }>,
        sodoken::BufReadSized<{ sss::KEYBYTES }>,
    )>,
>
       + 'a
       + Send {
    async move {
        // generate an ephemeral kx keypair
        let eph_kx_pub = sodoken::BufWriteSized::new_no_lock();
        let eph_kx_sec = sodoken::BufWriteSized::new_mem_locked()?;
        sodoken::kx::keypair(eph_kx_pub.clone(), eph_kx_sec.clone())?;
        // clone to keep this future 'Send'
        let eph_kx_pub2 = eph_kx_pub.read_lock().to_vec();
        send.write_all(&eph_kx_pub2).await?;

        // read the remote kx pubkey.
        let mut oth_eph_kx_pub = [0; 32];
        recv.read_exact(&mut oth_eph_kx_pub).await?;
        let oth_eph_kx_pub = sodoken::BufReadSized::from(oth_eph_kx_pub);

        // prepare our transport secrets
        let rx = sodoken::BufWriteSized::new_mem_locked()?;
        let tx = sodoken::BufWriteSized::new_mem_locked()?;

        // do the key exchange calculation
        // depending on if we're the "server" or "client".
        if is_srv {
            sodoken::kx::server_session_keys(
                rx.clone(),
                tx.clone(),
                eph_kx_pub,
                eph_kx_sec,
                oth_eph_kx_pub,
            )?;
        } else {
            sodoken::kx::client_session_keys(
                rx.clone(),
                tx.clone(),
                eph_kx_pub,
                eph_kx_sec,
                oth_eph_kx_pub,
            )?;
        }

        Ok((tx.to_read_sized(), rx.to_read_sized()))
    }
}

/// use secret keys to initialize secretstream encryption / decryption.
fn priv_init_ss<'a>(
    send: &'a mut PrivRawSend,
    tx: sodoken::BufReadSized<{ sss::KEYBYTES }>,
    recv: &'a mut PrivRawRecv,
    rx: sodoken::BufReadSized<{ sss::KEYBYTES }>,
) -> impl Future<
    Output = LairResult<(sss::SecretStreamEncrypt, sss::SecretStreamDecrypt)>,
>
       + 'a
       + Send {
    async move {
        // for our sender, initialize encryption by generating / sending header.
        let header = sodoken::BufWriteSized::new_no_lock();
        let enc = sss::SecretStreamEncrypt::new(tx, header.clone())?;
        // clone to keep this future 'Send'
        let mut header2 = *header.read_lock_sized();
        send.write_all(&header2).await?;

        // for our receiver, parse the incoming header
        recv.read_exact(&mut header2).await?;
        let dec = sss::SecretStreamDecrypt::new(rx, header2)?;

        Ok((enc, dec))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_sodium_secretstream() {
        // make a memory channel for testing.
        let (alice, bob) = tokio::io::duplex(4096);

        // split alice up and get a new s3 pair for her side.
        let (alice_recv, alice_send) = tokio::io::split(alice);
        let alice_fut =
            new_s3_pair::<usize, _, _>(alice_send, alice_recv, false);

        // split bob up and get a new s3 pair for his side.
        let (bob_recv, bob_send) = tokio::io::split(bob);
        let bob_fut = new_s3_pair::<usize, _, _>(bob_send, bob_recv, true);

        // await initialization in parallel to handshake properly.
        let ((alice_send, mut alice_recv), (bob_send, mut bob_recv)) =
            futures::future::try_join(alice_fut, bob_fut).await.unwrap();

        assert_eq!(
            &*alice_send.get_enc_ctx_key().read_lock(),
            &*bob_send.get_dec_ctx_key().read_lock(),
        );

        assert_eq!(
            &*alice_send.get_dec_ctx_key().read_lock(),
            &*bob_send.get_enc_ctx_key().read_lock(),
        );

        // try out sending
        alice_send.send(42).await.unwrap();
        bob_send.send(99).await.unwrap();

        // try out shutting down
        alice_send.shutdown().await.unwrap();
        bob_send.shutdown().await.unwrap();

        // try out receiving
        assert_eq!(42, bob_recv.next().await.unwrap().unwrap());
        assert_eq!(99, alice_recv.next().await.unwrap().unwrap());

        // make sure they are shut down
        assert_eq!(
            std::io::ErrorKind::UnexpectedEof,
            bob_recv.next().await.unwrap().unwrap_err().io_kind(),
        );
        assert_eq!(
            std::io::ErrorKind::UnexpectedEof,
            alice_recv.next().await.unwrap().unwrap_err().io_kind(),
        );
    }
}
