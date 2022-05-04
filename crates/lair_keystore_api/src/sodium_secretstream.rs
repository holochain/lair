//! Libsodium secretstream Async reader / writer wrappers.

use crate::*;
use futures::future::{BoxFuture, FutureExt};
use futures::stream::{BoxStream, Stream, StreamExt};
use one_err::*;
use parking_lot::Mutex;
use sodoken::secretstream::xchacha20poly1305 as sss;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;

use std::future::Future;
use std::sync::Arc;

/// Throw errors on the streams if a single message is > 8 KiB
const MAX_FRAME: usize = 1024 * 8; // 8 KiB

/// Traits related to sodium_secretstreams. Unless you're writing a new
/// stream implementation, you probably don't need these.
pub mod traits {
    use super::*;

    /// The send / write half of a sodium secret stream.
    pub trait AsS3Sender<T>: 'static + Send + Sync
    where
        T: 'static + serde::Serialize + Send,
    {
        /// Send data to the remote side of this connection.
        fn send(&self, t: T) -> BoxFuture<'static, LairResult<()>>;

        /// Get outgoing encryption context key.
        fn get_enc_ctx_key(&self) -> sodoken::BufReadSized<{ sss::KEYBYTES }>;

        /// Get incoming decryption context key.
        fn get_dec_ctx_key(&self) -> sodoken::BufReadSized<{ sss::KEYBYTES }>;

        /// Shutdown the channel.
        fn shutdown(&self) -> BoxFuture<'static, LairResult<()>>;
    }

    /// The recv / read half of a sodium secret stream.
    pub trait AsS3Receiver<T>:
        'static + Send + Stream<Item = LairResult<T>> + Unpin
    where
        T: for<'de> serde::Deserialize<'de>,
    {
    }
}
use traits::*;

/// The send / write half of a sodium secret stream.
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

    /// Get outgoing encryption context key.
    pub fn get_enc_ctx_key(&self) -> sodoken::BufReadSized<{ sss::KEYBYTES }> {
        AsS3Sender::get_enc_ctx_key(&*self.0)
    }

    /// Get incoming decryption context key.
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

/// The recv / read half of a sodium secret stream.
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

/// Create a new S3 server side pair.
pub fn new_s3_server<T, S, R>(
    send: S,
    recv: R,
    srv_id_pub_key: sodoken::BufReadSized<32>,
    srv_id_sec_key: sodoken::BufReadSized<32>,
) -> impl Future<Output = LairResult<(S3Sender<T>, S3Receiver<T>)>> + 'static + Send
where
    T: 'static + serde::Serialize + for<'de> serde::Deserialize<'de> + Send,
    S: 'static + tokio::io::AsyncWrite + Send + Unpin,
    R: 'static + tokio::io::AsyncRead + Send + Unpin,
{
    async move {
        use sodoken::crypto_box::curve25519xchacha20poly1305 as cbox;
        use sodoken::kx;

        // box these up into trait objects so we can easily refer to their types.
        let mut send: PrivRawSend = Box::new(send);
        let mut recv: PrivRawRecv = Box::new(recv);

        // read the sealed initiator message
        let mut cipher: [u8; 64 + cbox::SEALBYTES] = [0; 64 + cbox::SEALBYTES];
        recv.read_exact(&mut cipher).await?;
        let cipher = sodoken::BufReadSized::from(cipher);
        let msg = <sodoken::BufWriteSized<64>>::new_no_lock();
        cbox::seal_open(msg.clone(), cipher, srv_id_pub_key, srv_id_sec_key)
            .await?;
        let msg = msg.try_unwrap_sized().unwrap();

        let oth_cbox_pub = sodoken::BufReadSized::from(&msg[..32]);
        let oth_kx_pub = sodoken::BufReadSized::from(&msg[32..]);

        // generate an ephemeral kx keypair
        let eph_kx_pub = sodoken::BufWriteSized::new_no_lock();
        let eph_kx_sec = sodoken::BufWriteSized::new_mem_locked()?;
        kx::keypair(eph_kx_pub.clone(), eph_kx_sec.clone())?;

        // seal our ephemeral kx pub key
        let cipher =
            <sodoken::BufWriteSized<{ 32 + cbox::SEALBYTES }>>::new_no_lock();
        cbox::seal(cipher.clone(), eph_kx_pub.clone(), oth_cbox_pub).await?;
        let cipher = cipher.try_unwrap_sized().unwrap();

        // write the sealed response
        send.write_all(&cipher).await?;

        // prepare our transport secrets
        let rx = sodoken::BufWriteSized::new_mem_locked()?;
        let tx = sodoken::BufWriteSized::new_mem_locked()?;

        // derive our secretstream keys
        sodoken::kx::client_session_keys(
            rx.clone(),
            tx.clone(),
            eph_kx_pub,
            eph_kx_sec,
            oth_kx_pub,
        )?;

        let rx = rx.to_read_sized();
        let tx = tx.to_read_sized();

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

/// Create a new S3 client side pair.
pub fn new_s3_client<T, S, R>(
    send: S,
    recv: R,
    srv_id_pub_key: sodoken::BufReadSized<32>,
) -> impl Future<Output = LairResult<(S3Sender<T>, S3Receiver<T>)>> + 'static + Send
where
    T: 'static + serde::Serialize + for<'de> serde::Deserialize<'de> + Send,
    S: 'static + tokio::io::AsyncWrite + Send + Unpin,
    R: 'static + tokio::io::AsyncRead + Send + Unpin,
{
    async move {
        use sodoken::crypto_box::curve25519xchacha20poly1305 as cbox;
        use sodoken::kx;

        // box these up into trait objects so we can easily refer to their types.
        let mut send: PrivRawSend = Box::new(send);
        let mut recv: PrivRawRecv = Box::new(recv);

        // generate an ephemeral cbox keypair
        let eph_cbox_pub = sodoken::BufWriteSized::new_no_lock();
        let eph_cbox_sec = sodoken::BufWriteSized::new_mem_locked()?;
        cbox::keypair(eph_cbox_pub.clone(), eph_cbox_sec.clone()).await?;

        // generate an ephemeral kx keypair
        let eph_kx_pub = sodoken::BufWriteSized::new_no_lock();
        let eph_kx_sec = sodoken::BufWriteSized::new_mem_locked()?;
        kx::keypair(eph_kx_pub.clone(), eph_kx_sec.clone())?;

        // sealed initiator message
        let mut message: [u8; 64] = [0; 64];
        message[..32].copy_from_slice(&*eph_cbox_pub.read_lock());
        message[32..].copy_from_slice(&*eph_kx_pub.read_lock());
        let message = sodoken::BufReadSized::from(message);
        let cipher =
            <sodoken::BufWriteSized<{ 64 + cbox::SEALBYTES }>>::new_no_lock();
        cbox::seal(cipher.clone(), message, srv_id_pub_key).await?;
        let cipher = cipher.try_unwrap_sized().unwrap();

        // write the sealed initiator
        send.write_all(&cipher).await?;

        // read the sealed response ephemeral kx pub key
        let mut cipher: [u8; 32 + cbox::SEALBYTES] = [0; 32 + cbox::SEALBYTES];
        recv.read_exact(&mut cipher).await?;
        let cipher = sodoken::BufReadSized::from(cipher);
        let oth_eph_kx_pub = sodoken::BufWriteSized::new_no_lock();
        cbox::seal_open(
            oth_eph_kx_pub.clone(),
            cipher,
            eph_cbox_pub,
            eph_cbox_sec,
        )
        .await?;

        // prepare our transport secrets
        let rx = sodoken::BufWriteSized::new_mem_locked()?;
        let tx = sodoken::BufWriteSized::new_mem_locked()?;

        // derive our secretstream keys
        sodoken::kx::server_session_keys(
            rx.clone(),
            tx.clone(),
            eph_kx_pub,
            eph_kx_sec,
            oth_eph_kx_pub,
        )?;

        let rx = rx.to_read_sized();
        let tx = tx.to_read_sized();

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
        use sodoken::crypto_box::curve25519xchacha20poly1305::*;
        let srv_id_pub = sodoken::BufWriteSized::new_no_lock();
        let srv_id_sec = sodoken::BufWriteSized::new_mem_locked().unwrap();
        keypair(srv_id_pub.clone(), srv_id_sec.clone())
            .await
            .unwrap();
        let srv_id_pub = srv_id_pub.to_read_sized();
        let srv_id_sec = srv_id_sec.to_read_sized();

        // make a memory channel for testing.
        let (alice, bob) = tokio::io::duplex(4096);

        // split alice up and get a new s3 pair for her side.
        let (alice_recv, alice_send) = tokio::io::split(alice);
        let alice_fut = new_s3_client::<usize, _, _>(
            alice_send,
            alice_recv,
            srv_id_pub.clone(),
        );

        // split bob up and get a new s3 pair for his side.
        let (bob_recv, bob_send) = tokio::io::split(bob);
        let bob_fut = new_s3_server::<usize, _, _>(
            bob_send, bob_recv, srv_id_pub, srv_id_sec,
        );

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
