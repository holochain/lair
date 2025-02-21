//! Libsodium secretstream Async reader / writer wrappers.

use crate::*;
use futures::future::{BoxFuture, FutureExt};
use futures::stream::{BoxStream, Stream, StreamExt};
use one_err::*;
use parking_lot::Mutex;
use std::convert::TryInto;
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
        fn get_enc_ctx_key(
            &self,
        ) -> Arc<
            Mutex<
                sodoken::SizedLockedArray<{ sodoken::secretstream::KEYBYTES }>,
            >,
        >;

        /// Get incoming decryption context key.
        fn get_dec_ctx_key(
            &self,
        ) -> Arc<
            Mutex<
                sodoken::SizedLockedArray<{ sodoken::secretstream::KEYBYTES }>,
            >,
        >;

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
    pub fn get_enc_ctx_key(
        &self,
    ) -> Arc<
        Mutex<sodoken::SizedLockedArray<{ sodoken::secretstream::KEYBYTES }>>,
    > {
        AsS3Sender::get_enc_ctx_key(&*self.0)
    }

    /// Get incoming decryption context key.
    pub fn get_dec_ctx_key(
        &self,
    ) -> Arc<
        Mutex<sodoken::SizedLockedArray<{ sodoken::secretstream::KEYBYTES }>>,
    > {
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
    srv_id_pub_key: Arc<[u8; 32]>,
    srv_id_sec_key: Arc<Mutex<sodoken::SizedLockedArray<32>>>,
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

        // read the sealed initiator message
        let mut cipher = [0; 64 + sodoken::crypto_box::XSALSA_SEALBYTES];
        recv.read_exact(&mut cipher).await?;
        let mut msg = [0; 64];
        sodoken::crypto_box::xsalsa_seal_open(
            &mut msg,
            &cipher,
            &srv_id_pub_key,
            &srv_id_sec_key.lock().lock(),
        )?;

        let oth_cbox_pub: &[u8; 32] = (&msg[..32]).try_into().unwrap();
        let oth_kx_pub: &[u8; 32] = (&msg[32..]).try_into().unwrap();

        // generate an ephemeral kx keypair
        let mut eph_kx_pub = [0; sodoken::crypto_box::XSALSA_PUBLICKEYBYTES];
        let mut eph_kx_sec = sodoken::SizedLockedArray::<
            { sodoken::crypto_box::XSALSA_SECRETKEYBYTES },
        >::new()?;
        sodoken::crypto_box::xsalsa_keypair(
            &mut eph_kx_pub,
            &mut eph_kx_sec.lock(),
        )?;

        // seal our ephemeral kx pub key
        let mut cipher = sodoken::SizedLockedArray::<
            { 32 + sodoken::crypto_box::XSALSA_SEALBYTES },
        >::new()?;
        sodoken::crypto_box::xsalsa_seal(
            &mut *cipher.lock(),
            &eph_kx_pub,
            oth_cbox_pub,
        )?;

        // write the sealed response
        send.write_all(&*cipher.lock()).await?;

        // prepare our transport secrets
        let mut rx = sodoken::SizedLockedArray::<
            { sodoken::kx::SESSIONKEYBYTES },
        >::new()?;
        let mut tx = sodoken::SizedLockedArray::<
            { sodoken::kx::SESSIONKEYBYTES },
        >::new()?;

        // derive our secretstream keys
        sodoken::kx::client_session_keys(
            &mut rx.lock(),
            &mut tx.lock(),
            &eph_kx_pub,
            &eph_kx_sec.lock(),
            oth_kx_pub,
        )?;

        let rx = Arc::new(Mutex::new(rx));
        let tx = Arc::new(Mutex::new(tx));

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
    srv_id_pub_key: BinDataSized<32>,
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

        // generate an ephemeral cbox keypair
        let mut eph_cbox_pub = [0; sodoken::crypto_box::XSALSA_PUBLICKEYBYTES];
        let mut eph_cbox_sec = sodoken::SizedLockedArray::<
            { sodoken::crypto_box::XSALSA_SECRETKEYBYTES },
        >::new()?;
        // TODO Should be a crypto_kx_keypair?
        sodoken::crypto_box::xsalsa_keypair(
            &mut eph_cbox_pub,
            &mut eph_cbox_sec.lock(),
        )?;

        // generate an ephemeral kx keypair
        let mut eph_kx_pub = [0; sodoken::crypto_box::XSALSA_PUBLICKEYBYTES];
        let mut eph_kx_sec = sodoken::SizedLockedArray::<
            { sodoken::crypto_box::XSALSA_SECRETKEYBYTES },
        >::new()?;
        sodoken::crypto_box::xsalsa_keypair(
            &mut eph_kx_pub,
            &mut eph_kx_sec.lock(),
        )?;

        // sealed initiator message
        let mut message: [u8; 64] = [0; 64];
        message[..32].copy_from_slice(&eph_cbox_pub);
        message[32..].copy_from_slice(&eph_kx_pub);
        let mut cipher = sodoken::SizedLockedArray::<
            { 64 + sodoken::crypto_box::XSALSA_SEALBYTES },
        >::new()?;
        sodoken::crypto_box::xsalsa_seal(
            &mut *cipher.lock(),
            &message,
            &srv_id_pub_key,
        )?;

        // write the sealed initiator
        send.write_all(&*cipher.lock()).await?;

        // read the sealed response ephemeral kx pub key
        let mut cipher = [0; 32 + sodoken::crypto_box::XSALSA_SEALBYTES];
        recv.read_exact(&mut cipher).await?;
        // TODO kx size?
        let mut oth_eph_kx_pub = [0; 32];
        sodoken::crypto_box::xsalsa_seal_open(
            &mut oth_eph_kx_pub,
            &cipher,
            &eph_cbox_pub,
            &eph_cbox_sec.lock(),
        )?;

        // prepare our transport secrets
        let mut rx = sodoken::SizedLockedArray::<
            { sodoken::kx::SESSIONKEYBYTES },
        >::new()?;
        let mut tx = sodoken::SizedLockedArray::<
            { sodoken::kx::SESSIONKEYBYTES },
        >::new()?;

        // derive our secretstream keys
        sodoken::kx::server_session_keys(
            &mut rx.lock(),
            &mut tx.lock(),
            &eph_kx_pub,
            &eph_kx_sec.lock(),
            &oth_eph_kx_pub,
        )?;

        let rx = Arc::new(Mutex::new(rx));
        let tx = Arc::new(Mutex::new(tx));

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
use crate::types::SharedSizedLockedArray;
use inner::*;

/// use secret keys to initialize secretstream encryption / decryption.
fn priv_init_ss<'a>(
    send: &'a mut PrivRawSend,
    tx: SharedSizedLockedArray<{ sodoken::secretstream::KEYBYTES }>,
    recv: &'a mut PrivRawRecv,
    rx: SharedSizedLockedArray<{ sodoken::secretstream::KEYBYTES }>,
) -> impl Future<
    Output = LairResult<(
        sodoken::secretstream::State,
        sodoken::secretstream::State,
    )>,
>
       + 'a
       + Send {
    async move {
        // for our sender, initialize encryption by generating / sending header.
        let mut header = [0; sodoken::secretstream::HEADERBYTES];
        let mut enc = sodoken::secretstream::State::default();
        sodoken::secretstream::init_push(
            &mut enc,
            &mut header,
            &tx.lock().lock(),
        )?;

        send.write_all(&header).await?;

        // for our receiver, parse the incoming header
        recv.read_exact(&mut header).await?;
        let mut dec = sodoken::secretstream::State::default();
        sodoken::secretstream::init_pull(&mut dec, &header, &rx.lock().lock())?;

        Ok((enc, dec))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_sodium_secretstream() {
        let mut srv_id_pub = [0; sodoken::crypto_box::XSALSA_PUBLICKEYBYTES];
        let mut srv_id_sec = sodoken::SizedLockedArray::<
            { sodoken::crypto_box::XSALSA_SECRETKEYBYTES },
        >::new()
        .unwrap();
        sodoken::crypto_box::xsalsa_keypair(
            &mut srv_id_pub,
            &mut srv_id_sec.lock(),
        )
        .unwrap();
        let srv_id_pub = Arc::new(srv_id_pub);
        let srv_id_sec = Arc::new(Mutex::new(srv_id_sec));

        // make a memory channel for testing.
        let (alice, bob) = tokio::io::duplex(4096);

        // split alice up and get a new s3 pair for her side.
        let (alice_recv, alice_send) = tokio::io::split(alice);
        let alice_fut = new_s3_client::<usize, _, _>(
            alice_send,
            alice_recv,
            srv_id_pub.clone().into(),
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
            &*alice_send.get_enc_ctx_key().lock().lock(),
            &*bob_send.get_dec_ctx_key().lock().lock(),
        );

        assert_eq!(
            &*alice_send.get_dec_ctx_key().lock().lock(),
            &*bob_send.get_enc_ctx_key().lock().lock(),
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
