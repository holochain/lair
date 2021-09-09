#![allow(unused_imports)]
//! libsodium secretstream Async reader / writer wrappers.

use futures::future::{BoxFuture, FutureExt};
use futures::stream::{BoxStream, Stream, StreamExt};
use one_err::*;
use parking_lot::Mutex;
use sodoken::secretstream::xchacha20poly1305 as sss;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;

use crate::LairResult2 as LairResult;
use std::future::Future;
use std::sync::Arc;

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
#[derive(Clone)]
pub struct S3Sender<T>(pub Arc<dyn AsS3Sender<T>>);

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

/// create a new S3 send/receive pair
pub async fn new_s3_pair<T, S, R>(
    send: S,
    recv: R,
    is_srv: bool,
) -> LairResult<(S3Sender<T>, S3Receiver<T>)>
where
    T: 'static + serde::Serialize + for<'de> serde::Deserialize<'de> + Send,
    S: 'static + tokio::io::AsyncWrite + Send + Unpin,
    R: 'static + tokio::io::AsyncRead + Send + Unpin,
{
    let mut send: PrivRawSend = Box::new(send);
    let mut recv: PrivRawRecv = Box::new(recv);

    let (tx, rx) = priv_kx(&mut send, &mut recv, is_srv).await?;
    let (enc, dec) = priv_init_ss(&mut send, tx, &mut recv, rx).await?;
    let (send, recv) = priv_framed(send, recv);
    let (send, recv) = priv_crypt(send, enc, recv, dec);

    let send: PrivSend<T> = PrivSend::new(send);
    let send: S3Sender<T> = S3Sender(Arc::new(send));

    let recv: PrivRecv<T> = PrivRecv::new(recv);
    let recv: S3Receiver<T> = S3Receiver(Box::new(recv));

    Ok((send, recv))
}

// -- private -- //

type PrivRawSend = Box<dyn tokio::io::AsyncWrite + 'static + Send + Unpin>;
type PrivRawRecv = Box<dyn tokio::io::AsyncRead + 'static + Send + Unpin>;

/// perform key exchange to generate secret rx key and secret tx key
async fn priv_kx(
    send: &mut PrivRawSend,
    recv: &mut PrivRawRecv,
    is_srv: bool,
) -> LairResult<(
    sodoken::BufReadSized<{ sss::KEYBYTES }>,
    sodoken::BufReadSized<{ sss::KEYBYTES }>,
)> {
    let eph_kx_pub = sodoken::BufWriteSized::new_no_lock();
    let eph_kx_sec = sodoken::BufWriteSized::new_mem_locked()?;
    sodoken::kx::keypair(eph_kx_pub.clone(), eph_kx_sec.clone())?;
    send.write_all(&*eph_kx_pub.read_lock()).await?;

    let oth_eph_kx_pub = sodoken::BufWriteSized::new_no_lock();
    recv.read_exact(&mut *oth_eph_kx_pub.write_lock()).await?;

    let rx = sodoken::BufWriteSized::new_mem_locked()?;
    let tx = sodoken::BufWriteSized::new_mem_locked()?;
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

/// use secret keys to initialize secretstream encryption / decryption
async fn priv_init_ss(
    send: &mut PrivRawSend,
    tx: sodoken::BufReadSized<{ sss::KEYBYTES }>,
    recv: &mut PrivRawRecv,
    rx: sodoken::BufReadSized<{ sss::KEYBYTES }>,
) -> LairResult<(sss::SecretStreamEncrypt, sss::SecretStreamDecrypt)> {
    let header = sodoken::BufWriteSized::new_no_lock();
    let enc = sss::SecretStreamEncrypt::new(tx, header.clone())?;
    send.write_all(&*header.read_lock()).await?;

    recv.read_exact(&mut *header.write_lock()).await?;
    let dec = sss::SecretStreamDecrypt::new(rx, header)?;

    Ok((enc, dec))
}

fn priv_framed(
    send: PrivRawSend,
    recv: PrivRawRecv,
) -> (PrivFramedSend, PrivFramedRecv) {
    let send = PrivFramedSend(send);
    let recv = PrivFramedRecv::new(recv);
    (send, recv)
}

fn priv_crypt(
    send: PrivFramedSend,
    enc: sss::SecretStreamEncrypt,
    recv: PrivFramedRecv,
    dec: sss::SecretStreamDecrypt,
) -> (PrivCryptSend, PrivCryptRecv) {
    let send = PrivCryptSend::new(send, enc);
    let recv = PrivCryptRecv::new(recv, dec);
    (send, recv)
}

const MAX_FRAME: usize = 1024 * 8; // 8 KiB

struct PrivFramedSend(PrivRawSend);

impl PrivFramedSend {
    pub async fn send(&mut self, d: Box<[u8]>) -> LairResult<()> {
        if d.len() > MAX_FRAME {
            return Err(OneErr::with_message(
                "FrameOverflow",
                format!("{} > {}", d.len(), MAX_FRAME),
            ));
        }

        let ltag = (d.len() as u16).to_le_bytes();

        // TODO - something more efficient than just writing both buffers?

        self.0.write_all(&ltag).await?;
        self.0.write_all(&d).await?;
        Ok(())
    }

    pub async fn shutdown(&mut self) -> LairResult<()> {
        self.0.shutdown().await.map_err(OneErr::new)
    }
}

struct PrivFramedRecv(BoxStream<'static, LairResult<Box<[u8]>>>);

impl PrivFramedRecv {
    pub fn new(recv: PrivRawRecv) -> Self {
        let recv = futures::stream::try_unfold(recv, |mut recv| async move {
            // TODO - something more efficient than doing this in 2 steps?

            let mut ltag = [0; 2];
            recv.read_exact(&mut ltag).await?;
            let ltag = u16::from_le_bytes(ltag) as usize;

            if ltag > MAX_FRAME {
                return Err(OneErr::with_message(
                    "FrameOverflow",
                    format!("{} > {}", ltag, MAX_FRAME),
                ));
            }

            let mut msg = Vec::with_capacity(ltag);
            unsafe {
                msg.set_len(ltag);
            }

            recv.read_exact(&mut msg).await?;

            Ok(Some((msg.into_boxed_slice(), recv)))
        });
        Self(recv.boxed())
    }
}

impl Stream for PrivFramedRecv {
    type Item = LairResult<Box<[u8]>>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        Stream::poll_next(std::pin::Pin::new(&mut self.0), cx)
    }
}

struct PrivCryptSend {
    send: PrivFramedSend,
    enc: sss::SecretStreamEncrypt,
}

impl PrivCryptSend {
    pub fn new(send: PrivFramedSend, enc: sss::SecretStreamEncrypt) -> Self {
        Self { send, enc }
    }

    async fn send<D: Into<sodoken::BufRead>>(
        &mut self,
        d: D,
    ) -> LairResult<()> {
        let d = d.into();
        let len = d.len() + sss::ABYTES;
        let cipher = sodoken::BufExtend::new_no_lock(len);
        self.enc
            .push_message(d, <Option<sodoken::BufRead>>::None, cipher.clone())
            .await?;
        let cipher = cipher.try_unwrap().unwrap();
        self.send.send(cipher).await?;
        Ok(())
    }

    async fn shutdown(&mut self) -> LairResult<()> {
        self.send.shutdown().await
    }
}

struct PrivCryptRecv(BoxStream<'static, LairResult<Box<[u8]>>>);

impl PrivCryptRecv {
    pub fn new(recv: PrivFramedRecv, dec: sss::SecretStreamDecrypt) -> Self {
        let recv = futures::stream::try_unfold(
            (recv, dec),
            |(mut recv, mut dec)| async move {
                let cipher = match recv.next().await {
                    None => return Ok(None),
                    Some(cipher) => cipher?,
                };
                let cipher = sodoken::BufRead::from(cipher);
                let msg =
                    sodoken::BufWrite::new_no_lock(cipher.len() - sss::ABYTES);
                dec.pull(cipher, <Option<sodoken::BufRead>>::None, msg.clone())
                    .await?;
                let msg = msg.try_unwrap().unwrap();
                Ok(Some((msg, (recv, dec))))
            },
        );
        Self(recv.boxed())
    }
}

impl Stream for PrivCryptRecv {
    type Item = LairResult<Box<[u8]>>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        Stream::poll_next(std::pin::Pin::new(&mut self.0), cx)
    }
}

struct PrivSendInner {
    limit: Arc<tokio::sync::Semaphore>,
    send: Option<PrivCryptSend>,
}

struct PrivSend<T>(
    Arc<Mutex<PrivSendInner>>,
    std::marker::PhantomData<fn() -> *const T>,
)
where
    T: 'static + serde::Serialize + Send;

impl<T> PrivSend<T>
where
    T: 'static + serde::Serialize + Send,
{
    pub fn new(send: PrivCryptSend) -> Self {
        Self(
            Arc::new(Mutex::new(PrivSendInner {
                limit: Arc::new(tokio::sync::Semaphore::new(1)),
                send: Some(send),
            })),
            std::marker::PhantomData,
        )
    }
}

impl<T> AsS3Sender<T> for PrivSend<T>
where
    T: 'static + serde::Serialize + Send,
{
    fn send(&self, t: T) -> BoxFuture<'static, LairResult<()>> {
        let inner = self.0.clone();
        async move {
            let mut se = rmp_serde::encode::Serializer::new(Vec::new())
                .with_struct_map()
                .with_string_variants();
            t.serialize(&mut se).map_err(OneErr::new)?;
            let t = se.into_inner().into_boxed_slice();

            let limit = inner.lock().limit.clone();
            let _permit = limit.acquire_owned().await.map_err(OneErr::new)?;
            let mut send = inner.lock().send.take().unwrap();
            let r = send.send(t).await;
            inner.lock().send = Some(send);
            r
        }
        .boxed()
    }

    fn shutdown(&self) -> BoxFuture<'static, LairResult<()>> {
        let inner = self.0.clone();
        async move {
            let limit = inner.lock().limit.clone();
            let _permit = limit.acquire_owned().await.map_err(OneErr::new)?;
            let mut send = inner.lock().send.take().unwrap();
            let r = send.shutdown().await;
            inner.lock().send = Some(send);
            r
        }
        .boxed()
    }
}

struct PrivRecv<T>(BoxStream<'static, LairResult<T>>);

impl<T> PrivRecv<T>
where
    T: 'static + for<'de> serde::Deserialize<'de> + Send,
{
    pub fn new(recv: PrivCryptRecv) -> Self {
        let recv = futures::stream::try_unfold(recv, |mut recv| async move {
            let msg = match recv.next().await {
                None => return Ok(None),
                Some(msg) => msg?,
            };

            let item: T = rmp_serde::from_read(&*msg).map_err(OneErr::new)?;

            Ok(Some((item, recv)))
        });
        Self(recv.boxed())
    }
}

impl<T> Stream for PrivRecv<T>
where
    T: 'static + for<'de> serde::Deserialize<'de> + Send,
{
    type Item = LairResult<T>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        Stream::poll_next(std::pin::Pin::new(&mut self.0), cx)
    }
}

impl<T> AsS3Receiver<T> for PrivRecv<T> where
    T: 'static + for<'de> serde::Deserialize<'de> + Send
{
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_sodium_secretstream() {
        let (alice, bob) = tokio::io::duplex(4096);
        let (alice_recv, alice_send) = tokio::io::split(alice);
        let alice_fut =
            new_s3_pair::<usize, _, _>(alice_send, alice_recv, false);
        let (bob_recv, bob_send) = tokio::io::split(bob);
        let bob_fut = new_s3_pair::<usize, _, _>(bob_send, bob_recv, true);

        let ((alice_send, mut alice_recv), (bob_send, mut bob_recv)) =
            futures::future::try_join(alice_fut, bob_fut).await.unwrap();

        alice_send.send(42).await.unwrap();
        bob_send.send(99).await.unwrap();

        alice_send.shutdown().await.unwrap();
        bob_send.shutdown().await.unwrap();

        assert_eq!(42, bob_recv.next().await.unwrap().unwrap());
        assert_eq!(99, alice_recv.next().await.unwrap().unwrap());

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
