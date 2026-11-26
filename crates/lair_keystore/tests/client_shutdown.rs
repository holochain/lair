use futures::stream::StreamExt;
use lair_keystore_api::dependencies::*;
use lair_keystore_api::lair_client::async_io::new_async_io_lair_client;
use lair_keystore_api::prelude::*;
use lair_keystore_api::sodium_secretstream;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::io::AsyncWrite;

type ShutdownWait = Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

/// AsyncWrite wrapper whose shutdown blocks until the gate is opened.
struct GatedShutdown<S> {
    inner: S,
    started: Arc<tokio::sync::Semaphore>,
    gate: Arc<tokio::sync::Notify>,
    wait: Option<ShutdownWait>,
    open: bool,
}

impl<S: AsyncWrite + Unpin + Send + 'static> AsyncWrite for GatedShutdown<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if !this.open {
            if let Some(wait) = this.wait.as_mut() {
                match wait.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(()) => this.open = true,
                }
            } else {
                this.started.add_permits(1);
                let gate = this.gate.clone();
                this.wait = Some(Box::pin(async move {
                    gate.notified().await;
                }));
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_shutdown_awaits_single_teardown() {
    // server identity keypair
    let mut pk = [0; sodoken::crypto_box::XSALSA_PUBLICKEYBYTES];
    let mut sk = sodoken::SizedLockedArray::<
        { sodoken::crypto_box::XSALSA_SECRETKEYBYTES },
    >::new()
    .unwrap();
    sodoken::crypto_box::xsalsa_keypair(&mut pk, &mut sk.lock()).unwrap();
    let pk = Arc::new(pk);
    let sk = Arc::new(Mutex::new(sk));

    let started = Arc::new(tokio::sync::Semaphore::new(0));
    let send_gate = Arc::new(tokio::sync::Notify::new());
    let recv_gate = Arc::new(tokio::sync::Notify::new());

    let (cli, srv) = tokio::io::duplex(4096);
    let (cli_recv, cli_send) = tokio::io::split(cli);
    let (srv_recv, srv_send) = tokio::io::split(srv);

    // remote peer: finish the handshake, read until the client closes, then
    // wait for the test before closing its own write side
    let peer = tokio::spawn({
        let pk = pk.clone();
        let sk = sk.clone();
        let recv_gate = recv_gate.clone();
        async move {
            let (send, mut recv) =
                sodium_secretstream::new_s3_server::<LairApiEnum, _, _>(
                    srv_send, srv_recv, pk, sk,
                )
                .await
                .unwrap();
            while recv.next().await.is_some() {}
            recv_gate.notified().await;
            send.shutdown().await.unwrap();
        }
    });

    let client = new_async_io_lair_client(
        GatedShutdown {
            inner: cli_send,
            started: started.clone(),
            gate: send_gate.clone(),
            wait: None,
            open: false,
        },
        cli_recv,
        (*pk).into(),
    )
    .await
    .unwrap();

    // shutdown completions are observed over a channel; the join handles are
    // only awaited once, at the end, so a completed handle is never re-polled
    let (done_tx, mut done_rx) = tokio::sync::mpsc::unbounded_channel();

    // the first shutdown parks in the write-side shutdown
    let first = {
        let client = client.clone();
        let done_tx = done_tx.clone();
        tokio::spawn(async move {
            let r = client.shutdown().await;
            let _ = done_tx.send("first");
            r
        })
    };
    started.acquire().await.unwrap().forget();

    // requests are rejected immediately, before teardown completes
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        client.list_entries(),
    )
    .await
    .expect("request during shutdown hung")
    .expect_err("request during shutdown should fail");

    // a concurrent shutdown must await the same teardown
    let second = {
        let client = client.clone();
        let done_tx = done_tx.clone();
        tokio::spawn(async move {
            let r = client.shutdown().await;
            let _ = done_tx.send("second");
            r
        })
    };
    drop(done_tx);

    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(50),
            done_rx.recv(),
        )
        .await
        .is_err(),
        "a shutdown returned before teardown completed"
    );

    // let the write side close; the remote still holds its side open
    send_gate.notify_one();
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(50),
            done_rx.recv(),
        )
        .await
        .is_err(),
        "shutdown returned before the recv loop ended"
    );

    // let the remote close so the recv loop can end
    recv_gate.notify_one();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        first.await.unwrap().unwrap();
        second.await.unwrap().unwrap();
    })
    .await
    .expect("shutdown did not complete");
    peer.await.unwrap();

    // requests still fail fast after teardown
    client
        .list_entries()
        .await
        .expect_err("request after shutdown should fail");
}
