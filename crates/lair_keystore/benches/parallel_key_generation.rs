use criterion::{criterion_group, criterion_main, Criterion};
use futures::{future::FutureExt, stream::StreamExt};
use lair_keystore_api::actor::*;
use lair_keystore_api::*;
use once_cell::sync::Lazy;

static TOKIO: Lazy<tokio::runtime::Runtime> = Lazy::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
});

async fn init() -> (tempfile::TempDir, ghost_actor::GhostSender<LairClientApi>) {
    let tmpdir = tempfile::tempdir().unwrap();
    std::env::set_var("LAIR_DIR", tmpdir.path());

    lair_keystore::execute_lair().await.unwrap();

    let config = Config::builder().set_root_path(tmpdir.path()).build();

    let (api_send, mut evt_recv) =
        ipc::spawn_client_ipc(config).await.unwrap();

    tokio::task::spawn(async move {
        while let Some(msg) = evt_recv.next().await {
            match msg {
                LairClientEvent::RequestUnlockPassphrase {
                    respond,
                    ..
                } => {
                    respond.respond(Ok(async move {
                        Ok("passphrase".to_string())
                    }
                    .boxed()
                    .into()));
                }
            }
        }
    });

    let info = api_send.lair_get_server_info().await.unwrap();
    assert_eq!("lair-keystore", &info.name);

    (tmpdir, api_send)
}

fn parallel(api_send: ghost_actor::GhostSender<LairClientApi>) {
    TOKIO.block_on(async move {
        let mut all = Vec::new();
        for _ in 0..10 {
            let api_send = api_send.clone();
            all.push(tokio::task::spawn(async move {
                let _ = api_send.sign_ed25519_new_from_entropy().await.unwrap();
            }));
        }
        futures::future::try_join_all(all).await.unwrap();
    });
}

fn bench(c: &mut Criterion) {
    let (_tmpdir, api_send) = TOKIO.block_on(init());

    let mut group = c.benchmark_group("parallel_key_generation");
    group.bench_function("parallel", |b| b.iter(|| parallel(api_send.clone())));
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
