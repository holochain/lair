use criterion::{criterion_group, criterion_main, Criterion};
use lair_keystore_api::actor::*;
use lair_keystore_api::*;
use once_cell::sync::Lazy;

static TOKIO: Lazy<tokio::runtime::Runtime> = Lazy::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
});

async fn init() -> (
    tempfile::TempDir,
    ghost_actor::GhostSender<LairClientApi>,
    KeystoreIndex,
) {
    let tmpdir = tempfile::tempdir().unwrap();
    std::env::set_var("LAIR_DIR", tmpdir.path());

    lair_keystore::execute_lair().await.unwrap();

    let config = Config::builder().set_root_path(tmpdir.path()).build();

    let passphrase = sodoken::BufRead::from(&b"passphrase"[..]);
    let api_send = ipc::spawn_client_ipc(config, passphrase).await.unwrap();

    let info = api_send.lair_get_server_info().await.unwrap();
    assert_eq!("lair-keystore", &info.name);

    let (sign_idx, _pk) =
        api_send.sign_ed25519_new_from_entropy().await.unwrap();

    (tmpdir, api_send, sign_idx)
}

const SIG_DATA: &[u8] = &[0xdb; 32];

fn parallel(
    sign_idx: KeystoreIndex,
    api_send: ghost_actor::GhostSender<LairClientApi>,
) {
    TOKIO.block_on(async move {
        let mut all = Vec::new();

        // first, set up write tasks
        for _ in 0..10 {
            let api_send = api_send.clone();
            all.push(tokio::task::spawn(async move {
                let _ = api_send.sign_ed25519_new_from_entropy().await.unwrap();
            }));
        }

        // now, set up read tasks
        for _ in 0..100 {
            let api_send = api_send.clone();
            all.push(tokio::task::spawn(async move {
                let _ = api_send
                    .sign_ed25519_sign_by_index(
                        sign_idx,
                        SIG_DATA.to_vec().into(),
                    )
                    .await
                    .unwrap();
            }));
        }

        futures::future::try_join_all(all).await.unwrap();
    });
}

fn bench(c: &mut Criterion) {
    let (_tmpdir, api_send, sign_idx) = TOKIO.block_on(init());

    let mut group = c.benchmark_group("parallel_usage");
    group.bench_function("parallel", |b| {
        b.iter(|| parallel(sign_idx, api_send.clone()))
    });
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
