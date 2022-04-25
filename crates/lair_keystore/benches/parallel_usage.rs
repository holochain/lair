use criterion::{criterion_group, criterion_main, Criterion};
use lair_keystore_api::actor::*;
use lair_keystore_api::*;
use once_cell::sync::Lazy;
use std::sync::atomic;

static TOKIO: Lazy<tokio::runtime::Runtime> = Lazy::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
});

const CLIENT_COUNT: usize = 20;

const INIT_VAL: atomic::AtomicU32 = atomic::AtomicU32::new(0);
static RECENT_IDX: [atomic::AtomicU32; CLIENT_COUNT] = [INIT_VAL; CLIENT_COUNT];

async fn init() -> (
    tempfile::TempDir,
    Box<[ghost_actor::GhostSender<LairClientApi>]>,
) {
    let tmpdir = tempfile::tempdir().unwrap();
    std::env::set_var("LAIR_DIR", tmpdir.path());

    lair_keystore::execute_lair(false).await.unwrap();

    let config = Config::builder().set_root_path(tmpdir.path()).build();

    let passphrase = sodoken::BufRead::from(&b"passphrase"[..]);

    let mut api_list = Vec::with_capacity(CLIENT_COUNT);
    for i in 0..CLIENT_COUNT {
        let api_send =
            ipc::spawn_client_ipc(config.clone(), passphrase.clone())
                .await
                .unwrap();

        let info = api_send.lair_get_server_info().await.unwrap();
        assert_eq!("lair-keystore", &info.name);

        let (sign_idx, _pk) =
            api_send.sign_ed25519_new_from_entropy().await.unwrap();

        api_list.push(api_send);
        RECENT_IDX[i].store(sign_idx.into(), atomic::Ordering::Relaxed);
    }

    (tmpdir, api_list.into_boxed_slice())
}

const SIG_DATA: &[u8] = &[0xdb; 4096];

fn parallel(api_list: Box<[ghost_actor::GhostSender<LairClientApi>]>) {
    TOKIO.block_on(async move {
        let mut all = Vec::new();

        for i in 0..CLIENT_COUNT {
            // first, set up write task
            let api_send = api_list[i].clone();
            all.push(tokio::task::spawn(async move {
                let (sign_idx, _pk) =
                    api_send.sign_ed25519_new_from_entropy().await.unwrap();
                RECENT_IDX[i].store(sign_idx.into(), atomic::Ordering::Relaxed);
            }));

            // now, set up read task
            let api_send = api_list[i].clone();
            all.push(tokio::task::spawn(async move {
                let sign_idx = RECENT_IDX[i].load(atomic::Ordering::Relaxed);
                let _ = api_send
                    .sign_ed25519_sign_by_index(
                        sign_idx.into(),
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
    let (_tmpdir, api_list) = TOKIO.block_on(init());

    let mut group = c.benchmark_group("parallel_usage");
    group.bench_function("parallel", |b| b.iter(|| parallel(api_list.clone())));
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
