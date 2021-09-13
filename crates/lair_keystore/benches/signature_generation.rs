use criterion::{black_box, criterion_group, criterion_main, Criterion};
use lair_keystore_api::actor::*;
use lair_keystore_api::*;
use once_cell::sync::Lazy;
use std::sync::Arc;

static TOKIO: Lazy<tokio::runtime::Runtime> = Lazy::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
});

struct BenchStatic {
    pub _tmpdir: tempfile::TempDir,
    pub api_send: ghost_actor::GhostSender<LairClientApi>,
    pub sign_idx: KeystoreIndex,
}

impl BenchStatic {
    pub fn new() -> Self {
        let (tmpdir, api_send, sign_idx) = TOKIO.block_on(async move {
            let tmpdir = tempfile::tempdir().unwrap();
            std::env::set_var("LAIR_DIR", tmpdir.path());

            lair_keystore::execute_lair().await.unwrap();

            let config = Config::builder().set_root_path(tmpdir.path()).build();

            let passphrase = sodoken::BufRead::from(&b"passphrase"[..]);
            let api_send =
                ipc::spawn_client_ipc(config, passphrase).await.unwrap();

            let info = api_send.lair_get_server_info().await.unwrap();
            assert_eq!("lair-keystore", &info.name);

            let (sign_idx, _sign_pub_key) =
                api_send.sign_ed25519_new_from_entropy().await.unwrap();

            (tmpdir, api_send, sign_idx)
        });

        Self {
            _tmpdir: tmpdir,
            api_send,
            sign_idx,
        }
    }
}

static STATIC: Lazy<Arc<BenchStatic>> =
    Lazy::new(|| Arc::new(BenchStatic::new()));

fn sign_small() {
    let bench = &*STATIC;
    TOKIO.block_on(async move {
        let _result = bench
            .api_send
            .sign_ed25519_sign_by_index(
                bench.sign_idx,
                black_box(vec![0xdb; 32].into()),
            )
            .await
            .unwrap();
    });
}

fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("signature_generation");
    group.bench_function("sign_small_message", |b| b.iter(|| sign_small()));
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
