use ghost_actor::GhostControlSender;
use lair_keystore_api::actor::LairClientApiSender;

#[should_panic]
#[tokio::test(flavor = "multi_thread")]
async fn panicky_should_panic() {
    let orig_handler = std::panic::take_hook();

    // this test is backwards, we need to NOT error to fail the test
    macro_rules! no_err {
        ($t:expr) => {
            match $t {
                Err(e) => {
                    eprintln!("error: {:?}", e);
                    return;
                }
                Ok(r) => r,
            }
        };
    }

    let tmpdir = no_err!(tempfile::tempdir());
    std::env::set_var("LAIR_DIR", tmpdir.path());

    // set panicky to TRUE
    no_err!(lair_keystore::execute_lair(true).await);

    let did_panic =
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

    {
        let did_panic = did_panic.clone();
        // this is a bit loopy... but we need to undo
        // the panic handler that gets install in the execute lair
        // and replace it with the one installed in this test hook
        std::panic::set_hook(Box::new(move |panic_info| {
            eprintln!("GOT PANIC");
            did_panic.store(true, std::sync::atomic::Ordering::SeqCst);
            orig_handler(panic_info);
        }));
    }

    let passphrase = sodoken::BufRead::new_no_lock(b"passphrase");
    let config = lair_keystore_api::Config::builder()
        .set_root_path(tmpdir.path())
        .build();

    no_err!(std::fs::metadata(config.get_socket_path()));

    let api_send = no_err!(
        lair_keystore_api::ipc::spawn_client_ipc(
            config.clone(),
            passphrase.clone(),
        )
        .await
    );

    no_err!(api_send.lair_get_server_info().await);

    no_err!(api_send.ghost_actor_shutdown_immediate().await);
    drop(api_send);

    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    if did_panic.load(std::sync::atomic::Ordering::SeqCst) {
        println!("CALLING PANIC");
        panic!("ipc server paniced on client shutdown");
    }
}
