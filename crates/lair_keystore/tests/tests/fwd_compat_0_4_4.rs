use lair_keystore::dependencies::*;
use lair_keystore_api::prelude::*;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

#[cfg(not(windows))]
const NAME: &str = "lair-keystore-0.4.4";

#[cfg(windows)]
const NAME: &str = "lair-keystore-0.4.4.exe";

const PASSPHRASE: &[u8] = b"passphrase";

const TAG1: &str = "TAG1";
const TAG2: &str = "TAG2";

#[tokio::test(flavor = "multi_thread")]
async fn fwd_compat_0_4_4() {
    let tmpdir = tempdir::TempDir::new("lair_fwd_044").unwrap();

    println!("{tmpdir:?}");

    // -- make sure we have the correct 0.4.4 version avaliable -- //

    let mut cmd = tokio::process::Command::new(NAME);

    cmd.arg("--version");

    eprintln!("{cmd:?}");

    let ver = cmd
        .output()
        .await
        .expect("please ensure above command is on the PATH");

    assert!(ver.status.success());
    assert_eq!(b"lair_keystore 0.4.4\n", ver.stdout.as_slice());

    // -- initialize the 0.4.4 keystore -- //

    let mut cmd = tokio::process::Command::new(NAME);

    cmd.arg("--lair-root")
        .arg(tmpdir.path())
        .arg("init")
        .arg("--piped")
        .stdin(std::process::Stdio::piped());

    eprintln!("{cmd:?}");

    let mut init = cmd.spawn().unwrap();
    let mut stdin = init.stdin.take().unwrap();
    stdin.write_all(PASSPHRASE).await.unwrap();
    stdin.shutdown().await.unwrap();
    drop(stdin);

    let init = init.wait_with_output().await.unwrap();

    assert!(init.status.success());
    println!("{}", String::from_utf8_lossy(init.stdout.as_slice()));

    // -- fetch the connection string -- //

    let mut cmd = tokio::process::Command::new(NAME);

    cmd.arg("--lair-root").arg(tmpdir.path()).arg("url");

    eprintln!("{cmd:?}");

    let s_url = cmd
        .output()
        .await
        .expect("please ensure above command is on the PATH");

    assert!(s_url.status.success());
    let s_url = String::from_utf8_lossy(s_url.stdout.as_slice()).to_string();
    let s_url = url::Url::parse(&s_url).unwrap();

    println!("s_url: {s_url}");

    // -- run the actual server -- //

    let mut cmd = tokio::process::Command::new(NAME);

    cmd.arg("--lair-root")
        .arg(tmpdir.path())
        .arg("server")
        .arg("--piped")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped());

    eprintln!("{cmd:?}");

    let mut server = cmd.spawn().unwrap();
    let mut stdin = server.stdin.take().unwrap();
    stdin.write_all(PASSPHRASE).await.unwrap();
    stdin.shutdown().await.unwrap();
    drop(stdin);

    let mut server_lines =
        tokio::io::BufReader::new(server.stdout.take().unwrap()).lines();

    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let line = server_lines.next_line().await.unwrap().unwrap();
            println!("-:=:- {line}");
            if line.contains("lair-keystore running") {
                break;
            }
        }
    })
    .await
    .unwrap();

    // -- connect a client and insert data into the store -- //

    let client044 = lair_keystore_api::ipc_keystore::ipc_keystore_connect(
        s_url.clone(),
        PASSPHRASE,
    )
    .await
    .unwrap();

    let _seed_info_ref =
        client044.new_seed(TAG1.into(), None, true).await.unwrap();

    let _wka_cert = client044.new_wka_tls_cert(TAG2.into()).await.unwrap();

    // -- shut down the 044 client and server -- //

    client044.shutdown().await.unwrap();
    drop(client044);
    server.kill().await.unwrap();
    drop(server);

    // -- run the new server using the 044 store -- //

    let mut config_path = tmpdir.path().to_owned();
    config_path.push("lair-keystore-config.yaml");
    let config = tokio::fs::read(&config_path).await.unwrap();

    println!("{}", String::from_utf8_lossy(&config));

    let config = LairServerConfigInner::from_bytes(&config).unwrap();

    lair_keystore::server::StandaloneServer::new(Arc::new(config))
        .await
        .unwrap()
        .run(PASSPHRASE)
        .await
        .unwrap();

    // -- connect a client to the new server and check functionality -- //

    let client = lair_keystore_api::ipc_keystore::ipc_keystore_connect(
        s_url.clone(),
        PASSPHRASE,
    )
    .await
    .unwrap();

    let entry_list = client.list_entries().await.unwrap();

    assert_eq!(2, entry_list.len());

    for entry in entry_list {
        match entry {
            LairEntryInfo::Seed { tag, .. } => {
                assert_eq!(TAG1, &*tag);
            }
            LairEntryInfo::WkaTlsCert { tag, .. } => {
                assert_eq!(TAG2, &*tag);
            }
            oth => panic!("unexpected: {:?}", oth),
        }
    }

    let entry = match client.get_entry(TAG1.into()).await.unwrap() {
        LairEntryInfo::Seed { seed_info, .. } => seed_info,
        _ => panic!(),
    };

    let sig = client
        .sign_by_pub_key(
            entry.ed25519_pub_key.clone(),
            None,
            b"hello".to_vec().into(),
        )
        .await
        .unwrap();
    assert!(entry
        .ed25519_pub_key
        .verify_detached(sig, &b"hello"[..])
        .await
        .unwrap());

    // secretbox encrypt some data
    let (nonce, cipher) = client
        .secretbox_xsalsa_by_tag(TAG1.into(), None, b"hello".to_vec().into())
        .await
        .unwrap();

    // make sure we can decrypt our own message
    let msg = client
        .secretbox_xsalsa_open_by_tag(TAG1.into(), None, nonce, cipher)
        .await
        .unwrap();

    assert_eq!(b"hello", &*msg);

    // try exporting the seed (just to ourselves)
    let _ = client
        .export_seed_by_tag(
            TAG1.into(),
            entry.x25519_pub_key.clone(),
            entry.x25519_pub_key.clone(),
            None,
        )
        .await
        .unwrap();
}
