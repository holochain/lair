use common::{connect_with_config, create_config};
use lair_keystore_api::dependencies::{sodoken, tokio};
use parking_lot::Mutex;
use std::sync::Arc;

mod common;

#[cfg(not(windows))] // No encryption on Windows, ignore this test
#[tokio::test(flavor = "multi_thread")]
async fn migrate_unencrypted() {
    use rusqlite::Connection;

    let tmpdir = tempdir::TempDir::new("lair keystore test").unwrap();

    let passphrase = Arc::new(Mutex::new(sodoken::LockedArray::from(
        b"passphrase".to_vec(),
    )));

    let config = create_config(&tmpdir, passphrase.clone()).await;

    // Set up an unencrypted database, by not setting a key on the connection
    {
        let conn = Connection::open(&config.store_file).unwrap();

        // Needs to contain data otherwise encryption will just succeed!
        conn.execute("CREATE TABLE migrate_me (name TEXT NOT NULL)", ())
            .unwrap();
        conn.execute(
            "INSERT INTO migrate_me (name) VALUES ('hello_migrated')",
            (),
        )
        .unwrap();

        conn.close().unwrap();
    }

    match connect_with_config(config.clone(), passphrase.clone()).await {
        Ok(_) => {
            panic!("Shouldn't have been able to spawn lair-keystore");
        }
        Err(_) => {
            // That's good, we shouldn't have been able to connect because the database won't auto-migrate without `LAIR_MIGRATE_UNENCRYPTED`
        }
    }

    std::env::set_var("LAIR_MIGRATE_UNENCRYPTED", "true");

    connect_with_config(config.clone(), passphrase.clone())
        .await
        .unwrap();
}
