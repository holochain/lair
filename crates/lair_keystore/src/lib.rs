#![deny(missing_docs)]
#![deny(warnings)]
// it's not possible to specify required
// bounds with the `async fn` syntax.
#![allow(clippy::manual_async_fn)]

//! secret lair private keystore
//!
//! # Usage
//!
//! ## Communications  Protocol
//!
//! See [docs/protocol.md](./docs/protocol.md)

include!(concat!(env!("OUT_DIR"), "/ver.rs"));

use crate::store::EntryStoreSender;
use lair_keystore_api::*;
use std::io::{BufRead, BufReader, Error, ErrorKind};
use std::sync::Arc;

pub mod internal;

pub mod store;

pub mod ipc;

/// Main loop of lair executable.
pub async fn execute_lair() -> LairResult<()> {
    let mut config = Config::builder();

    if let Some(lair_dir) = std::env::var_os("LAIR_DIR") {
        config = config.set_root_path(lair_dir);
    }

    let config = config.build();

    println!("#lair-keystore-dir:{:?}#", config.get_root_path());

    let internal::pid_check::PidCheckResult {} =
        internal::pid_check::pid_check(&config)?;

    ipc::spawn_bind_server_ipc(config).await?;

    Ok(())
}

/// Gen loop of lair executable with file path.
pub async fn execute_load_ed25519_keypair_from_file(
    load_ed25519_keypair_from_file: std::path::PathBuf,
    passphrase: sodoken::BufRead,
) -> LairResult<()> {
    use std::fs::File;
    let file = File::open(load_ed25519_keypair_from_file)?;
    let encrypted_blob = BufReader::new(file)
        .lines()
        .map(|line| {
            line.and_then(|v| {
                v.parse().map_err(|e| Error::new(ErrorKind::InvalidData, e))
            })
        })
        .collect::<Result<Vec<u8>, Error>>()?;
    execute_load_ed25519_keypair(encrypted_blob.to_vec(), passphrase).await
}

/// Gen loop of lair executable with encrypted blob.
pub async fn execute_load_ed25519_keypair(
    load_ed25519_keypair: Vec<u8>,
    passphrase: sodoken::BufRead,
) -> LairResult<()> {
    let mut config = Config::builder();

    if let Some(lair_dir) = std::env::var_os("LAIR_DIR") {
        config = config.set_root_path(lair_dir);
    }

    let config = config.build();

    println!("#lair-keystore-dir:{:?}#", config.get_root_path());

    let internal::pid_check::PidCheckResult {} =
        internal::pid_check::pid_check(&config)?;

    let db_key = read_or_generate_db_key(config.clone(), passphrase).await?;

    let store_actor = store::spawn_entry_store_actor(config, db_key).await?;

    let keypair = entry::EntrySignEd25519 {
        priv_key:
            lair_keystore_api::internal::sign_ed25519::SignEd25519PrivKey::from(
                load_ed25519_keypair[64..].to_vec(),
            ),
        pub_key:
            lair_keystore_api::internal::sign_ed25519::SignEd25519PubKey::from(
                load_ed25519_keypair[32..64].to_vec(),
            ),
    };

    store_actor
        .add_initial_sign_ed25519_keypair(keypair)
        .await?;
    Ok(())
}

pub(crate) async fn read_or_generate_db_key(
    config: Arc<Config>,
    passphrase: sodoken::BufRead,
) -> LairResult<sodoken::BufReadSized<32>> {
    let db_key_path = config.get_db_key_path().to_owned();
    match tokio::fs::read(db_key_path.clone()).await {
        Ok(content) => {
            use sodoken::argon2id::SALTBYTES;

            // read the salt from the file
            let salt: sodoken::BufReadSized<SALTBYTES> =
                (&content[0..SALTBYTES]).into();

            // calculate the pre_key given salt and passphrase
            let pre_key = sodoken::BufWriteSized::new_mem_locked()?;
            sodoken::argon2id::hash(
                pre_key.clone(),
                passphrase,
                salt,
                sodoken::argon2id::OPSLIMIT_SENSITIVE,
                sodoken::argon2id::MEMLIMIT_SENSITIVE,
            )
            .await?;

            // extract our message parts
            use sodoken::secretstream_xchacha20poly1305::*;
            let header: sodoken::BufReadSized<SECRETSTREAM_HEADERBYTES> =
                (&content[32..32 + SECRETSTREAM_HEADERBYTES]).into();
            let cipher = sodoken::BufRead::new_no_lock(
                &content[32 + SECRETSTREAM_HEADERBYTES..],
            );

            // decrypt the db key given our calculated pre_key
            let mut dec = SecretStreamDecrypt::new(pre_key, header)?;
            let db_key = sodoken::BufWriteSized::new_mem_locked()?;
            dec.pull(
                cipher,
                <Option<sodoken::BufRead>>::None,
                // erm... fix this in sodoken
                db_key.to_write_unsized().to_extend(),
            )
            .await?;

            Ok(db_key.to_read_sized())
        }
        Err(_) => {
            // generate a new random salt
            let salt = sodoken::BufWriteSized::new_no_lock();
            sodoken::random::randombytes_buf(salt.clone()).await?;

            // calculate the pre_key given salt and passphrase
            let pre_key = sodoken::BufWriteSized::new_mem_locked()?;
            sodoken::argon2id::hash(
                pre_key.clone(),
                passphrase,
                salt.clone(),
                sodoken::argon2id::OPSLIMIT_SENSITIVE,
                sodoken::argon2id::MEMLIMIT_SENSITIVE,
            )
            .await?;

            // generate a new random db_key
            let db_key = sodoken::BufWriteSized::new_mem_locked()?;
            sodoken::random::randombytes_buf(db_key.clone()).await?;

            // encrypt the db_key with the pre_key
            use sodoken::secretstream_xchacha20poly1305::*;
            let cipher = sodoken::BufWrite::new_unbound_no_lock();
            cipher
                .to_extend()
                .extend_lock()
                .extend_mut_from_slice(&*salt.read_lock())?;

            let mut enc = SecretStreamEncrypt::new(pre_key, cipher.clone())?;
            enc.push_final(
                db_key.clone(),
                <Option<sodoken::BufRead>>::None,
                cipher.clone(),
            )
            .await?;

            // write the salt and cipher to the db key file
            // erm... this is annoying...
            let data = cipher.read_lock().to_vec();
            tokio::fs::write(db_key_path, &data).await?;

            Ok(db_key.to_read_sized())
        }
    }
}
