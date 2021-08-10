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

use sodoken::argon2id::SALTBYTES;
use sodoken::secretstream_xchacha20poly1305::*;

#[derive(Clone)]
pub(crate) struct DbKeyEnc {
    pub salt: sodoken::BufReadSized<SALTBYTES>,
    pub header: sodoken::BufReadSized<SECRETSTREAM_HEADERBYTES>,
    pub cipher: sodoken::BufRead,
}

impl DbKeyEnc {
    pub async fn read(config: &Config) -> LairResult<Self> {
        let db_key_path = config.get_db_key_path();

        let content = tokio::fs::read(db_key_path)
            .await
            .map_err(LairError::other)?;

        let salt: sodoken::BufReadSized<SALTBYTES> =
            (&content[0..SALTBYTES]).into();

        let header: sodoken::BufReadSized<SECRETSTREAM_HEADERBYTES> =
            (&content[SALTBYTES..SALTBYTES + SECRETSTREAM_HEADERBYTES]).into();

        let cipher = sodoken::BufRead::new_no_lock(
            &content[SALTBYTES + SECRETSTREAM_HEADERBYTES..],
        );

        Ok(Self {
            salt,
            header,
            cipher,
        })
    }

    /// write the salt and cipher to the db key file
    pub async fn write(&self, config: &Config) -> LairResult<()> {
        let db_key_path = config.get_db_key_path();

        let mut data = Vec::with_capacity(
            self.salt.len() + self.header.len() + self.cipher.len(),
        );

        data.extend_from_slice(&*self.salt.read_lock());
        data.extend_from_slice(&*self.header.read_lock());
        data.extend_from_slice(&*self.cipher.read_lock());

        tokio::fs::write(db_key_path, &data)
            .await
            .map_err(LairError::other)?;

        Ok(())
    }

    async fn calc_pre_key(
        passphrase: sodoken::BufRead,
        salt: sodoken::BufReadSized<SALTBYTES>,
    ) -> LairResult<sodoken::BufReadSized<32>> {
        use once_cell::sync::Lazy;

        // argon is designed to be both cpu and memory hard
        // from a cpu perspective it doesn't make sense to run more
        // argons than the number of cpus we have.
        // from a memory perspective, if we run too many at a time,
        // we end up with horrible slow things like memory virtualization.
        // MODERATE limits with min(num_cpus::get(), 4) seems to work ok.
        static ARGON_LIMIT: Lazy<Arc<tokio::sync::Semaphore>> =
            Lazy::new(|| {
                Arc::new(tokio::sync::Semaphore::new(std::cmp::min(
                    num_cpus::get(),
                    4,
                )))
            });
        let _permit = ARGON_LIMIT
            .clone()
            .acquire_owned()
            .await
            .expect("this semaphore is never closed");

        let pre_key = sodoken::BufWriteSized::new_mem_locked()?;
        sodoken::argon2id::hash(
            pre_key.clone(),
            passphrase,
            salt,
            sodoken::argon2id::OPSLIMIT_MODERATE,
            sodoken::argon2id::MEMLIMIT_MODERATE,
        )
        .await
        .map_err(|e| LairError::from(format!("argon fail: {:?}", e)))?;
        Ok(pre_key.to_read_sized())
    }

    pub async fn calc_db_key(
        &self,
        passphrase: sodoken::BufRead,
    ) -> LairResult<sodoken::BufReadSized<32>> {
        // calculate the pre_key given salt and passphrase
        let pre_key = Self::calc_pre_key(passphrase, self.salt.clone()).await?;

        // decrypt the db key given our calculated pre_key
        let mut dec = SecretStreamDecrypt::new(pre_key, self.header.clone())
            .map_err(|e| {
                LairError::from(format!("decrypt new fail: {:?}", e))
            })?;

        let db_key = sodoken::BufWriteSized::new_mem_locked()?;
        dec.pull(
            self.cipher.clone(),
            <Option<sodoken::BufRead>>::None,
            db_key.clone(),
        )
        .await
        .map_err(|e| LairError::from(format!("decrypt pull fail: {:?}", e)))?;

        Ok(db_key.to_read_sized())
    }

    pub async fn generate(
        passphrase: sodoken::BufRead,
    ) -> LairResult<(Self, sodoken::BufReadSized<32>)> {
        // generate a new random salt
        let salt = sodoken::BufWriteSized::new_no_lock();
        sodoken::random::randombytes_buf(salt.clone()).await?;

        // calculate the pre_key given salt and passphrase
        let pre_key =
            Self::calc_pre_key(passphrase, salt.to_read_sized()).await?;

        // generate a new random db_key
        let db_key = sodoken::BufWriteSized::new_mem_locked()?;
        sodoken::random::randombytes_buf(db_key.clone()).await?;

        let header = sodoken::BufWriteSized::new_no_lock();
        let mut enc = SecretStreamEncrypt::new(pre_key, header.clone())?;

        let cipher = sodoken::BufWrite::new_unbound_no_lock();
        enc.push_final(
            db_key.clone(),
            <Option<sodoken::BufRead>>::None,
            cipher.clone(),
        )
        .await?;

        Ok((
            Self {
                salt: salt.to_read_sized(),
                header: header.to_read_sized(),
                cipher: cipher.to_read(),
            },
            db_key.to_read_sized(),
        ))
    }
}

pub(crate) async fn read_or_generate_db_key(
    config: Arc<Config>,
    passphrase: sodoken::BufRead,
) -> LairResult<sodoken::BufReadSized<32>> {
    match DbKeyEnc::read(&config).await {
        Ok(dbk_enc) => dbk_enc.calc_db_key(passphrase).await,
        Err(_) => {
            let (dbk_enc, db_key) = DbKeyEnc::generate(passphrase).await?;
            dbk_enc.write(&config).await?;
            Ok(db_key)
        }
    }
}
