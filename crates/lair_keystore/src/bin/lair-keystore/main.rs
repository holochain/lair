#![deny(warnings)]
#![deny(missing_docs)]
//! main entry point

use structopt::StructOpt;
use tracing::*;

static LAIR_KEYSTORE_ABOUT: &str = r#"A secure storage system for Holochain cryptographic keys and secrets.

- one `lair-keystore` per `holochain`
- attaches the secure storage and IPC process
    to a directory configurable via command
    line options. a sensible platform specific
    dir will be used as a default dir (and be
    logged when executed)"#;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "lair-keystore",
    about = LAIR_KEYSTORE_ABOUT
)]
struct Opt {
    /// Print out version info and exit.
    #[structopt(short, long)]
    version: bool,

    /// DANGER! - SECRETS EXPOSED!
    /// - Dump the keystore to stdout.
    /// - Requires --load-db-passphrase
    /// - and don't forget --lair-dir if needed.
    #[structopt(long, verbatim_doc_comment)]
    danger_dump_keystore: bool,

    /// generates a keystore with a provided key.
    #[structopt(
        long,
        help = "Loads a signature keypair from a
file into the keystore and exits."
    )]
    load_ed25519_keypair_from_file: Option<std::path::PathBuf>,

    /// generates a keystore with a provided key.
    #[structopt(
        long,
        help = "Loads a signature keypair from a base64
string into the keystore and exits."
    )]
    load_ed25519_keypair_from_base64: Option<String>,

    /// passphrase to use for injecting keys into the keystore
    /// note, this is not very secure... we should find a
    /// better pattern
    #[structopt(long)]
    load_db_passphrase: Option<String>,

    /// Set the lair data directory.
    #[structopt(
        short = "d",
        long,
        env = "LAIR_DIR",
        help = "Can be used to override the default keystore
directory to run multiple instances or for other purposes"
    )]
    lair_dir: Option<std::path::PathBuf>,
}

/// main entry point
#[tokio::main(flavor = "multi_thread")]
pub async fn main() -> lair_keystore_api::LairResult<()> {
    let _ = subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .finish(),
    );
    trace!("tracing initialized");

    let opt = Opt::from_args();

    if opt.version {
        println!("lair-keystore {}", lair_keystore::LAIR_VER);
        return Ok(());
    }

    if let Some(lair_dir) = opt.lair_dir {
        std::env::set_var("LAIR_DIR", lair_dir);
    }

    let passphrase = opt
        .load_db_passphrase
        .map(|p| sodoken::BufRead::new_no_lock(p.as_bytes()));

    if opt.danger_dump_keystore {
        if passphrase.is_none() {
            panic!(
                "'--load-db-passphrase' required for '--danger-dump-keystore'"
            );
        }
        return lair_keystore::danger_dump_keystore(passphrase.unwrap()).await;
    }

    if let Some(load_ed25519_keypair_from_file) =
        opt.load_ed25519_keypair_from_file
    {
        if passphrase.is_none() {
            panic!("'--load-db-passphrase' required for '--load-ed25519-keypair-from-file'");
        }
        println!(
            "Creating a lair-keystore with provided keys at {:?}",
            load_ed25519_keypair_from_file
        );
        trace!("executing lair gen tasks from file");
        return lair_keystore::execute_load_ed25519_keypair_from_file(
            load_ed25519_keypair_from_file,
            passphrase.unwrap(),
        )
        .await;
    }
    if let Some(load_ed25519_keypair_from_base64) =
        opt.load_ed25519_keypair_from_base64
    {
        if passphrase.is_none() {
            panic!("'--load-db-passphrase' required for '--load-ed25519-keypair-from-base64'");
        }
        println!(
            "Creating a lair-keystore with provided keys {:?}",
            load_ed25519_keypair_from_base64
        );
        trace!("executing lair gen tasks from obj");

        match base64::decode(load_ed25519_keypair_from_base64) {
            Ok(keypair) => {
                return lair_keystore::execute_load_ed25519_keypair(
                    keypair,
                    passphrase.unwrap(),
                )
                .await;
            }
            Err(e) => return Err(lair_keystore_api::LairError::other(e)),
        }
    }

    trace!("executing lair main tasks");
    lair_keystore::execute_lair().await?;

    info!("lair-keystore up and running");

    // print our "ready to accept connections" message
    println!("#lair-keystore-ready#");
    println!("#lair-keystore-version:{}#", lair_keystore::LAIR_VER);

    // wait forever... i.e. until a ctrl-c
    futures::future::pending::<()>().await;

    Ok(())
}
