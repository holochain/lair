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

    /// generates a keystore with a provided key.
    #[structopt(
        long,
        help = "Loads a signature keypair from a yaml 
file into the keystore and exits."
    )]
    load_ed25519_keypair_from_yaml: Option<std::path::PathBuf>,

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

    if let Some(load_ed25519_keypair_from_yaml) =
        opt.load_ed25519_keypair_from_yaml
    {
        println!(
            "Creating a lair-keystore with provided keys at {:?}",
            load_ed25519_keypair_from_yaml
        );
        trace!("executing lair gen tasks");
        return lair_keystore::execute_load_ed25519_keypair_from_yaml(
            load_ed25519_keypair_from_yaml,
        )
        .await;
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
