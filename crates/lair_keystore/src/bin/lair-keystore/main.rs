#![deny(warnings)]
#![deny(missing_docs)]
//! main entry point

use structopt::StructOpt;
use tracing::*;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "lair-keystore"
    help = "lair-keystore runs an IPC process for handling the most private data (like private keys) on behalf of Holochain with a very high regard for security.
    One and only one `holochain` instance should talk to one `lair-keystore` instance.
    lair-keystore runs tied to a configurable directory.
    If multiple lair-keystore instances are run they must be run from separate directories.
    A platform specific directory will be used as a default which will be equal to directories::ProjectDirs::from(\"host\", \"Holo\", \"Lair\")
    https://docs.rs/directories/3.0.2/directories/struct.ProjectDirs.html#examples"
)]
struct Opt {
    /// Print out version info and exit.
    #[structopt(short, long)]
    version: bool,

    /// Set the lair data directory.
    #[structopt(
        short = "d",
        long,
        env = "LAIR_DIR",
        help = "Can be used to override the default keystore directory to run multiple instances or for other purposes"
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
