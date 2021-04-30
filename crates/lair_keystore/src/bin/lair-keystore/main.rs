#![deny(warnings)]
#![deny(missing_docs)]
//! main entry point

use structopt::StructOpt;
use tracing::*;

#[derive(Debug, StructOpt)]
#[structopt(name = "lair-keystore")]
struct Opt {
    /// Print out version info and exit.
    #[structopt(short, long)]
    version: bool,

    /// Set the lair data directory.
    #[structopt(short = "d", long, env = "LAIR_DIR", help = "lair will run as an IPC process using this directory as its root for all aspects of persistence. a platform specific dir will be used as a default equal to directories::ProjectDirs::from(\"host\", \"Holo\", \"Lair\")"))]
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
