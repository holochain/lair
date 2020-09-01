#![deny(warnings)]
#![deny(missing_docs)]
//! main entry point

use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "lair-keystore")]
struct Opt {
    /// Print out version info and exit.
    #[structopt(short, long)]
    version: bool,

    /// Set the lair data directory.
    #[structopt(short = "d", long, env = "LAIR_DIR")]
    lair_dir: Option<std::path::PathBuf>,
}

/// main entry point
#[tokio::main]
pub async fn main() -> lair_keystore_api::LairResult<()> {
    let opt = Opt::from_args();

    if opt.version {
        println!("lair-keystore {}", lair_keystore::LAIR_VER);
        return Ok(());
    }

    if let Some(lair_dir) = opt.lair_dir {
        std::env::set_var("LAIR_DIR", lair_dir);
    }

    lair_keystore::execute_lair().await?;

    // print our "ready to accept connections" message
    println!("#lair-keystore-ready#");
    println!("#lair-keystore-version:{}#", lair_keystore::LAIR_VER);

    // wait forever... i.e. until a ctrl-c
    futures::future::pending::<()>().await;

    Ok(())
}
