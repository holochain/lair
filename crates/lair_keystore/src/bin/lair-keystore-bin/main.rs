//! sqlite/sqlcipher backed LairKeystore server control binary

use lair_keystore_api::LairResult;
use structopt::StructOpt;

pub(crate) const CONFIG_N: &str = "lair-keystore-config.yaml";

mod cmd_init;
mod cmd_url;

#[derive(Debug, StructOpt)]
pub(crate) struct OptInit {
    /// Prompt for passphrase interactively.
    #[structopt(short = "i", long)]
    pub interactive: bool,
}

#[derive(Debug, StructOpt)]
enum Cmd {
    /// Set up a new lair private keystore.
    /// Currently '-i' is required to specify the passphrase interactively.
    Init(OptInit),

    /// Print the connection_url for a configured lair-keystore server
    /// to stdout and exit.
    Url,
}

#[derive(Debug, StructOpt)]
#[structopt(about = "secret lair private keystore")]
struct Opt {
    /// Lair root storage and config directory.
    #[structopt(short = "r", long, default_value = ".", env = "LAIR_ROOT")]
    lair_root: std::path::PathBuf,

    /// The subcommand to execute
    #[structopt(subcommand)]
    cmd: Cmd,
}

async fn exec() -> LairResult<()> {
    let opt = Opt::from_args();
    let Opt { lair_root, cmd } = opt;
    let lair_root = dunce::canonicalize(&lair_root)?;
    match cmd {
        Cmd::Init(opt) => cmd_init::exec(lair_root, opt).await,
        Cmd::Url => cmd_url::exec(lair_root).await,
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    if let Err(e) = exec().await {
        eprintln!("{}", e);
    }
}
