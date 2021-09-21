// grrr clippy... you cannot specify extra bounds with the async fn syntax...
#![allow(clippy::manual_async_fn)]
// default implementations don't always make sense...
#![allow(clippy::new_without_default)]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(warnings)]

//! sqlite/sqlcipher backed LairKeystore server control binary

use lair_keystore_api::prelude::*;
use std::sync::Arc;
use structopt::StructOpt;

pub(crate) const CONFIG_N: &str = "lair-keystore-config.yaml";

mod cmd_init;
mod cmd_server;
mod cmd_url;

#[derive(Debug, StructOpt)]
pub(crate) struct OptInit {
    /// Prompt for passphrase interactively.
    #[structopt(short = "i", long)]
    pub interactive: bool,
}

#[derive(Debug, StructOpt)]
pub(crate) struct OptServer {
    /// Prompt for passphrase interactively.
    #[structopt(short = "i", long)]
    pub interactive: bool,
}

#[derive(Debug, StructOpt)]
enum Cmd {
    /// Set up a new lair private keystore. Currently '-i'
    /// is required to specify the passphrase interactively.
    #[structopt(verbatim_doc_comment)]
    Init(OptInit),

    /// Print the connection_url for a configured lair-keystore
    /// server to stdout and exit.
    #[structopt(verbatim_doc_comment)]
    Url,

    /// Run a lair keystore server instance. Note you must
    /// have initialized a config file first with
    /// 'lair-keystore init'.
    #[structopt(verbatim_doc_comment)]
    Server(OptServer),
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

async fn get_config(
    lair_root: &std::path::Path,
) -> LairResult<LairServerConfig> {
    let mut config_n = lair_root.to_owned();
    config_n.push(CONFIG_N);

    let bytes = match tokio::fs::read(&config_n).await {
        Err(e) => {
            return Err(format!(
                "Could not read config file {:?}, did you initialize the keystore? - {}",
                config_n,
                e,
            ).into());
        }
        Ok(b) => b,
    };

    let config = LairServerConfigInner::from_bytes(&bytes)?;

    Ok(Arc::new(config))
}

async fn exec() -> LairResult<()> {
    let opt = Opt::from_args();
    let Opt { lair_root, cmd } = opt;
    let lair_root = dunce::canonicalize(&lair_root)?;
    match cmd {
        Cmd::Init(opt) => cmd_init::exec(lair_root, opt).await,
        Cmd::Url => {
            let config = get_config(lair_root.as_path()).await?;
            cmd_url::exec(config).await
        }
        Cmd::Server(opt) => {
            let config = get_config(lair_root.as_path()).await?;
            cmd_server::exec(config, opt).await
        }
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    if let Err(e) = exec().await {
        eprintln!("{}", e);
    }
}
