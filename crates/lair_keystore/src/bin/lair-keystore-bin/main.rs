// grrr clippy... you cannot specify extra bounds with the async fn syntax...
#![allow(clippy::manual_async_fn)]
// default implementations don't always make sense...
#![allow(clippy::new_without_default)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

//! sqlite/sqlcipher backed LairKeystore server control binary

use clap::{Args, Parser, Subcommand};
use lair_keystore::dependencies::*;
use lair_keystore_api::prelude::*;
use std::sync::Arc;

pub(crate) const CONFIG_N: &str = "lair-keystore-config.yaml";

mod cmd_import_seed;
mod cmd_init;
mod cmd_server;
mod cmd_url;

pub(crate) async fn read_interactive_passphrase(
    prompt: &str,
) -> LairResult<sodoken::LockedArray> {
    let prompt = prompt.to_owned();
    let pass_tmp = tokio::task::spawn_blocking(move || {
        LairResult::Ok(
            rpassword::prompt_password(prompt)
                .map_err(one_err::OneErr::new)?
                .into_bytes(),
        )
    })
    .await
    .map_err(one_err::OneErr::new)??;

    Ok(sodoken::LockedArray::from(pass_tmp))
}

// you're wrong clippy... it's clearer this way because
// it matches the adjoining len() >= 2
#[allow(clippy::len_zero)]
pub(crate) async fn read_piped_passphrase() -> LairResult<sodoken::LockedArray>
{
    let mut stdin = tokio::io::stdin();
    let mut pass_tmp = Vec::new();

    use tokio::io::AsyncReadExt;
    stdin.read_to_end(&mut pass_tmp).await?;

    if pass_tmp.len() >= 2
        && pass_tmp[pass_tmp.len() - 1] == 10
        && pass_tmp[pass_tmp.len() - 2] == 13
    {
        pass_tmp.pop();
        pass_tmp.pop();
    } else if pass_tmp.len() >= 1 && pass_tmp[pass_tmp.len() - 1] == 10 {
        pass_tmp.pop();
    }

    Ok(sodoken::LockedArray::from(pass_tmp))
}

#[derive(Debug, Args)]
pub(crate) struct OptInit {
    /// Instead of the normal "interactive" method of passphrase
    /// retrieval, read the passphrase from stdin. Be careful
    /// how you make use of this, as it could be less secure,
    /// for example, make sure it is not saved in your
    /// `~/.bash_history`.
    #[arg(short = 'p', long)]
    pub piped: bool,
}

#[derive(Debug, Args)]
pub(crate) struct OptServer {
    /// Instead of the normal "interactive" method of passphrase
    /// retrieval, read the passphrase from stdin. Be careful
    /// how you make use of this, as it could be less secure,
    /// for example, make sure it is not saved in your
    /// `~/.bash_history`.
    #[arg(short = 'p', long)]
    pub piped: bool,
}

#[derive(Debug, Args)]
pub(crate) struct OptImportSeed {
    /// Instead of the normal "interactive" method of passphrase
    /// retrieval, read the passphrase from stdin. Be careful
    /// how you make use of this, as it could be less secure.
    /// Passphrases are newline delimited in this order:
    /// - 1 - keystore unlock passphrase
    /// - 2 - bundle unlock passphrase
    /// - 3 - deep lock passphrase
    ///   (if -d / --deep-lock is specified)
    #[arg(short = 'p', long)]
    pub piped: bool,

    /// Specify that this seed should be loaded as a
    /// "deep-locked" seed. This seed will require an
    /// additional passphrase specified at access time
    /// (signature / box / key derivation) to decrypt the seed.
    #[arg(short = 'd', long)]
    pub deep_lock: bool,

    /// The identification tag for this seed.
    pub tag: String,

    /// The base64url encoded hc_seed_bundle.
    pub seed_bundle_base64: String,

    /// Mark this seed as "exportable" indicating
    /// this key can be extracted again after having
    /// been imported.
    #[arg(short = 'e', long)]
    pub exportable: bool,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Set up a new lair private keystore.
    Init(OptInit),

    /// Print the connection_url for a configured lair-keystore
    /// server to stdout and exit.
    Url,

    /// Run a lair keystore server instance. Note you must
    /// have initialized a config file first with
    /// 'lair-keystore init'.
    Server(OptServer),

    /// Load a seed bundle into this lair-keystore instance.
    /// Note, this operation requires capturing the pid_file,
    /// make sure you do not have a lair-server running.
    /// Note, we currently only support importing seed bundles
    /// with a pwhash cipher. We'll try the passphrase you
    /// supply with all ciphers used to lock the bundle.
    ImportSeed(OptImportSeed),
}

/// secret lair private keystore
#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Opt {
    /// Lair root storage and config directory.
    #[arg(short = 'r', long, default_value = ".", env = "LAIR_ROOT")]
    lair_root: std::path::PathBuf,

    /// The subcommand to execute
    #[command(subcommand)]
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
                "Could not read config file {config_n:?}, did you initialize the keystore? - {e}",
            ).into());
        }
        Ok(b) => b,
    };

    let config = LairServerConfigInner::from_bytes(&bytes)?;

    Ok(Arc::new(config))
}

async fn exec() -> LairResult<()> {
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_writer(std::io::stderr)
            .compact()
            .finish(),
    )
    .unwrap();

    tracing::info!("starting lair-keystore");

    let opt = Opt::parse();
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
        Cmd::ImportSeed(opt) => {
            let config = get_config(lair_root.as_path()).await?;
            cmd_import_seed::exec(config, opt).await
        }
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> LairResult<()> {
    exec().await
}
