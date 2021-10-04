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

fn vec_to_locked(mut pass_tmp: Vec<u8>) -> LairResult<sodoken::BufRead> {
    match sodoken::BufWrite::new_mem_locked(pass_tmp.len()) {
        Err(e) => {
            pass_tmp.fill(0);
            Err(e)
        }
        Ok(p) => {
            {
                let mut lock = p.write_lock();
                lock.copy_from_slice(&pass_tmp);
                pass_tmp.fill(0);
            }
            Ok(p.to_read())
        }
    }
}

pub(crate) async fn read_interactive_passphrase() -> LairResult<sodoken::BufRead>
{
    let pass_tmp = tokio::task::spawn_blocking(|| {
        LairResult::Ok(
            rpassword::read_password_from_tty(Some("\n# passphrase> "))
                .map_err(one_err::OneErr::new)?
                .into_bytes(),
        )
    })
    .await
    .map_err(one_err::OneErr::new)??;

    vec_to_locked(pass_tmp)
}

// you're wrong clippy... it's clearer this way because
// it matches the adjoining len() >= 2
#[allow(clippy::len_zero)]
pub(crate) async fn read_piped_passphrase() -> LairResult<sodoken::BufRead> {
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
    vec_to_locked(pass_tmp)
}

#[derive(Debug, StructOpt)]
pub(crate) struct OptInit {
    /// Instead of the normal "interactive" method of passphrase
    /// retrieval, read the passphrase from stdin. Be careful
    /// how you make use of this, as it could be less secure,
    /// for example, make sure it is not saved in your
    /// `~/.bash_history`.
    #[structopt(short = "p", long, verbatim_doc_comment)]
    pub piped: bool,
}

#[derive(Debug, StructOpt)]
pub(crate) struct OptServer {
    /// Instead of the normal "interactive" method of passphrase
    /// retreival, read the passphrase from stdin. Be careful
    /// how you make use of this, as it could be less secure,
    /// for example, make sure it is not saved in your
    /// `~/.bash_history`.
    #[structopt(short = "p", long, verbatim_doc_comment)]
    pub piped: bool,

    /// Instead of the normal "interactive" method of passphrase
    /// retreival, start the keystore in "locked" mode. The
    /// keystore will need to be "unlocked" via some other method
    /// before it can begin processing requests.
    #[structopt(short = "l", long, verbatim_doc_comment)]
    pub locked: bool,
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
