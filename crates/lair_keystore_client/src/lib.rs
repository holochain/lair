#![deny(missing_docs)]
#![deny(warnings)]
//! client connector to secret lair private keystore

include!(concat!(env!("OUT_DIR"), "/ver.rs"));

use lair_keystore_api::actor::*;
use lair_keystore_api::*;
use std::sync::Arc;
use tracing::*;

pub mod internal;

macro_rules! e {
    ($e:expr) => {{
        match $e {
            Ok(r) => Ok(r),
            Err(e) => {
                error!(
                    error = ?e,
                    file = file!(),
                    line = line!(),
                );
                Err(e)
            }
        }
    }};
}

/// If a lair executable is already running, connect to it.
/// If it is not, attempt to run and disown one into the background.
/// Note, it is still preferable for lair to be executed / managed
/// as a system service, but this provides a quick up-and-running
/// experience.
pub async fn assert_running_lair_and_connect(
    config: Arc<Config>,
) -> LairResult<(
    ghost_actor::GhostSender<LairClientApi>,
    LairClientEventReceiver,
)> {
    // step 1 - just try to connect
    if let Ok(r) = e!(check_ipc_connect(config.clone()).await) {
        trace!("first try check Ok");
        return Ok(r);
    }

    // step 2 - try to execute the lair executable
    if let Ok(mut proc) =
        e!(internal::run_lair_executable(config.clone()).await)
    {
        // step 2.1 - if the executable ran, try to connect to it.
        if let Ok(r) = e!(check_ipc_connect(config.clone()).await) {
            trace!("second try (run executable) check Ok");
            return Ok(r);
        }

        // couldn't connect... kill it
        proc.kill().map_err(LairError::other)?;
    }

    // step 3 - try to build the lair executable using cargo
    e!(internal::cargo_build_lair_executable())?;

    // step 3.1 - now run it
    let mut proc = internal::run_lair_executable(config.clone()).await?;

    // step 3.2 - if the executable ran, try to connect to it.
    if let Ok(r) = e!(check_ipc_connect(config).await) {
        trace!("third try (build executable) check Ok");
        return Ok(r);
    }

    // couldn't connect... kill it
    proc.kill().map_err(LairError::other)?;

    Err("could not execute / connect to lair process".into())
}

async fn check_ipc_connect(
    config: Arc<Config>,
) -> LairResult<(
    ghost_actor::GhostSender<LairClientApi>,
    LairClientEventReceiver,
)> {
    let (api, evt) = ipc::spawn_client_ipc(config.clone()).await?;

    trace!("send check server info");
    let srv_info = api.lair_get_server_info().await?;
    trace!(?srv_info, "got check server info");

    if srv_info.version != LAIR_VER {
        return Err(format!(
            "version mismatch, expected {}, got {}",
            LAIR_VER, srv_info.version,
        )
        .into());
    }

    Ok((api, evt))
}

#[cfg(test)]
#[cfg(feature = "bin-tests")]
mod bin_tests {
    use super::*;

    fn init_tracing() {
        let _ = subscriber::set_global_default(
            tracing_subscriber::FmtSubscriber::builder()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::from_default_env(),
                )
                .finish(),
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn basic_running_connect() -> LairResult<()> {
        init_tracing();

        let tmpdir = tempfile::tempdir().unwrap();
        std::env::set_var("LAIR_DIR", tmpdir.path());

        trace!(lair_dir = ?tmpdir.path(), "RUNNING WITH LAIR_DIR");

        let config = lair_keystore_api::Config::builder()
            .set_root_path(tmpdir.path())
            .build();

        trace!("running executable...");
        let mut child = internal::run_lair_executable(config.clone()).await?;
        trace!("executable running.");

        trace!("connecting...");
        let (api, _evt) = assert_running_lair_and_connect(config).await?;
        trace!("connected.");

        trace!("checking version...");
        let srv_info = api.lair_get_server_info().await?;
        assert_eq!(LAIR_VER, srv_info.version);
        trace!("version checked.");

        trace!("killing executable...");
        child.kill().unwrap();
        trace!("executable killed.");

        Ok(())
    }
}
