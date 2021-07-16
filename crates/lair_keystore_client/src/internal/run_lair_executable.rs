use crate::*;

/// Manually run a lair executable.
/// Child returned mainly so tests can kill the process.
pub async fn run_lair_executable(
    config: Arc<Config>,
) -> LairResult<std::process::Child> {
    let stdout = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(config.get_stdout_path())
        .map_err(LairError::other)?;
    let stderr = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(config.get_stderr_path())
        .map_err(LairError::other)?;
    let cmd = std::process::Command::new("lair-keystore")
        .env("LAIR_DIR", config.get_root_path())
       .stdout(stdout)
       .stderr(stderr)
        .stdin(std::process::Stdio::null())
        .spawn()
        .map_err(LairError::other)?;
    wait_ready(config.get_stdout_path()).await?;
    Ok(cmd)
}

async fn wait_ready(stdout_path: &std::path::Path) -> LairResult<()> {
    let mut stdout = tokio::fs::OpenOptions::new()
        .read(true)
        .open(stdout_path)
        .await
        .map_err(LairError::other)?;
    let now = std::time::Instant::now();
    let mut buf = String::new();
    while now.elapsed().as_millis() < 2000 {
        use tokio::io::AsyncReadExt;
        stdout
            .read_to_string(&mut buf)
            .await
            .map_err(LairError::other)?;
        if buf.contains("#lair-keystore-ready#") {
            return Ok(());
        }
    }
    Err("timout waiting for lair-keystore ready".into())
}

#[cfg(test)]
#[cfg(feature = "bin-tests")]
mod bin_tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn spawn_process() -> LairResult<()> {
        let tmpdir = tempfile::tempdir().unwrap();
        std::env::set_var("LAIR_DIR", tmpdir.path());

        let config = lair_keystore_api::Config::builder()
            .set_root_path(tmpdir.path())
            .build();

        let mut child = super::run_lair_executable(config).await?;

        child.kill().unwrap();

        Ok(())
    }
}
