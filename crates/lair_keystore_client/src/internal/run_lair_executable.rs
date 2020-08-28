use crate::*;

/// Manually run a lair executable.
/// Child returned mainly so tests can kill the process.
pub fn run_lair_executable(
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
    Ok(cmd)
}

#[cfg(test)]
mod tests {
    #[test]
    fn spawn_process() {
        let tmpdir = tempfile::tempdir().unwrap();
        std::env::set_var("LAIR_DIR", tmpdir.path());

        let config = lair_keystore_api::Config::builder()
            .set_root_path(tmpdir.path())
            .build();

        let mut child = super::run_lair_executable(config).unwrap();

        child.kill().unwrap();
    }
}
