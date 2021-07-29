//! Utilities for dealing with pid files.

use crate::*;
use std::{
    io::{Read, Write},
    str::FromStr,
};
use sysinfo::{ProcessExt, SystemExt};

/// Result from invoking `pid_check()` function.
pub struct PidCheckResult {
    /// Access to the lair store file.
    pub sql_db_path: std::path::PathBuf,
}

/// Execute lair pid_check verifying we are the one true Lair process
/// with access to given store / pidfile.
/// This is sync instead of async as it is intended to be used at
/// lair process startup, before we agree to acquire access to the store file.
pub fn pid_check(config: &Config) -> LairResult<PidCheckResult> {
    let mut sys = sysinfo::System::new();

    let mut last_err = None;

    // three time pidfile check loop
    for i in 0..3 {
        if i != 0 {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        match pid_check_write(config, &mut sys) {
            Ok(_) => {
                last_err = None;
                break;
            }
            Err(e) => {
                last_err = Some(e);
            }
        }
    }

    if let Some(e) = last_err {
        return Err(e);
    }

    let sql_db_path = config.get_store_path().to_owned();

    Ok(PidCheckResult { sql_db_path })
}

/// only returns success if we were able to write pidfile with our pid
fn pid_check_write(
    config: &Config,
    sys: &mut sysinfo::System,
) -> LairResult<()> {
    std::fs::create_dir_all(config.get_root_path())
        .map_err(LairError::other)?;

    {
        let mut read_pid = std::fs::OpenOptions::new();
        read_pid.read(true);
        let mut buf = Vec::new();

        match read_pid.open(config.get_pid_path()) {
            Ok(mut read_pid) => {
                read_pid.read_to_end(&mut buf).map_err(LairError::other)?;
                let pid =
                    sysinfo::Pid::from_str(&String::from_utf8_lossy(&buf))
                        .map_err(LairError::other)?;
                sys.refresh_process(pid);
                match sys.get_process(pid) {
                    Some(process)
                        if process.name() == env!("CARGO_PKG_NAME") =>
                    {
                        // a lair process is already running-abort running this one
                        return Err(LairError::ProcessAlreadyExists);
                    }
                    _ => {
                        // there was not a process running under this pid
                        // we can remove it as stale.
                        std::fs::remove_file(config.get_pid_path())
                            .map_err(LairError::other)?;
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // ok to proceed, as there shouldn't be a process running
            }
            Err(e) => return Err(LairError::other(e)),
        }
    }

    let mut write_pid = std::fs::OpenOptions::new();
    let mut write_pid = write_pid
        .write(true)
        .create_new(true)
        .open(config.get_pid_path())
        .map_err(LairError::other)?;

    write_pid
        .write_all(format!("{}", sysinfo::get_current_pid()?).as_bytes())
        .map_err(LairError::other)?;

    Ok(())
}
