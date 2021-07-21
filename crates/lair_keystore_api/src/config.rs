#[cfg(windows)]
use crate::trace;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

/// Use root path as is for socket path
#[cfg(not(windows))]
fn build_socket_path(root_path: &Path) -> PathBuf {
    let mut socket_path = root_path.to_path_buf();
    socket_path.push("socket");
    socket_path
}

/// Use root path with adjustememts for pipe name
#[cfg(windows)]
fn build_socket_path(root_path: &Path) -> PathBuf {
    trace!("Config.root_path = {:?}", root_path);
    let mut socket_path = PathBuf::new();
    socket_path.push(r"\\.\pipe");
    // Add only valid path items
    for item in root_path.iter() {
        let maybe_first_char = item.to_string_lossy().chars().next();
        if let Some(first_char) = maybe_first_char {
            if first_char != '\\' {
                socket_path.push(item);
            }
        }
    }
    socket_path.push("socket");
    trace!("Config.socket_path = {:?}", socket_path);
    socket_path
}

/// Lair configuration struct.
pub struct Config {
    root_path: PathBuf,
    store_path: PathBuf,
    pid_path: PathBuf,
    socket_path: PathBuf,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
}

impl Config {
    pub(crate) fn finalize(mut self) -> Arc<Config> {
        std::fs::create_dir_all(self.root_path.as_path())
            .expect("can cannonicalize root path");
        self.root_path = self
            .root_path
            .canonicalize()
            .expect("can cannonicalize root path");
        self.store_path = self.root_path.clone();
        self.store_path.push("store");
        self.pid_path = self.root_path.clone();
        self.pid_path.push("pid");
        self.socket_path = build_socket_path(&self.root_path);
        self.stdout_path = self.root_path.clone();
        self.stdout_path.push("stdout");
        self.stderr_path = self.root_path.clone();
        self.stderr_path.push("stderr");
        Arc::new(self)
    }

    /// Obtain a new config builder.
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::default()
    }

    /// Get the root data directory as specified by this config.
    pub fn get_root_path(&self) -> &Path {
        self.root_path.as_path()
    }

    /// Get the path to the lair store.
    pub fn get_store_path(&self) -> &Path {
        self.store_path.as_path()
    }

    /// Get the path to the lair pidfile.
    pub fn get_pid_path(&self) -> &Path {
        self.pid_path.as_path()
    }

    /// Get the path to the lair ipc socket.
    pub fn get_socket_path(&self) -> &Path {
        self.socket_path.as_path()
    }

    /// Get the path to the lair stdout file.
    pub fn get_stdout_path(&self) -> &Path {
        self.stdout_path.as_path()
    }

    /// Get the path to the lair stderr file.
    pub fn get_stderr_path(&self) -> &Path {
        self.stderr_path.as_path()
    }
}

/// Lair configuration builder.
pub struct ConfigBuilder(Config);

impl Default for ConfigBuilder {
    fn default() -> Self {
        let pdir = directories::ProjectDirs::from("host", "Holo", "Lair")
            .expect("can determine project dir");
        Self(Config {
            root_path: pdir.data_local_dir().to_path_buf(),
            store_path: PathBuf::new(),
            pid_path: PathBuf::new(),
            socket_path: PathBuf::new(),
            stdout_path: PathBuf::new(),
            stderr_path: PathBuf::new(),
        })
    }
}

impl ConfigBuilder {
    /// Obtain a new config builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Consume the config builder to obtain a true Config instance.
    pub fn build(self) -> Arc<Config> {
        self.0.finalize()
    }

    /// Override the default data directory.
    pub fn set_root_path<P>(mut self, p: P) -> Self
    where
        P: Into<PathBuf>,
    {
        self.0.root_path = p.into();
        self
    }
}
