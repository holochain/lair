//! Exclusive ownership locking for persistent lair stores.
//!
//! A store file must only be opened by a single lair instance at a time,
//! otherwise concurrent writers can clobber the database. Ownership is
//! tracked with an OS file lock on a sidecar file derived from the resolved
//! store path. The lock is released when the last [`StoreLock`] clone is
//! dropped, so keep one alive for as long as any store handle or in-flight
//! store operation can exist.

use crate::*;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

const LOCK_FILE_SUFFIX: &str = ".lock";

/// Process-wide registry of lock paths currently owned by this process.
///
/// The OS lock already rejects competing owners on the supported platforms,
/// but tracking this in-process gives us deterministic same-process rejection
/// and clearer errors regardless of platform lock semantics.
fn owned_lock_paths() -> &'static Mutex<std::collections::HashSet<PathBuf>> {
    static OWNED: OnceLock<Mutex<std::collections::HashSet<PathBuf>>> =
        OnceLock::new();
    OWNED.get_or_init(|| Mutex::new(std::collections::HashSet::new()))
}

struct StoreLockInner {
    _file: std::fs::File,
    store_path: PathBuf,
    lock_path: PathBuf,
}

impl Drop for StoreLockInner {
    fn drop(&mut self) {
        // Closing the file releases the OS lock. Remove the process-local
        // registration so the path can be acquired again.
        if let Ok(mut owned) = owned_lock_paths().lock() {
            owned.remove(&self.lock_path);
        }
    }
}

/// Exclusive ownership guard for a persistent lair store.
///
/// While at least one clone of this guard is alive, no other lair instance
/// (in this process or another process) can acquire ownership of the same
/// store. The guard is cheap to clone and should be held by every resource
/// that can access the store.
#[derive(Clone)]
pub struct StoreLock {
    _inner: Arc<StoreLockInner>,
}

impl StoreLock {
    /// The resolved store path protected by this lock.
    pub(crate) fn store_path(&self) -> &Path {
        &self._inner.store_path
    }
}

/// Validate that the given store file path is usable.
pub(crate) fn validate_store_path(store_file: &Path) -> LairResult<()> {
    let parent = store_file.parent().ok_or_else(|| -> one_err::OneErr {
        format!("invalid store_file dir: {}", store_file.display()).into()
    })?;

    if !std::fs::metadata(parent)?.is_dir() {
        return Err("invalid store file directory".into());
    }

    match std::fs::symlink_metadata(store_file) {
        // it's ok if the store file doesn't exist yet
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(one_err::OneErr::new(e)),
        Ok(m) if m.file_type().is_symlink() => {
            // existing symlinks are resolved by `resolve_store_path`, but a
            // dangling link has no stable target to derive the lock from
            match std::fs::metadata(store_file) {
                Ok(m) if m.is_file() => (),
                Ok(_) => return Err("store file is not a file".into()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err("store file is a dangling symlink".into());
                }
                Err(e) => return Err(one_err::OneErr::new(e)),
            }
        }
        Ok(m) => {
            // if it exists, it must be a file
            if !m.is_file() {
                return Err("store file is not a file".into());
            }
        }
    }

    Ok(())
}

/// Resolve the store file path so that all aliases of the same store share
/// a single identity, even before the store file exists.
///
/// The store file may not exist yet, so the parent directory is canonicalized
/// when the file is missing. If the store file does exist, canonicalizing it
/// also resolves symlinks.
pub(crate) fn resolve_store_path(store_file: &Path) -> LairResult<PathBuf> {
    let (dir, file_name) = if store_file.exists() {
        let resolved = dunce::canonicalize(store_file)?;
        let dir = resolved.parent().ok_or_else(|| -> one_err::OneErr {
            format!("invalid store_file dir: {}", store_file.display()).into()
        })?;
        let file_name =
            resolved.file_name().ok_or_else(|| -> one_err::OneErr {
                format!("invalid store_file name: {}", store_file.display())
                    .into()
            })?;
        (dir.to_owned(), file_name.to_owned())
    } else {
        let dir = store_file.parent().ok_or_else(|| -> one_err::OneErr {
            format!("invalid store_file dir: {}", store_file.display()).into()
        })?;
        let file_name =
            store_file.file_name().ok_or_else(|| -> one_err::OneErr {
                format!("invalid store_file name: {}", store_file.display())
                    .into()
            })?;
        (dunce::canonicalize(dir)?, file_name.to_owned())
    };

    Ok(dir.join(file_name))
}

/// Derive the sidecar lock path from a resolved store path.
fn lock_path_for_store_path(store_path: &Path) -> LairResult<PathBuf> {
    let mut lock_name = store_path
        .file_name()
        .ok_or_else(|| -> one_err::OneErr {
            format!("invalid store_file name: {}", store_path.display()).into()
        })?
        .to_owned();
    lock_name.push(LOCK_FILE_SUFFIX);
    Ok(store_path.with_file_name(lock_name))
}

/// Acquire exclusive ownership of the given store file.
///
/// This is a nonblocking OS file lock. It returns an error if another lair
/// instance in this process or another process already owns the store.
pub fn acquire_store_lock(store_file: &Path) -> LairResult<StoreLock> {
    validate_store_path(store_file)?;

    let store_path = resolve_store_path(store_file)?;
    let lock_path = lock_path_for_store_path(&store_path)?;

    {
        let owned = owned_lock_paths().lock().map_err(|_| {
            one_err::OneErr::new("store lock registry poisoned")
        })?;
        if owned.contains(&lock_path) {
            return Err(
                format!("StoreAlreadyOwned: {}", lock_path.display()).into()
            );
        }
    }

    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(one_err::OneErr::new)?;

    match file.try_lock() {
        Ok(()) => (),
        Err(std::fs::TryLockError::WouldBlock) => {
            return Err(
                format!("StoreAlreadyOwned: {}", lock_path.display()).into()
            );
        }
        Err(std::fs::TryLockError::Error(e)) => {
            return Err(one_err::OneErr::new(e));
        }
    }

    {
        let mut owned = owned_lock_paths().lock().map_err(|_| {
            one_err::OneErr::new("store lock registry poisoned")
        })?;
        if !owned.insert(lock_path.clone()) {
            // another thread in this process won the race
            return Err(
                format!("StoreAlreadyOwned: {}", lock_path.display()).into()
            );
        }
    }

    Ok(StoreLock {
        _inner: Arc::new(StoreLockInner {
            _file: file,
            store_path,
            lock_path,
        }),
    })
}

/// Prepare the canonical persistent store, acquiring exclusive ownership of
/// the store path and constructing the sqlite store factory.
///
/// The returned guard is also cloned into the factory and into every store
/// the factory creates, so ownership is held for as long as any store handle
/// or in-flight store operation exists.
pub fn prepare_persistent_store(
    config: LairServerConfig,
) -> impl Future<Output = LairResult<(StoreLock, LairStoreFactory)>> + 'static + Send
{
    async move {
        let store_file = config.store_file.clone();

        let lock = tokio::task::spawn_blocking(move || {
            acquire_store_lock(&store_file)
        })
        .await
        .map_err(one_err::OneErr::new)??;

        // use the same resolved path for the lock and the sqlite store so
        // they cannot diverge (including during unencrypted-db migration)
        let store_path = lock.store_path().to_owned();

        let store_factory =
            crate::store_sqlite::create_sql_pool_factory_with_lock(
                &store_path,
                &config.database_salt,
                lock.clone(),
            );

        Ok((lock, store_factory))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_store_path(tmpdir: &tempfile::TempDir) -> PathBuf {
        tmpdir.path().join("store_file")
    }

    #[test]
    fn lock_is_exclusive_and_reacquirable() {
        let tmpdir =
            tempfile::TempDir::with_prefix("lair-store-lock-test").unwrap();
        let store_file = test_store_path(&tmpdir);

        let lock = acquire_store_lock(&store_file).unwrap();

        // competing owner in the same process is rejected
        assert!(acquire_store_lock(&store_file).is_err());

        // the lock file is derived from the store path
        assert!(tmpdir.path().join("store_file.lock").is_file());

        drop(lock);

        // ownership can be reacquired after the last guard is dropped
        let _lock = acquire_store_lock(&store_file).unwrap();
    }

    #[test]
    fn independent_stores_can_be_owned_together() {
        let tmpdir =
            tempfile::TempDir::with_prefix("lair-store-lock-test").unwrap();

        let _lock_a =
            acquire_store_lock(&tmpdir.path().join("store_a")).unwrap();
        let _lock_b =
            acquire_store_lock(&tmpdir.path().join("store_b")).unwrap();
    }

    #[test]
    fn validation_rejects_invalid_store_paths() {
        let tmpdir =
            tempfile::TempDir::with_prefix("lair-store-lock-test").unwrap();

        // store file is a directory
        let dir_store = tmpdir.path().join("store_dir");
        std::fs::create_dir(&dir_store).unwrap();
        assert!(acquire_store_lock(&dir_store).is_err());

        // parent directory does not exist
        let missing_parent = tmpdir.path().join("missing").join("store_file");
        assert!(acquire_store_lock(&missing_parent).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn lock_uses_resolved_store_path() {
        let tmpdir =
            tempfile::TempDir::with_prefix("lair-store-lock-test").unwrap();
        let real_dir = tmpdir.path().join("real");
        std::fs::create_dir(&real_dir).unwrap();
        let link_dir = tmpdir.path().join("link");
        std::os::unix::fs::symlink(&real_dir, &link_dir).unwrap();

        let link_store = link_dir.join("store_file");
        let lock = acquire_store_lock(&link_store).unwrap();

        let expected =
            dunce::canonicalize(&real_dir).unwrap().join("store_file");
        assert_eq!(expected.as_path(), lock.store_path());

        // another alias of the same store cannot acquire ownership
        assert!(acquire_store_lock(&real_dir.join("store_file")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn dangling_store_symlink_is_rejected() {
        let tmpdir =
            tempfile::TempDir::with_prefix("lair-store-lock-test").unwrap();
        let target = tmpdir.path().join("target");
        let link = tmpdir.path().join("store_link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        // a dangling link has no stable store identity to lock
        assert!(acquire_store_lock(&link).is_err());

        // existing symlinks are still supported and resolve to the target
        std::fs::write(&target, b"store").unwrap();
        let lock = acquire_store_lock(&link).unwrap();
        assert_eq!(
            dunce::canonicalize(&target).unwrap().as_path(),
            lock.store_path()
        );
    }

    #[test]
    fn lock_path_resolves_existing_store_file() {
        let tmpdir =
            tempfile::TempDir::with_prefix("lair-store-lock-test").unwrap();
        let store_file = test_store_path(&tmpdir);
        std::fs::write(&store_file, b"not-actually-a-db").unwrap();

        let store_path = resolve_store_path(&store_file).unwrap();
        assert_eq!(dunce::canonicalize(&store_file).unwrap(), store_path);

        let lock_path = lock_path_for_store_path(&store_path).unwrap();
        assert_eq!(
            dunce::canonicalize(tmpdir.path())
                .unwrap()
                .join("store_file.lock"),
            lock_path
        );
    }
}
