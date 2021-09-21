//! lair store backed by a sqlite / sqlcipher database file

use lair_keystore_api::LairResult;
use parking_lot::Mutex;
use sodoken::*;
use std::future::Future;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const READ_CON_COUNT: usize = 3;

struct SqlPoolInner {
    write_limit: Arc<Semaphore>,
    write_con: Option<rusqlite::Connection>,
    read_limit: Arc<Semaphore>,
    read_cons: [Option<rusqlite::Connection>; READ_CON_COUNT],
}

struct SqlCon {
    _permit: OwnedSemaphorePermit,
    is_write: bool,
    con: Option<rusqlite::Connection>,
    pool: Arc<Mutex<SqlPoolInner>>,
}

impl Drop for SqlCon {
    fn drop(&mut self) {
        let con = self.con.take().unwrap();

        {
            let mut lock = self.pool.lock();
            if self.is_write {
                lock.write_con = Some(con);
            } else {
                for rc in lock.read_cons.iter_mut() {
                    if rc.is_none() {
                        *rc = Some(con);
                        break;
                    }
                }
            }
        }
    }
}

impl SqlCon {
    pub fn last_insert_rowid(&self) -> i64 {
        self.con.as_ref().unwrap().last_insert_rowid()
    }

    pub async fn transaction<R, F>(&mut self, f: F) -> LairResult<R>
    where
        R: 'static + Send,
        F: 'static
            + FnOnce(&mut rusqlite::Transaction<'_>) -> LairResult<R>
            + Send,
    {
        let b = if self.is_write {
            rusqlite::TransactionBehavior::Immediate
        } else {
            rusqlite::TransactionBehavior::Deferred
        };
        let mut con = self.con.take().unwrap();
        let (con, r) = tokio::task::spawn_blocking(move || {
            let r = match con
                .transaction_with_behavior(b)
                .map_err(one_err::OneErr::new)
            {
                Err(err) => Err(err),
                Ok(mut txn) => match f(&mut txn) {
                    Ok(r) => {
                        if let Err(err) = txn.commit() {
                            Err(one_err::OneErr::new(err))
                        } else {
                            Ok(r)
                        }
                    }
                    Err(err) => Err(err),
                },
            };
            (con, r)
        })
        .await
        .map_err(one_err::OneErr::new)?;
        self.con = Some(con);
        r
    }
}

/// extension trait for execute that we don't care about results
trait ExecExt {
    fn execute_optional<P>(&self, sql: &str, params: P) -> LairResult<()>
    where
        P: rusqlite::Params;
}

impl ExecExt for rusqlite::Connection {
    fn execute_optional<P>(&self, sql: &str, params: P) -> LairResult<()>
    where
        P: rusqlite::Params,
    {
        use rusqlite::OptionalExtension;
        self.query_row(sql, params, |_| Ok(()))
            .optional()
            .map_err(one_err::OneErr::new)?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct SqlPool(Arc<Mutex<SqlPoolInner>>);

impl SqlPool {
    fn new_sync(
        path: std::path::PathBuf,
        db_key: sodoken::BufReadSized<32>,
    ) -> LairResult<Self> {
        use rusqlite::OpenFlags;

        let key_pragma = secure_write_key_pragma(db_key)?;

        let write_con = rusqlite::Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_URI,
        )
        .map_err(one_err::OneErr::new)?;

        set_pragmas(&write_con, key_pragma.clone())?;

        write_con.execute_optional(
            "CREATE TABLE IF NOT EXISTS lair_entries (
                id INTEGER PRIMARY KEY NOT NULL,
                data BLOB NOT NULL
            );",
            [],
        )?;

        let mut read_cons: [Option<rusqlite::Connection>; READ_CON_COUNT] =
            Default::default();

        for rc_mut in read_cons.iter_mut() {
            let read_con = rusqlite::Connection::open_with_flags(
                &path,
                OpenFlags::SQLITE_OPEN_READ_ONLY
                    | OpenFlags::SQLITE_OPEN_NO_MUTEX
                    | OpenFlags::SQLITE_OPEN_URI,
            )
            .map_err(one_err::OneErr::new)?;

            set_pragmas(&read_con, key_pragma.clone())?;

            *rc_mut = Some(read_con);
        }

        Ok(Self(Arc::new(Mutex::new(SqlPoolInner {
            write_limit: Arc::new(Semaphore::new(1)),
            write_con: Some(write_con),
            read_limit: Arc::new(Semaphore::new(READ_CON_COUNT)),
            read_cons,
        }))))
    }

    pub fn new(
        path: std::path::PathBuf,
        db_key: sodoken::BufReadSized<32>,
    ) -> impl Future<Output = LairResult<Self>> + 'static + Send {
        async move {
            tokio::task::spawn_blocking(move || Self::new_sync(path, db_key))
                .await
                .map_err(one_err::OneErr::new)?
        }
    }

    fn read(&self) -> impl Future<Output = SqlCon> + 'static + Send {
        let inner = self.0.clone();
        async move {
            let permit = inner.lock().read_limit.clone();
            let permit = permit.acquire_owned().await.unwrap();

            let mut con = None;
            {
                let mut lock = inner.lock();
                for rc in lock.read_cons.iter_mut() {
                    if rc.is_some() {
                        con = rc.take();
                        break;
                    }
                }
            }

            SqlCon {
                _permit: permit,
                is_write: false,
                con,
                pool: inner,
            }
        }
    }

    fn write(&self) -> impl Future<Output = SqlCon> + 'static + Send {
        let inner = self.0.clone();
        async move {
            let permit = inner.lock().write_limit.clone();
            let permit = permit.acquire_owned().await.unwrap();

            let con = inner.lock().write_con.take();

            SqlCon {
                _permit: permit,
                is_write: true,
                con,
                pool: inner,
            }
        }
    }
}

const KEY_PRAGMA_LEN: usize = 83;
const KEY_PRAGMA: &[u8; KEY_PRAGMA_LEN] =
    br#"PRAGMA key = "x'0000000000000000000000000000000000000000000000000000000000000000'";"#;

/// write a sqlcipher key pragma maintaining mem protection
fn secure_write_key_pragma(
    key: sodoken::BufReadSized<32>,
) -> LairResult<BufRead> {
    // write the pragma line
    let key_pragma: BufWriteSized<KEY_PRAGMA_LEN> =
        BufWriteSized::new_mem_locked().map_err(one_err::OneErr::new)?;

    {
        use std::io::Write;

        let mut key_pragma = key_pragma.write_lock();
        key_pragma.copy_from_slice(KEY_PRAGMA);
        let mut c = std::io::Cursor::new(&mut key_pragma[16..80]);
        for b in &*key.read_lock() {
            write!(c, "{:02X}", b).map_err(one_err::OneErr::new)?;
        }
    }

    Ok(key_pragma.to_read())
}

fn set_pragmas(
    con: &rusqlite::Connection,
    key_pragma: BufRead,
) -> LairResult<()> {
    con.busy_timeout(std::time::Duration::from_millis(30_000))
        .map_err(one_err::OneErr::new)?;

    con.execute_optional(
        std::str::from_utf8(&*key_pragma.read_lock()).unwrap(),
        [],
    )?;

    con.pragma_update(None, "trusted_schema", &"0".to_string())
        .map_err(one_err::OneErr::new)?;

    con.pragma_update(None, "journal_mode", &"WAL".to_string())
        .map_err(one_err::OneErr::new)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn sqlite_sanity() {
        let tmpdir = tempdir::TempDir::new("lair-keystore-test").unwrap();
        let mut sqlite = tmpdir.path().to_path_buf();
        sqlite.push("db.sqlite3");

        let db_key = sodoken::BufReadSized::new_no_lock([0; 32]);
        let _pool = SqlPool::new(sqlite, db_key).await.unwrap();
    }
}
