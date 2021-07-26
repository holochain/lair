use lair_keystore_api::{LairError, LairResult};
use parking_lot::Mutex;
use rusqlite::params;
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
                .map_err(LairError::other)
            {
                Err(err) => Err(err),
                Ok(mut txn) => match f(&mut txn) {
                    Ok(r) => {
                        if let Err(err) = txn.commit() {
                            Err(LairError::other(err))
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
        .map_err(LairError::other)?;
        self.con = Some(con);
        r
    }
}

#[derive(Clone)]
pub struct SqlPool(Arc<Mutex<SqlPoolInner>>);

impl SqlPool {
    fn new_sync(path: std::path::PathBuf) -> LairResult<Self> {
        use rusqlite::OpenFlags;

        let fake_key: BufWriteSized<32> =
            // if this were real, we would use locked memory
            BufWriteSized::new_no_lock();
        let fake_key_pragma = secure_write_key_pragma(fake_key)?;

        let write_con = rusqlite::Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_URI,
        )
        .map_err(LairError::other)?;

        set_pragmas(&write_con, fake_key_pragma.clone())?;

        write_con
            .execute(
                "CREATE TABLE IF NOT EXISTS lair_entries (
                id INTEGER PRIMARY KEY NOT NULL,
                data BLOB NOT NULL
            );",
                [],
            )
            .map_err(LairError::other)?;

        let mut read_cons: [Option<rusqlite::Connection>; READ_CON_COUNT] =
            Default::default();

        for rc_mut in read_cons.iter_mut() {
            let read_con = rusqlite::Connection::open_with_flags(
                &path,
                OpenFlags::SQLITE_OPEN_READ_ONLY
                    | OpenFlags::SQLITE_OPEN_NO_MUTEX
                    | OpenFlags::SQLITE_OPEN_URI,
            )
            .map_err(LairError::other)?;

            set_pragmas(&read_con, fake_key_pragma.clone())?;

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
    ) -> impl Future<Output = LairResult<Self>> + 'static + Send {
        async move {
            tokio::task::spawn_blocking(move || Self::new_sync(path))
                .await
                .map_err(LairError::other)?
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

    pub fn init_load_unlock(
        &self,
    ) -> impl Future<Output = LairResult<Option<Vec<u8>>>> + 'static + Send
    {
        let reader = self.read();
        async move {
            let mut reader = reader.await;
            match reader
                .transaction(|txn| {
                    txn.query_row(
                        "SELECT data FROM lair_entries WHERE id = 0;",
                        [],
                        |row| row.get(0),
                    )
                    .map_err(LairError::other)
                })
                .await
            {
                Ok(data) => Ok(Some(data)),
                Err(_) => Ok(None),
            }
        }
    }

    pub fn write_unlock(
        &self,
        entry_data: Vec<u8>,
    ) -> impl Future<Output = LairResult<()>> + 'static + Send {
        let writer = self.write();
        async move {
            let mut writer = writer.await;
            writer
                .transaction(move |txn| {
                    txn.execute(
                        "INSERT INTO lair_entries (id, data) VALUES (?1, ?2);",
                        params![0, entry_data],
                    )
                    .map_err(LairError::other)?;
                    Ok(())
                })
                .await
        }
    }

    pub fn load_all_entries(
        &self,
    ) -> impl Future<Output = LairResult<Vec<(super::KeystoreIndex, Vec<u8>)>>>
           + 'static
           + Send {
        let reader = self.read();
        async move {
            let mut reader = reader.await;
            reader
                .transaction(|txn| {
                    let mut s = txn
                        .prepare(
                            "SELECT id, data FROM lair_entries WHERE id > 0;",
                        )
                        .map_err(LairError::other)?;
                    let it = s
                        .query_map([], |row| {
                            let id: u32 = row.get(0)?;
                            Ok((id.into(), row.get(1)?))
                        })
                        .map_err(LairError::other)?;
                    let mut out = Vec::new();
                    for i in it {
                        out.push(i.map_err(LairError::other)?);
                    }
                    Ok(out)
                })
                .await
        }
    }

    pub fn write_next_entry(
        &self,
        entry_data: Vec<u8>,
    ) -> impl Future<Output = LairResult<super::KeystoreIndex>> + 'static + Send
    {
        let writer = self.write();
        async move {
            let mut writer = writer.await;
            writer
                .transaction(move |txn| {
                    txn.execute(
                        "INSERT INTO lair_entries (data) VALUES (?1);",
                        params![entry_data],
                    )
                    .map_err(LairError::other)?;
                    Ok(())
                })
                .await?;
            Ok((writer.last_insert_rowid() as u32).into())
        }
    }
}

const KEY_PRAGMA_LEN: usize = 83;
const KEY_PRAGMA: &[u8; KEY_PRAGMA_LEN] =
    br#"PRAGMA key = "x'0000000000000000000000000000000000000000000000000000000000000000'";"#;

/// write a sqlcipher key pragma maintaining mem protection
fn secure_write_key_pragma<K>(key: K) -> LairResult<BufRead>
where
    K: Into<BufReadSized<32>> + 'static + Send,
{
    let key = key.into();

    // write the pragma line
    let key_pragma: BufWriteSized<KEY_PRAGMA_LEN> =
        BufWriteSized::new_mem_locked().map_err(LairError::other)?;

    {
        use std::io::Write;

        let mut key_pragma = key_pragma.write_lock();
        key_pragma.copy_from_slice(KEY_PRAGMA);
        let mut c = std::io::Cursor::new(&mut key_pragma[16..80]);
        for b in &*key.read_lock() {
            write!(c, "{:02X}", b).map_err(LairError::other)?;
        }
    }

    Ok(key_pragma.to_read())
}

fn set_pragmas(
    con: &rusqlite::Connection,
    key_pragma: BufRead,
) -> LairResult<()> {
    con.busy_timeout(std::time::Duration::from_millis(30_000))
        .map_err(LairError::other)?;

    con.execute(std::str::from_utf8(&*key_pragma.read_lock()).unwrap(), [])
        .map_err(LairError::other)?;

    con.pragma_update(None, "trusted_schema", &"0".to_string())
        .map_err(LairError::other)?;

    con.pragma_update(None, "journal_mode", &"WAL".to_string())
        .map_err(LairError::other)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn sqlite_sanity() {
        let tmpdir = tempfile::tempdir().unwrap();
        let mut sqlite = tmpdir.path().to_path_buf();
        sqlite.push("db.sqlite3");

        let pool = SqlPool::new(sqlite).await.unwrap();

        assert!(pool.init_load_unlock().await.unwrap().is_none());
        pool.write_unlock(b"testing".to_vec()).await.unwrap();
        assert!(pool.init_load_unlock().await.unwrap().is_some());

        let cont: Arc<std::sync::atomic::AtomicBool> =
            Arc::new(std::sync::atomic::AtomicBool::new(true));

        let mut all_read = Vec::new();
        for _ in 0..2 {
            let pool = pool.clone();
            let cont = cont.clone();
            all_read.push(tokio::task::spawn(async move {
                loop {
                    let c = cont.load(std::sync::atomic::Ordering::Relaxed);

                    tokio::time::sleep(std::time::Duration::from_millis(10))
                        .await;

                    let count = pool.load_all_entries().await.unwrap().len();
                    println!("got count: {}", count);

                    if !c {
                        break;
                    }
                }
            }));
        }

        let mut all_write = Vec::new();
        for _ in 0..10 {
            let pool = pool.clone();
            all_write.push(tokio::task::spawn(async move {
                let start = std::time::Instant::now();
                let id =
                    pool.write_next_entry(b"testing".to_vec()).await.unwrap();
                println!("write {} in {} s", id, start.elapsed().as_secs_f64());
            }));
        }

        futures::future::try_join_all(all_write).await.unwrap();
        cont.store(false, std::sync::atomic::Ordering::Relaxed);
        futures::future::try_join_all(all_read).await.unwrap();
    }
}