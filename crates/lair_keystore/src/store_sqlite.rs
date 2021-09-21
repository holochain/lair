//! lair store backed by a sqlite / sqlcipher database file

use futures::future::{BoxFuture, FutureExt};
use lair_keystore_api::lair_core::traits::*;
use lair_keystore_api::lair_core::*;
use lair_keystore_api::LairResult;
use parking_lot::Mutex;
use rusqlite::params;
use sodoken::*;
use std::future::Future;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const READ_CON_COUNT: usize = 3;

struct SqlPoolInner {
    db_key: sodoken::BufReadSized<32>,
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
    /*
    fn last_insert_rowid(&self) -> i64 {
        self.con.as_ref().unwrap().last_insert_rowid()
    }
    */

    async fn transaction<R, F>(&mut self, f: F) -> LairResult<R>
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

/// SqlPool is a sqlite/sqlcipher connection pool LairStore.
#[derive(Clone)]
pub struct SqlPool(Arc<Mutex<SqlPoolInner>>);

impl SqlPool {
    fn new_sync(
        path: std::path::PathBuf,
        db_key: sodoken::BufReadSized<32>,
    ) -> LairResult<LairStore> {
        use rusqlite::OpenFlags;

        let key_pragma = secure_write_key_pragma(db_key.clone())?;

        let write_con = rusqlite::Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_URI,
        )
        .map_err(one_err::OneErr::new)?;

        set_pragmas(&write_con, key_pragma.clone())?;

        // only set WAL mode on the first write connection
        // it's a slow operation, and not needed on subsequent connections.
        write_con
            .pragma_update(None, "journal_mode", &"WAL".to_string())
            .map_err(one_err::OneErr::new)?;

        write_con.execute_optional(
            r#"
            CREATE TABLE IF NOT EXISTS lair_keystore (
                id                INTEGER  PRIMARY KEY  NOT NULL,
                tag               TEXT                  NOT NULL,
                ed25519_pub_key   BLOB                  NULL,
                x25519_pub_key    BLOB                  NULL,
                data              BLOB                  NOT NULL
            );

            CREATE INDEX IF NOT EXISTS lair_keystore_tag_idx
                ON lair_keystore
                ( tag );

            CREATE INDEX IF NOT EXISTS lair_keystore_ed25519_pub_key_idx
                ON lair_keystore
                ( ed25519_pub_key );

            CREATE INDEX IF NOT EXISTS lair_keystore_x25519_pub_key_idx
                ON lair_keystore
                ( x25519_pub_key );
            "#,
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

        let inner = Self(Arc::new(Mutex::new(SqlPoolInner {
            db_key,
            write_limit: Arc::new(Semaphore::new(1)),
            write_con: Some(write_con),
            read_limit: Arc::new(Semaphore::new(READ_CON_COUNT)),
            read_cons,
        })));

        Ok(LairStore(Arc::new(inner)))
    }

    /// Construct a new SqlPool instance.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        path: std::path::PathBuf,
        db_key: sodoken::BufReadSized<32>,
    ) -> impl Future<Output = LairResult<LairStore>> + 'static + Send {
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

impl AsLairStore for SqlPool {
    fn get_bidi_context_key(&self) -> sodoken::BufReadSized<32> {
        self.0.lock().db_key.clone()
    }

    fn list_entries(
        &self,
    ) -> BoxFuture<'static, LairResult<Vec<LairEntryInfo>>> {
        let read = self.read();
        async move {
            let mut read = read.await;
            read.transaction(|txn| {
                let mut s = txn
                    .prepare("SELECT data FROM lair_keystore;")
                    .map_err(one_err::OneErr::new)?;
                let it = s
                    .query_map([], |row| {
                        // go ahead and clone here, so we're not doing the decoding
                        // while the database is connected...
                        let data: Vec<u8> = row.get(0)?;
                        Ok(data.into_boxed_slice())
                    })
                    .map_err(one_err::OneErr::new)?;
                let mut out = Vec::new();
                for i in it {
                    let e = LairEntryInner::decode(
                        &i.map_err(one_err::OneErr::new)?,
                    )?;
                    let e = match e {
                        LairEntryInner::Seed { tag, seed_info, .. } => {
                            LairEntryInfo::Seed { tag, seed_info }
                        }
                        LairEntryInner::DeepLockedSeed {
                            tag,
                            seed_info,
                            ..
                        } => LairEntryInfo::DeepLockedSeed { tag, seed_info },
                        LairEntryInner::TlsCert { tag, cert_info, .. } => {
                            LairEntryInfo::TlsCert { tag, cert_info }
                        }
                        _ => continue,
                    };
                    out.push(e);
                }
                Ok(out)
            })
            .await
        }
        .boxed()
    }

    fn write_entry(
        &self,
        entry: LairEntry,
    ) -> BoxFuture<'static, LairResult<()>> {
        let write = self.write();
        async move {
            let mut write = write.await;
            let bytes = entry.encode()?;
            write
                .transaction(move |txn| {
                    txn.execute_optional(
                        r#"
                    INSERT INTO lair_keystore (
                        tag,
                        data
                    ) VALUES (
                        ?1,
                        ?2
                    );"#,
                        params![entry.tag(), bytes],
                    )
                })
                .await
        }
        .boxed()
    }

    fn get_entry_by_tag(
        &self,
        tag: Arc<str>,
    ) -> BoxFuture<'static, LairResult<LairEntry>> {
        let read = self.read();
        async move {
            let mut read = read.await;
            let data = read
                .transaction(move |txn| {
                    txn.query_row(
                        "SELECT data FROM lair_keystore WHERE tag = ?1;",
                        params![tag],
                        |row| row.get::<_, Vec<u8>>(0),
                    )
                    .map_err(one_err::OneErr::new)
                })
                .await?;
            let e = LairEntryInner::decode(&data)?;
            Ok(Arc::new(e))
        }
        .boxed()
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

    con.pragma_update(None, "synchronous", &"1".to_string())
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
        let pool = SqlPool::new(sqlite, db_key).await.unwrap();

        let pk = pool
            .new_seed("test-tag".into())
            .await
            .unwrap()
            .ed25519_pub_key;

        let mut list = pool.list_entries().await.unwrap();
        assert_eq!(1, list.len());
        match list.remove(0) {
            LairEntryInfo::Seed { seed_info, .. } => {
                assert_eq!(&*seed_info.ed25519_pub_key, &*pk);
            }
            oth => panic!("unexpected: {:?}", oth),
        }

        let entry = pool.get_entry_by_tag("test-tag".into()).await.unwrap();
        match &*entry {
            LairEntryInner::Seed { seed_info, .. } => {
                assert_eq!(&*seed_info.ed25519_pub_key, &*pk);
            }
            oth => panic!("unexpected: {:?}", oth),
        }
    }
}
