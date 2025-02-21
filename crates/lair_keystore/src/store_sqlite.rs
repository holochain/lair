//! Lair store backed by a sqlite / sqlcipher database file.

use crate::*;
use futures::future::{BoxFuture, FutureExt};
use lair_keystore_api::lair_store::traits::*;
use parking_lot::Mutex;
use rusqlite::params;
use std::future::Future;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const READ_CON_COUNT: usize = 3;

/// Create a [LairStoreFactory] backed
/// by an encrypted (sqlcipher) sqlite database.
/// WARNING: If running on windows, this currently degenerates to a
/// plaintext (non-encrypted) sqlite database.
pub fn create_sql_pool_factory<P>(
    sqlite_file_path: P,
    db_salt: &BinDataSized<16>,
) -> LairStoreFactory
where
    P: AsRef<std::path::Path>,
{
    let sqlite_file_path = sqlite_file_path.as_ref().to_owned();
    struct X(std::path::PathBuf, BinDataSized<16>);
    impl AsLairStoreFactory for X {
        fn connect_to_store(
            &self,
            unlock_secret: SharedSizedLockedArray<32>,
        ) -> BoxFuture<'static, LairResult<LairStore>> {
            let sqlite_file_path = self.0.clone();
            let db_salt = self.1.clone();
            async move {
                SqlPool::new(sqlite_file_path, unlock_secret, db_salt).await
            }
            .boxed()
        }
    }
    let inner = X(sqlite_file_path, db_salt.clone());
    LairStoreFactory(Arc::new(inner))
}

struct SqlPoolInner {
    ctx_secret: SharedSizedLockedArray<32>,
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
        if let Some(con) = self.con.take() {
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
    fn execute_optional<P>(&self, sql: &str, params: P) -> rusqlite::Result<()>
    where
        P: rusqlite::Params;
}

impl ExecExt for rusqlite::Connection {
    fn execute_optional<P>(&self, sql: &str, params: P) -> rusqlite::Result<()>
    where
        P: rusqlite::Params,
    {
        use rusqlite::OptionalExtension;
        self.query_row(sql, params, |_| Ok(())).optional()?;
        Ok(())
    }
}

/// SqlPool is a sqlite/sqlcipher connection pool LairStore.
#[derive(Clone)]
pub struct SqlPool(Arc<Mutex<SqlPoolInner>>);

impl SqlPool {
    fn new_sync(
        path: std::path::PathBuf,
        db_key: SharedSizedLockedArray<32>,
        db_salt: BinDataSized<16>,
    ) -> LairResult<LairStore> {
        use rusqlite::OpenFlags;

        // derive a key for context encryption in and out of store file
        let mut ctx_secret = sodoken::SizedLockedArray::<32>::new()?;
        sodoken::kdf::derive_from_key(
            &mut *ctx_secret.lock(),
            42,
            b"CtxSecKy",
            &db_key.lock().lock(),
        )?;

        // derive a key to use for the sqlcipher encryption
        let mut dbk_secret = sodoken::SizedLockedArray::<32>::new()?;
        sodoken::kdf::derive_from_key(
            &mut *dbk_secret.lock(),
            142,
            b"DbKSecKy",
            &db_key.lock().lock(),
        )?;

        // initialize the sqlcipher key pragma
        let key_pragma =
            Arc::new(Mutex::new(secure_write_key_pragma(dbk_secret)?));

        let mut write_con = match create_configured_db_connection(
            &path,
            key_pragma.clone(),
            db_salt.clone(),
        ) {
            Ok(con) => con,
            Err(err) => {
                if "true"
                    == std::env::var("LAIR_MIGRATE_UNENCRYPTED")
                        .unwrap_or_default()
                        .as_str()
                {
                    encrypt_unencrypted_database(
                        &path,
                        key_pragma.clone(),
                        db_salt.clone(),
                    )?;
                    create_configured_db_connection(
                        &path,
                        key_pragma.clone(),
                        db_salt.clone(),
                    )
                    .map_err(one_err::OneErr::new)?
                } else {
                    return Err(one_err::OneErr::new(err));
                }
            }
        };

        // only set WAL mode on the first write connection
        // it's a slow operation, and not needed on subsequent connections.
        write_con
            .pragma_update(None, "journal_mode", "WAL".to_string())
            .map_err(one_err::OneErr::new)?;

        // initialize tables if they don't already exist
        {
            let tx = write_con
                .transaction_with_behavior(
                    rusqlite::TransactionBehavior::Exclusive,
                )
                .map_err(one_err::OneErr::new)?;
            tx.execute_batch(sql::SCHEMA)
                .map_err(one_err::OneErr::new)?;
            tx.commit().map_err(one_err::OneErr::new)?;
        }

        let _version = write_con
            .query_row(sql::SELECT_VERSION, [], |row| row.get::<_, i64>(0))
            .map_err(one_err::OneErr::new)?;

        // initialize READ_CON_COUNT read connections to the database
        let mut read_cons: [Option<rusqlite::Connection>; READ_CON_COUNT] =
            Default::default();

        for rc_mut in read_cons.iter_mut() {
            // open READ_ONLY connection to the database
            let read_con = rusqlite::Connection::open_with_flags(
                &path,
                OpenFlags::SQLITE_OPEN_READ_ONLY
                    | OpenFlags::SQLITE_OPEN_NO_MUTEX
                    | OpenFlags::SQLITE_OPEN_URI,
            )
            .map_err(one_err::OneErr::new)?;

            // set generic pragmas
            set_pragmas(&read_con, key_pragma.clone(), db_salt.clone())
                .map_err(one_err::OneErr::new)?;

            *rc_mut = Some(read_con);
        }

        // build the pool state instance
        let inner = Self(Arc::new(Mutex::new(SqlPoolInner {
            ctx_secret: Arc::new(Mutex::new(ctx_secret)),
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
        db_key: SharedSizedLockedArray<32>,
        db_salt: BinDataSized<16>,
    ) -> impl Future<Output = LairResult<LairStore>> + 'static + Send {
        async move {
            tokio::task::spawn_blocking(move || {
                Self::new_sync(path, db_key, db_salt)
            })
            .await
            .map_err(one_err::OneErr::new)?
        }
    }

    /// Get a read_only connection to the database from the pool
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

    /// Get the single write connection to the database from the pool
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

fn create_configured_db_connection(
    path: &std::path::PathBuf,
    key_pragma: SharedSizedLockedArray<KEY_PRAGMA_LEN>,
    db_salt: BinDataSized<16>,
) -> rusqlite::Result<rusqlite::Connection> {
    use rusqlite::OpenFlags;

    // open a single write connection to the database
    let write_con = rusqlite::Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_URI,
    )?;

    // set generic pragmas
    set_pragmas(&write_con, key_pragma, db_salt)?;

    Ok(write_con)
}

impl AsLairStore for SqlPool {
    fn get_bidi_ctx_key(&self) -> SharedSizedLockedArray<32> {
        self.0.lock().ctx_secret.clone()
    }

    fn list_entries(
        &self,
    ) -> BoxFuture<'static, LairResult<Vec<LairEntryInfo>>> {
        let read = self.read();
        async move {
            let mut read = read.await;
            read.transaction(|txn| {
                let mut s = txn
                    .prepare(sql::SELECT_ALL)
                    .map_err(one_err::OneErr::new)?;
                let it = s
                    .query_map([], |row| {
                        // go ahead and clone here, so we're not doing the
                        // decoding while the database is connected...
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
                        LairEntryInner::WkaTlsCert {
                            tag, cert_info, ..
                        } => LairEntryInfo::WkaTlsCert { tag, cert_info },
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
        let this = self.clone();
        async move {
            let seed_info = match &*entry {
                LairEntryInner::Seed { seed_info, .. } => {
                    Some(seed_info.clone())
                }
                LairEntryInner::DeepLockedSeed { seed_info, .. } => {
                    Some(seed_info.clone())
                }
                _ => None,
            };
            let bytes = entry.encode()?;
            let mut write = this.write().await;
            if let Some(seed_info) = seed_info {
                write
                    .transaction(move |txn| {
                        // if the entry type has seed info
                        // add the extra columns so we can look up
                        // the entry by public keys
                        txn.execute(
                            sql::INSERT_SEED,
                            params![
                                entry.tag(),
                                &seed_info.ed25519_pub_key[..],
                                &seed_info.x25519_pub_key[..],
                                bytes,
                            ],
                        )
                        .map(|_| ())
                        .map_err(one_err::OneErr::new)
                    })
                    .await
            } else {
                write
                    .transaction(move |txn| {
                        txn.execute(sql::INSERT, params![entry.tag(), bytes])
                            .map(|_| ())
                            .map_err(one_err::OneErr::new)
                    })
                    .await
            }
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
                    txn.query_row(sql::SELECT_BY_TAG, params![tag], |row| {
                        row.get::<_, Vec<u8>>(0)
                    })
                    .map_err(one_err::OneErr::new)
                })
                .await?;
            let e = LairEntryInner::decode(&data)?;
            Ok(Arc::new(e))
        }
        .boxed()
    }

    fn get_entry_by_ed25519_pub_key(
        &self,
        ed25519_pub_key: Ed25519PubKey,
    ) -> BoxFuture<'static, LairResult<LairEntry>> {
        let read = self.read();
        async move {
            let mut read = read.await;
            let data = read
                .transaction(move |txn| {
                    txn.query_row(
                        sql::SELECT_BY_SIGN_PK,
                        params![&ed25519_pub_key[..]],
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

    fn get_entry_by_x25519_pub_key(
        &self,
        x25519_pub_key: X25519PubKey,
    ) -> BoxFuture<'static, LairResult<LairEntry>> {
        let read = self.read();
        async move {
            let mut read = read.await;
            let data = read
                .transaction(move |txn| {
                    txn.query_row(
                        "SELECT data FROM lair_keystore WHERE x25519_pub_key = ?1;",
                        params![&x25519_pub_key[..]],
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
    mut key: sodoken::SizedLockedArray<32>,
) -> LairResult<sodoken::SizedLockedArray<KEY_PRAGMA_LEN>> {
    // write the pragma line
    let mut key_pragma =
        sodoken::SizedLockedArray::<{ KEY_PRAGMA_LEN }>::new()?;

    {
        use std::io::Write;

        let mut key_pragma = key_pragma.lock();
        key_pragma.copy_from_slice(KEY_PRAGMA);
        let mut c = std::io::Cursor::new(&mut key_pragma[16..80]);
        for b in &*key.lock() {
            write!(c, "{b:02X}").map_err(one_err::OneErr::new)?;
        }
    }

    Ok(key_pragma)
}

fn configure_encryption(con: &rusqlite::Connection) -> rusqlite::Result<()> {
    con.execute_batch(
        r#"
--ensure we use version 4 settings even if we get a newer sqlcipher
--https://www.zetetic.net/sqlcipher/sqlcipher-api/#cipher_compatibility
PRAGMA cipher_compatibility = 4;

--sqlcipher ios compatibility requires this, but breaks salting
--https://www.zetetic.net/sqlcipher/sqlcipher-api/#cipher_plaintext_header_size
PRAGMA cipher_plaintext_header_size = 32;
"#,
    )
}

fn set_salt(
    con: &rusqlite::Connection,
    name: &'static str,
    db_salt: BinDataSized<16>,
) -> rusqlite::Result<()> {
    let mut salt = format!("PRAGMA {name} = \"x'");
    for b in *db_salt.0 {
        salt.push_str(&format!("{b:02X}"));
    }
    salt.push_str("'\";");

    con.execute_optional(&salt, [])
}

fn set_pragmas(
    con: &rusqlite::Connection,
    key_pragma: SharedSizedLockedArray<KEY_PRAGMA_LEN>,
    db_salt: BinDataSized<16>,
) -> rusqlite::Result<()> {
    con.busy_timeout(std::time::Duration::from_millis(30_000))?;

    con.execute_optional(
        std::str::from_utf8(&*key_pragma.lock().lock()).unwrap(),
        [],
    )?;

    set_salt(con, "cipher_salt", db_salt)?;

    configure_encryption(con)?;

    con.pragma_update(None, "trusted_schema", "0".to_string())?;

    con.pragma_update(None, "synchronous", "1".to_string())?;

    Ok(())
}

fn encrypt_unencrypted_database(
    path: &std::path::PathBuf,
    key_pragma: SharedSizedLockedArray<KEY_PRAGMA_LEN>,
    db_salt: BinDataSized<16>,
) -> LairResult<()> {
    // e.g. keystore/store_file -> keystore/store_file-encrypted
    let encrypted_path = path
        .parent()
        .ok_or_else(|| -> one_err::OneErr {
            format!("Database file path has no parent: {:?}", path).into()
        })?
        .join(
            path.file_stem()
                .and_then(|s| s.to_str())
                .ok_or_else(|| -> one_err::OneErr {
                    format!("Database file path has no name: {:?}", path).into()
                })?
                .to_string()
                + "-encrypted"
                + &path
                    .extension()
                    .and_then(|s| s.to_str())
                    .map(|p| ".".to_string() + p)
                    .unwrap_or_default(),
        );

    tracing::warn!(
        "Attempting encryption of unencrypted database: {:?} -> {:?}",
        path,
        encrypted_path
    );

    // Migrate the database
    {
        let conn =
            rusqlite::Connection::open(path).map_err(one_err::OneErr::new)?;

        // Ensure everything in the WAL is written to the main database
        conn.execute("VACUUM", ()).map_err(one_err::OneErr::new)?;

        // Start an exclusive transaction to avoid anybody writing to the database while we're migrating it
        conn.execute("BEGIN EXCLUSIVE", ())
            .map_err(one_err::OneErr::new)?;

        {
            let mut lock = key_pragma.lock();
            conn.execute(
                "ATTACH DATABASE :db_name AS encrypted KEY :key",
                rusqlite::named_params! {
                    ":db_name": encrypted_path.to_str(),
                    ":key": &lock.lock()[14..81],
                },
            )
            .map_err(one_err::OneErr::new)?;
        }

        conn.execute_batch(
            r#"
PRAGMA encrypted.cipher_compatibility = 4;
PRAGMA encrypted.cipher_plaintext_header_size = 32;
"#,
        )
        .map_err(one_err::OneErr::new)?;

        set_salt(&conn, "encrypted.cipher_salt", db_salt)
            .map_err(one_err::OneErr::new)?;

        conn.query_row("SELECT sqlcipher_export('encrypted')", (), |_| Ok(0))
            .map_err(one_err::OneErr::new)?;

        conn.execute("COMMIT", ()).map_err(one_err::OneErr::new)?;

        conn.execute("DETACH DATABASE encrypted", ())
            .map_err(one_err::OneErr::new)?;
        conn.close()
            .map_err(|(_, err)| err)
            .map_err(one_err::OneErr::new)?;
    }

    // Swap the databases over
    std::fs::remove_file(path)?;
    std::fs::rename(encrypted_path, path)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn sqlite_sanity() {
        // this is just a sanity / smoke test
        // this is exercised better in the full server_test.rs

        let tmpdir = tempdir::TempDir::new("lair-keystore-test").unwrap();
        let mut sqlite = tmpdir.path().to_path_buf();
        sqlite.push("db.sqlite3");

        let db_key = Arc::new(Mutex::new(
            sodoken::SizedLockedArray::<32>::new().unwrap(),
        ));
        let db_salt = BinDataSized([0; 16].into());

        let pool = SqlPool::new(sqlite, db_key, db_salt).await.unwrap();

        let pk = pool
            .new_seed("test-tag".into(), false)
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

        pool.new_wka_tls_cert("test-cert".into()).await.unwrap();
    }
}
