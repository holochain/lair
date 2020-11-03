//! internal ghost actor file wrapper

use crate::*;

ghost_actor::ghost_chan! {
    /// chan wrapper for file access
    pub(crate) chan EntryStoreFile<LairError> {
        /// init and load up the "unlock" entry if it exists
        fn init_load_unlock() -> Option<Vec<u8>>;

        /// write the unlock entry to the file
        fn write_unlock(entry_data: Vec<u8>) -> ();

        /// loading all entries from the file
        fn load_all_entries() -> Vec<(super::KeystoreIndex, Vec<u8>)>;

        /// write a new entry to the store file
        fn write_next_entry(entry_data: Vec<u8>) -> super::KeystoreIndex;
    }
}

pub(crate) async fn spawn_entry_store_file_task(
    store_file: tokio::fs::File,
) -> LairResult<futures::channel::mpsc::Sender<EntryStoreFile>> {
    let (s, r) = futures::channel::mpsc::channel(10);

    tokio::task::spawn(entry_store_file_task(store_file, r));

    Ok(s)
}

/// this is not an actor, because we cannot do paralel file access
/// we actually need to process requests in series.
async fn entry_store_file_task(
    mut store_file: tokio::fs::File,
    mut recv: futures::channel::mpsc::Receiver<EntryStoreFile>,
) -> LairResult<()> {
    use futures::{future::FutureExt, stream::StreamExt};

    while let Some(req) = recv.next().await {
        match req {
            EntryStoreFile::InitLoadUnlock { respond, .. } => {
                let res = init_load_unlock(&mut store_file).await;
                respond.r(Ok(async move { res }.boxed().into()));
            }
            EntryStoreFile::WriteUnlock {
                respond,
                entry_data,
                ..
            } => {
                let res = write_unlock(&mut store_file, entry_data).await;
                respond.r(Ok(async move { res }.boxed().into()));
            }
            EntryStoreFile::LoadAllEntries { respond, .. } => {
                let res = load_all_entries(&mut store_file).await;
                respond.r(Ok(async move { res }.boxed().into()));
            }
            EntryStoreFile::WriteNextEntry {
                respond,
                entry_data,
                ..
            } => {
                let res = write_next_entry(&mut store_file, entry_data).await;
                respond.r(Ok(async move { res }.boxed().into()));
            }
        }
    }

    Ok(())
}

async fn init_load_unlock(
    store_file: &mut tokio::fs::File,
) -> LairResult<Option<Vec<u8>>> {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};

    let meta = store_file.metadata().await.map_err(LairError::other)?;
    let total_size = meta.len();
    if total_size >= entry::ENTRY_SIZE as u64 {
        store_file
            .seek(std::io::SeekFrom::Start(0))
            .await
            .map_err(LairError::other)?;

        let mut buf = vec![0; entry::ENTRY_SIZE];
        store_file
            .read_exact(&mut buf)
            .await
            .map_err(LairError::other)?;

        Ok(Some(buf))
    } else {
        Ok(None)
    }
}

async fn write_unlock(
    store_file: &mut tokio::fs::File,
    entry_data: Vec<u8>,
) -> LairResult<()> {
    use tokio::io::{AsyncSeekExt, AsyncWriteExt};

    store_file
        .seek(std::io::SeekFrom::Start(0))
        .await
        .map_err(LairError::other)?;

    store_file
        .write_all(&entry_data)
        .await
        .map_err(LairError::other)?;

    store_file.sync_all().await.map_err(LairError::other)?;

    Ok(())
}

async fn query_entry_count(
    store_file: &mut tokio::fs::File,
) -> LairResult<u64> {
    let meta = store_file.metadata().await.map_err(LairError::other)?;
    let total_size = meta.len();
    let entry_count = total_size / entry::ENTRY_SIZE as u64;

    if entry_count * entry::ENTRY_SIZE as u64 != total_size {
        // @todo - panic for now... eventually cover over invalid entry
        panic!(
            "BAD entry size {} count * {} size != {} file size",
            entry_count,
            entry::ENTRY_SIZE,
            total_size
        );
    }

    Ok(entry_count)
}

async fn load_all_entries(
    store_file: &mut tokio::fs::File,
) -> LairResult<Vec<(super::KeystoreIndex, Vec<u8>)>> {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};

    let entry_count = query_entry_count(store_file).await?;

    if entry_count <= 1 {
        return Ok(Vec::with_capacity(0));
    }

    store_file
        .seek(std::io::SeekFrom::Start(entry::ENTRY_SIZE as u64))
        .await
        .map_err(LairError::other)?;

    let mut out = Vec::new();

    for i in 1..(entry_count as u32) {
        let mut buf = vec![0; entry::ENTRY_SIZE];
        store_file
            .read_exact(&mut buf)
            .await
            .map_err(LairError::other)?;
        out.push((i.into(), buf));
    }

    Ok(out)
}

async fn write_next_entry(
    store_file: &mut tokio::fs::File,
    entry_data: Vec<u8>,
) -> LairResult<super::KeystoreIndex> {
    use tokio::io::{AsyncSeekExt, AsyncWriteExt};

    if entry_data.len() != entry::ENTRY_SIZE {
        return Err(format!(
            "bad entry size, expected {}, got {}",
            entry::ENTRY_SIZE,
            entry_data.len(),
        )
        .into());
    }

    let entry_count = query_entry_count(store_file).await?;

    let start_loc = entry_count * entry::ENTRY_SIZE as u64;

    store_file
        .seek(std::io::SeekFrom::Start(start_loc))
        .await
        .map_err(LairError::other)?;

    store_file
        .write_all(&entry_data)
        .await
        .map_err(LairError::other)?;

    store_file.sync_all().await.map_err(LairError::other)?;

    Ok((entry_count as u32).into())
}
