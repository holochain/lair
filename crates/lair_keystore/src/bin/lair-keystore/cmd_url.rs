use super::*;

pub(crate) async fn exec(mut lair_root: std::path::PathBuf) -> LairResult<()> {
    lair_root.push(CONFIG_N);

    let bytes = tokio::fs::read(&lair_root).await?;
    let config =
        lair_keystore_api::lair_core::LairServerConfigInner::from_bytes(
            &bytes,
        )?;

    println!("{}", config.connection_url);

    Ok(())
}
