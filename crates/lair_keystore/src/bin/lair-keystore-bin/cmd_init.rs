use super::*;
use std::sync::Mutex;
use tokio::io::AsyncWriteExt;

pub(crate) async fn exec(
    lair_root: std::path::PathBuf,
    opt: OptInit,
) -> LairResult<()> {
    tokio::fs::DirBuilder::new()
        .recursive(true)
        .create(&lair_root)
        .await?;

    let mut config_n = lair_root.clone();
    config_n.push(CONFIG_N);

    if tokio::fs::metadata(&config_n).await.is_ok() {
        return Err(format!(
            "{config_n:?} already exists - refusing to overwrite existing store"
        )
        .into());
    }

    let passphrase = if opt.piped {
        read_piped_passphrase().await?
    } else {
        read_interactive_passphrase("\n# passphrase> ").await?
    };

    println!("\n# lair-keystore init generating secure config...");

    let config = LairServerConfigInner::new(
        &lair_root,
        Arc::new(Mutex::new(passphrase)),
    )
    .await?;

    let mut config_f = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&config_n)
        .await?;

    config_f.write_all(config.to_string().as_bytes()).await?;
    config_f.shutdown().await?;
    drop(config_f);

    println!("\n# lair-keystore init config:\n{config_n:?}");
    println!(
        "\n# lair-keystore init connection_url:\n{}",
        config.connection_url
    );

    Ok(())
}
