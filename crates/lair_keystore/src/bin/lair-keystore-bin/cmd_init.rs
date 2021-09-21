use super::*;
use tokio::io::AsyncWriteExt;

pub(crate) async fn exec(
    lair_root: std::path::PathBuf,
    opt: OptInit,
) -> LairResult<()> {
    if !opt.interactive {
        return Err("lair-keystore init -i currently required for interactive passphrase entry".into());
    }

    tokio::fs::DirBuilder::new()
        .recursive(true)
        .create(&lair_root)
        .await?;

    let mut config_n = lair_root.clone();
    config_n.push(CONFIG_N);

    if tokio::fs::metadata(&config_n).await.is_ok() {
        return Err(format!(
            "{:?} already exists - refusing to overwrite existing store",
            config_n
        )
        .into());
    }

    let mut pass_tmp =
        rpassword::read_password_from_tty(Some("\n# passphrase> "))
            .map_err(one_err::OneErr::new)?
            .into_bytes();
    let passphrase = match sodoken::BufWrite::new_mem_locked(pass_tmp.len()) {
        Err(e) => {
            pass_tmp.fill(0);
            return Err(e);
        }
        Ok(p) => {
            {
                let mut lock = p.write_lock();
                lock.copy_from_slice(&pass_tmp);
                pass_tmp.fill(0);
            }
            p.to_read()
        }
    };

    println!("\n# lair-keystore init generating secure config...");

    let config = lair_keystore_api::lair_core::LairServerConfigInner::new(
        &lair_root, passphrase,
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

    println!("\n# lair-keystore init config:\n{:?}", config_n);
    println!(
        "\n# lair-keystore init connection_url:\n{}",
        config.connection_url
    );

    Ok(())
}
