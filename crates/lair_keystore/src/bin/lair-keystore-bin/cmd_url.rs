use super::*;

pub(crate) async fn exec(config: LairServerConfig) -> LairResult<()> {
    println!("{}", config.connection_url);

    Ok(())
}
