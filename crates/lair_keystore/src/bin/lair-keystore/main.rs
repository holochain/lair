#![deny(warnings)]
#![deny(missing_docs)]
//! main entry point

/// main entry point
#[tokio::main]
pub async fn main() -> lair_keystore_api::LairResult<()> {
    lair_keystore::execute_lair().await?;

    // wait forever... i.e. until a ctrl-c
    futures::future::pending::<()>().await;

    Ok(())
}
