#![deny(warnings)]
#![deny(missing_docs)]
//! main entry point

/// main entry point
#[tokio::main]
pub async fn main() -> lair_api::LairResult<()> {
    lair::execute_lair().await?;

    // wait forever... i.e. until a ctrl-c
    futures::future::pending::<()>().await;

    Ok(())
}
