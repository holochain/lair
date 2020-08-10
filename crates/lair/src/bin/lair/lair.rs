#![deny(warnings)]
#![deny(missing_docs)]
//! main entry point

/// main entry point
#[tokio::main]
pub async fn main() -> lair_api::LairResult<()> {
    Ok(lair::execute_lair().await?)
}
