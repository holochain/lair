// grrr clippy... you cannot specify extra bounds with the async fn syntax...
#![allow(clippy::manual_async_fn)]
// default implementations don't always make sense...
#![allow(clippy::new_without_default)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

//! Secret lair private keystore API library.
//!
//! [![Project](https://img.shields.io/badge/project-holochain-blue.svg?style=flat-square)](http://holochain.org/)
//! [![Forum](https://img.shields.io/badge/chat-forum%2eholochain%2enet-blue.svg?style=flat-square)](https://forum.holochain.org)
//! [![Chat](https://img.shields.io/badge/chat-chat%2eholochain%2enet-blue.svg?style=flat-square)](https://chat.holochain.org)
//!
//! [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
//! [![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
//!
//! This library crate contains most of the logic for dealing with lair.
//!
//! - If you wish to run an in-process / in-memory keystore, or connect to
//!   an external lair keystore as a client, this is the library for you.
//! - If you want to run the canonical lair-keystore, see the
//!   [lair_keystore](https://crates.io/crates/lair_keystore) crate.
//! - If you want to run a canonical lair-keystore in-process, using
//!   the canonical sqlcipher database, see the
//!   [lair_keystore](https://crates.io/crates/lair_keystore) crate.
//! - See the [lair_api] module for information about the lair_keystore_api
//!   protocol.
//! - See [LairClient] for the client struct api.
//!
//! #### Establishing a client connection to a canonical ipc keystore binary:
//!
//! ```
//! # #[tokio::main]
//! # async fn main() {
//! use lair_keystore_api::prelude::*;
//! use lair_keystore_api::ipc_keystore::*;
//! # use lair_keystore_api::dependencies::*;
//! # use lair_keystore_api::mem_store::*;
//! # use std::sync::Arc;
//! # let tmp_dir = tempdir::TempDir::new("lair_ipc_doc_test").unwrap();
//! # let passphrase = sodoken::BufRead::from(&b"passphrase"[..]);
//! # let config = Arc::new(
//! #     hc_seed_bundle::PwHashLimits::Minimum
//! #         .with_exec(|| {
//! #             LairServerConfigInner::new(
//! #                 tmp_dir.path(),
//! #                 passphrase.clone(),
//! #             )
//! #         })
//! #         .await
//! #         .unwrap(),
//! # );
//! # let keystore = IpcKeystoreServer::new(
//! #     config.clone(),
//! #     create_mem_store_factory(),
//! #     passphrase.clone(),
//! # )
//! # .await
//! # .unwrap();
//! # let connection_url = config.connection_url.clone();
//!
//! // create a client connection
//! let client =
//!     ipc_keystore_connect(connection_url, passphrase)
//!         .await
//!         .unwrap();
//!
//! // create a new seed
//! let seed_info = client.new_seed(
//!     "test-seed".into(),
//!     None,
//!     false,
//! ).await.unwrap();
//!
//! // sign some data
//! let sig = client.sign_by_pub_key(
//!     seed_info.ed25519_pub_key.clone(),
//!     None,
//!     b"test-data".to_vec().into(),
//! ).await.unwrap();
//!
//! // verify the signature
//! assert!(seed_info.ed25519_pub_key.verify_detached(
//!     sig,
//!     b"test-data".to_vec(),
//! ).await.unwrap());
//! # }
//! ```

include!(concat!(env!("OUT_DIR"), "/ver.rs"));

/// Re-exported dependencies.
pub mod dependencies {
    pub use base64;
    pub use dunce;
    pub use hc_seed_bundle;
    pub use hc_seed_bundle::dependencies::*;
    pub use nanoid;
    pub use once_cell;
    pub use parking_lot;
    pub use serde_json;
    pub use serde_yaml;
    pub use tokio;
    pub use tracing;
    pub use url;
}

use dependencies::*;

/// Lair result type.
pub type LairResult<T> = Result<T, one_err::OneErr>;

pub mod config;
pub mod encoding_types;
pub mod in_proc_keystore;
pub mod internal;
pub mod ipc_keystore;
pub mod lair_api;
pub mod lair_client;
pub mod lair_server;
pub mod lair_store;
pub mod mem_store;
pub mod sodium_secretstream;

/// Re-export module of types generally used with lair.
pub mod prelude {
    pub use crate::config::*;
    pub use crate::encoding_types::*;
    pub use crate::lair_api::*;
    pub use crate::lair_client::*;
    pub use crate::lair_server::*;
    pub use crate::lair_store::*;
    pub use crate::LairResult;
    pub use hc_seed_bundle::PwHashLimits;
}

use prelude::*;

#[doc(inline)]
pub use crate::ipc_keystore::ipc_keystore_connect;
#[doc(inline)]
pub use crate::ipc_keystore::ipc_keystore_connect_options;
#[doc(inline)]
pub use crate::lair_client::LairClient;
