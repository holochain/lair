<a href="https://github.com/holochain/lair/blob/master/LICENSE-APACHE">![Crates.io](https://img.shields.io/crates/l/lair_keystore_api)</a>
<a href="https://crates.io/crates/lair_keystore_api">![Crates.io](https://img.shields.io/crates/v/lair_keystore_api)</a>

# lair_keystore_api

Secret lair private keystore API library.

This library crate contains most of the logic for dealing with lair.

- If you wish to run an in-process / in-memory keystore, or connect to
an external lair keystore as a client, this is the library for you.
- If you want to run the canonical lair-keystore, see the
[lair_keystore](https://crates.io/crates/lair_keystore) crate.
- If you want to run a canonical lair-keystore in-process, using
the canonical sqlcipher database, see the
[lair_keystore](https://crates.io/crates/lair_keystore) crate.
- See the [lair_api] module for information about the lair_keystore_api
protocol.
- See [LairClient] for the client struct api.

##### Establishing a client connection to a canonical ipc keystore binary:

```rust
use lair_keystore_api::prelude::*;
use lair_keystore_api::ipc_keystore::*;

// create a client connection
let client =
    ipc_keystore_connect(connection_url, passphrase)
        .await
        .unwrap();

// create a new seed
let seed_info = client.new_seed(
    "test-seed".into(),
    None,
    false,
).await.unwrap();

// sign some data
let sig = client.sign_by_pub_key(
    seed_info.ed25519_pub_key.clone(),
    None,
    b"test-data".to_vec().into(),
).await.unwrap();

// verify the signature
assert!(seed_info.ed25519_pub_key.verify_detached(
    sig,
    b"test-data".to_vec(),
).await.unwrap());
```
