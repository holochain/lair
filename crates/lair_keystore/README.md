# lair_keystore

Secret lair private keystore

[![Project](https://img.shields.io/badge/project-holochain-blue.svg?style=flat-square)](http://holochain.org/)
[![Forum](https://img.shields.io/badge/chat-forum%2eholochain%2enet-blue.svg?style=flat-square)](https://forum.holochain.org)
[![Chat](https://img.shields.io/badge/chat-chat%2eholochain%2enet-blue.svg?style=flat-square)](https://chat.holochain.org)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

This crate mostly provides the `lair-keystore` executable allowing
initialization, configuration, and running of a Lair keystore.

If you want to run an in-process keystore, this crate also provides the
canonical sqlite store.

For making use of a Lair keystore in a client application, see the
[lair_keystore_api](https://crates.io/crates/lair_keystore_api) crate.

## What is lair-keystore, and why does it exist?

Lair Keystore is a general asymmetric cryptographic private key store
project originally written for Holochain, but intended to be usable for
any application.

The store mainly tracks the "seed" data that for ed25519 and x25519 allow
generation of keypairs, and can be thought of as synonymous with private
keys.

Lair allows derivation of this seed material for usage similar to HD
wallets, with the intention that an end-user could create a "root" seed,
from which could be deterministically derived a revocation seed and any
number of device and application seeds, which would all be retrievable from
a securely stored paper mnemonic of the root. (This has not yet been
implemented in Holochain).

Lair Keystore was originally intended to be a standalone binary.
Given the overhead and security implications of having a process with access
to private key material, it was originally envisioned that an end-user would
run a single keystore on their system, and be prompted with a pin-entry UI
that would unlock access to the private keys for a specified period of time,
or every time an operation with a private key occurred in the case of "deep
locked" seeds. (This has also not been implemented in Holochain, and
moreover, Holochain has moved farther away from this intention by running
Lair Keystore as an "in process" library which makes it easier to bundle
executables).

[lair_keystore_api::LairClient] is the main type that is used to access
the keystore, and it mainly functions over an IPC connection (unix domain
sockets on Linux and MacOs, and named pipes on Windows). This type allows
you to create, access, export, and import tagged seeds, and then, using
either those tags or the public keys that are derived from those seeds,
perform signing, verification, encryption, and decryption operations.

## Rust conventions for dashes and underscores:

- Install with an underscore: `cargo install lair_keystore`
- Use binary with a dash: `$ lair-keystore help`
- Cargo.toml with an underscore:

```
[dependencies]
lair_keystore = "0.1.1"
```

- Library usage with underscores:

```rust
use lair_keystore::*;
```
