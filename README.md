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
use lair_keystore::create_sql_pool_factory;
let _sqlite_store_factory = create_sql_pool_factory(".");
```

## `lair-keystore` commandline executable usage:


License: MIT OR Apache-2.0

### `lair-keystore --help`
```text
lair_keystore 0.4.7
secret lair private keystore

USAGE:
    lair-keystore [OPTIONS] <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -r, --lair-root <lair-root>    Lair root storage and config directory [env: LAIR_ROOT=]  [default: .]

SUBCOMMANDS:
    help           Prints this message or the help of the given subcommand(s)
    import-seed    Load a seed bundle into this lair-keystore instance.
                   Note, this operation requires capturing the pid_file,
                   make sure you do not have a lair-server running.
                   Note, we currently only support importing seed bundles
                   with a pwhash cipher. We'll try the passphrase you
                   supply with all ciphers used to lock the bundle.
    init           Set up a new lair private keystore.
    server         Run a lair keystore server instance. Note you must
                   have initialized a config file first with
                   'lair-keystore init'.
    url            Print the connection_url for a configured lair-keystore
                   server to stdout and exit.

```
### `lair-keystore init --help`
```text
lair-keystore-init 0.4.7
Set up a new lair private keystore.

USAGE:
    lair-keystore init [FLAGS]

FLAGS:
    -h, --help       Prints help information
    -p, --piped      Instead of the normal "interactive" method of passphrase
                     retrieval, read the passphrase from stdin. Be careful
                     how you make use of this, as it could be less secure,
                     for example, make sure it is not saved in your
                     `~/.bash_history`.
    -V, --version    Prints version information

```
### `lair-keystore url --help`
```text
lair-keystore-url 0.4.7
Print the connection_url for a configured lair-keystore
server to stdout and exit.

USAGE:
    lair-keystore url

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

```
### `lair-keystore import-seed --help`
```text
lair-keystore-import-seed 0.4.7
Load a seed bundle into this lair-keystore instance.
Note, this operation requires capturing the pid_file,
make sure you do not have a lair-server running.
Note, we currently only support importing seed bundles
with a pwhash cipher. We'll try the passphrase you
supply with all ciphers used to lock the bundle.

USAGE:
    lair-keystore import-seed [FLAGS] <tag> <seed-bundle-base64>

FLAGS:
    -d, --deep-lock     Specify that this seed should be loaded as a
                        "deep-locked" seed. This seed will require an
                        additional passphrase specified at access time
                        (signature / box / key derivation) to decrypt the seed.
    -e, --exportable    Mark this seed as "exportable" indicating
                        this key can be extracted again after having
                        been imported.
    -h, --help          Prints help information
    -p, --piped         Instead of the normal "interactive" method of passphrase
                        retreival, read the passphrase from stdin. Be careful
                        how you make use of this, as it could be less secure.
                        Passphrases are newline delimited in this order:
                        - 1 - keystore unlock passphrase
                        - 2 - bundle unlock passphrase
                        - 3 - deep lock passphrase
                              (if -d / --deep-lock is specified)
    -V, --version       Prints version information

ARGS:
    <tag>                   The identification tag for this seed.
    <seed-bundle-base64>    The base64url encoded hc_seed_bundle.

```
### `lair-keystore server --help`
```text
lair-keystore-server 0.4.7
Run a lair keystore server instance. Note you must
have initialized a config file first with
'lair-keystore init'.

USAGE:
    lair-keystore server [FLAGS]

FLAGS:
    -h, --help       Prints help information
    -p, --piped      Instead of the normal "interactive" method of passphrase
                     retreival, read the passphrase from stdin. Be careful
                     how you make use of this, as it could be less secure,
                     for example, make sure it is not saved in your
                     `~/.bash_history`.
    -V, --version    Prints version information

```
