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
