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
