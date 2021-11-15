## `lair-keystore init --help`
```no-compile
lair-keystore-init 0.1.0-alpha.5
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