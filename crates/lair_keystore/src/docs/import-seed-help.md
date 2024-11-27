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
