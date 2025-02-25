## Unreleased

- Update to Rust 1.85 [#144](https://github.com/holochain/lair/pull/144)
- Update to latest `sodoken` version, comes with breaking changes to the Lair API to switch from read buffers to locked 
  arrays. See the documentation for updated usage examples. [#143](https://github.com/holochain/lair/pull/143)

## 0.5.3

- Upgrade `sysinfo` dependency to resolve an issue with building against a recent libc [#140](https://github.com/holochain/lair/pull/140)
- Set tracing writer to write to `stderr` instead of `stdout` [#138](https://github.com/holochain/lair/pull/138)
- The `lair-keystore` binary now exits with an error (exit code `1`) if an error occurs [#138](https://github.com/holochain/lair/pull/138)

## 0.5.2

- enables some basic tracing [#135](https://github.com/holochain/lair/pull/135)

## 0.5.1

- fix to build.rs to not check sql formatting unless environment variable CHK_SQL_FMT=1

## 0.5.0

- breaking sqlcipher update for ios compatibility

## 0.4.1

- Add a way to migrate unencrypted databases to encrypted by providing an environment variable `LAIR_MIGRATE_UNENCRYPTED="true"`, Lair will detect databases which can't be opened and attempt migration. #121

# 0.4.0

- pin serde and rmp-serde #119

## 0.0.2
