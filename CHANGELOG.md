# Changelog

All notable changes to this project will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## \[[0.9.0](https://github.com/holochain/lair/compare/v0.8.0...v0.9.0)\] - 2026-11-26

### Features

- \[**BREAKING**\] Await client shutdown before returning by @jost-s in [#180](https://github.com/holochain/lair/pull/180)
  - **Breaking Change**: Lair_keystore::InProcKeystore is now a named-field struct that holds the exclusive store lock, and client shutdown blocks until teardown completes instead of returning after signalling.

### Miscellaneous Tasks

- Update the AI_POLICY.md with shared content in [#174](https://github.com/holochain/lair/pull/174)
- Update the AI_POLICY.md with shared content
- Update the CONTRIBUTING.md with shared content

### Automated Changes

- *(deps)* Bump the updates group with 4 updates by @dependabot[bot] in [#179](https://github.com/holochain/lair/pull/179)
- Update dependabot.yml with shared content in [#173](https://github.com/holochain/lair/pull/173)
- Update dependabot.yml with shared content

### First-time Contributors

- @dependabot[bot] made their first contribution in [#179](https://github.com/holochain/lair/pull/179)

## \[[0.8.0](https://github.com/holochain/lair/compare/v0.7.1...v0.8.0)\] - 2026-11-24

### Features

- Add a persistent in-process keystore constructor by @jost-s in [#177](https://github.com/holochain/lair/pull/177)
  - Add lair_keystore::InProcKeystore::new, which acquires exclusive ownership of the configured sqlite store and runs the lair server in-process. This lets callers use the canonical persistent store without an ipc socket, avoiding socket path limits on iOS.
  - The factory-taking lair_keystore_api::InProcKeystore::new is unchanged.
- \[**BREAKING**\] Lock the store with an exclusive OS file lock by @jost-s
  - Replace the pid/process-name check with an exclusive, nonblocking OS file lock derived from the resolved store path. The shared store preparation is used by StandaloneServer, so competing lair instances in the same process or across processes cannot clobber the store.
  - The lock is held as long as any store factory or store handle is alive and is released on startup failure or when the last resource closes.
  - **Breaking Change**: Remove the public pid_file config field, the pid_check module, and the sysinfo re-export. Store ownership is now enforced with an OS file lock derived from the store path.

### Automated Changes

- Update CODEOWNERS with shared content in [#170](https://github.com/holochain/lair/pull/170)

## \[[0.7.1](https://github.com/holochain/lair/compare/v0.7.0...v0.7.1)\] - 2026-04-30

### Features

- Switch from `serde_yaml` to `yaml_serde` by @ThetaSinner in [#166](https://github.com/holochain/lair/pull/166)

### Miscellaneous Tasks

- Update the CONTRIBUTING.md with shared content in [#165](https://github.com/holochain/lair/pull/165)

## \[[0.7.0](https://github.com/holochain/lair/compare/v0.6.3...v0.7.0)\] - 2026-04-20

### Miscellaneous Tasks

- Downgrade rusqlite until dependency conflicts can be resolved downstream by @ThetaSinner in [#163](https://github.com/holochain/lair/pull/163)
- \[**BREAKING**\] Update dependencies by @ThetaSinner

### CI

- Update release actions by @ThetaSinner

### Documentation

- Remove unused PR template by @ThetaSinner in [#162](https://github.com/holochain/lair/pull/162)

## \[[0.6.3](https://github.com/holochain/lair/compare/v0.6.2...v0.6.3)\] - 2025-09-29

### Miscellaneous Tasks

- Update dependencies (#155) by @ThetaSinner in [#155](https://github.com/holochain/lair/pull/155)
  - Chore: Update dependencies
  - Chore: Format SQL
- Fix build script to support publishing (#151) by @ThetaSinner in [#151](https://github.com/holochain/lair/pull/151)

### CI

- Use v1.3.0 of the release integration actions (#159) by @ThetaSinner in [#159](https://github.com/holochain/lair/pull/159)
- Update release integration action versions (#156) by @ThetaSinner in [#156](https://github.com/holochain/lair/pull/156)

### Refactor

- Replace the unmaintained crate `tempdir` with the maintained crate `tempfile` (#154) by @ThetaSinner in [#154](https://github.com/holochain/lair/pull/154)
- Replace `structopt` with `clap` in the `lair-keystore` binary (#153) by @ThetaSinner in [#153](https://github.com/holochain/lair/pull/153)

## [0.6.2] - 2025-06-19

### Added

- Add some why docs (#147) by @neonphog in [#147](https://github.com/holochain/lair/pull/147)

### Changed

- Add release workflows (#149) by @ThetaSinner in [#149](https://github.com/holochain/lair/pull/149)
- Update project dependencies and tidy workspace (#148) by @ThetaSinner in [#148](https://github.com/holochain/lair/pull/148)

## 0.6.1

- Update to a stable version of `sodoken` at 0.1.0

## 0.6.0

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
