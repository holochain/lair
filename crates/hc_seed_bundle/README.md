# hc_seed_bundle

SeedBundle parsing and generation library.

[![Project](https://img.shields.io/badge/project-holochain-blue.svg?style=flat-square)](http://holochain.org/)
[![Forum](https://img.shields.io/badge/chat-forum%2eholochain%2enet-blue.svg?style=flat-square)](https://forum.holochain.org)
[![Chat](https://img.shields.io/badge/chat-chat%2eholochain%2enet-blue.svg?style=flat-square)](https://chat.holochain.org)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

#### Links

- [Git Repo - https://github.com/holochain/lair](https://github.com/holochain/lair)
- [API Documentation - https://docs.rs/hc_seed_bundle](https://docs.rs/hc_seed_bundle)
- [Javascript Implementation - https://holochain.github.io/hcSeedBundle/](https://holochain.github.io/hcSeedBundle/)

#### Rationale

- Applications like Holochain have different requirements than classic
  blockchain systems in terms of key management. Namely there is no need
  for read-only or hardened wallets (Holochain handles these concepts
  through capabilities and membranes).
- Applications like Holochain still have need of hierarchy and determinism
  in key (or in this case seed) derivation.
- Since we're using libsodium for hashing, signature, and encryption
  algorithms, let's use it for derivation as well.
- To be psychologically compatible with the
  [Bitcoin "HD Wallet" spec](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki),
  we will do away with the "context" part of sodium KDF by always setting
  it to `b"SeedBndl"` and focusing on the `subkey_id` and can declare a
  chain of subsequent derivations of a 32 byte seed in the form
  `m/68/1/65/8` where we apply `subkey_id`s 68, 1, 65, then 8 in turn.

#### hcSeedBundle Encoding Spec

Encoded in [MSGPACK](https://msgpack.org/index.html) binary format.

To better facilitate rust/javascript interoperability, the rust library
will treat msgpack "ext" types as binary data.

##### SeedBundle

```
// seed_bundle is a top-level array
'seed_bundle':array [
  // literal 'hcsb0' version / heuristic marker
  'id_ver':str,

  // list of SeedCiphers define how to decrypt
  'cipher_list':array [
    'cipher_1':SeedCipher,
    'cipher_2':SeedCipher,
    // ..
    'cipher_N':SeedCipher,
  ],

  // associated application data
  'app_data':bin,
]
```

##### SeedCipher::PwHash

```
// the PwHash type SeedCipher defines a straight-forward
// pwhash secret that is use to secretstream encrypt a seed
'seed_cipher':array [
  // literal 'pw' indicates the pw hash cipher type
  'type':str,

  // argon2id 16 byte salt
  'salt':bin,

  // argon2id mem limit capped to u32 for js compatibility
  'mem_limit':int,

  // argon2id ops limit capped to u32 for js compatibility
  'ops_limit':int,

  // secretstream 24 byte header
  'header':bin,

  // secretstream 49 byte cipher
  'cipher':bin,
]
```

##### SeedCipher::SecurityQuestions

```
// Security Questions SeedCipher defines a pwhash cipher
// based on concatonating 3 answers that are lcased/trimmed
'seed_cipher':array [
  // literal 'qa' indicates the security question cipher type
  'type':str,

  // argon2id 16 byte salt
  'salt':bin,

  // argon2id mem limit capped to u32 for js compatibility
  'mem_limit':int,

  // argon2id ops limit capped to u32 for js compatibility
  'ops_limit':int,

  // the first security question to be answered
  'question_1':str,

  // the second security question to be answered
  'question_2':str,

  // the third security question to be answered
  'question_3':str,

  // secretstream 24 byte header
  'header':bin,

  // secretstream 49 byte cipher
  'cipher':bin,
]
```

#### Algorithms

- `sodium_kdf32` - seed derivation
  - set to output 32 bytes (`[32 byte sub-seed]`)
  - context bytes - fixed `b"SeedBndl"`
  - subkey_id clamped to u32 to better support javascript
- `argon2id32` - generates secret for seed secretstream encryption
  - set to output 32 bytes (`[32 secret bytes]`)
  - salt: `[16 salt bytes from bundle]`
  - mem_limit: default `MODERATE`
  - ops_limit: default `MODERATE`
  - passphrase: user-supplied
- `secretstream_xchacha20poly1305`
  - single `push_final/pull_final` with entire contents

License: MIT OR Apache-2.0
