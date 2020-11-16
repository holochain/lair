
# Protocol
This section outlines the communication format and describes the payload byte order for each wire type.


## High-level overview of framing
The essential blocks of every message have 16 bytes of header information followed by the payload
bytes.

- Headers (16 bytes)
  - Message length (4 bytes - unsigned-LE)
  - Wire type (4 bytes - unsigned-LE)
  - Message ID (8 bytes - opaque/implementation-specific)
- Body
  - Payload data (bytes based on message length from Header)

```
                1               2               3               4 bytes
  0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
 +---------------------------------------------------------------+
 | Message length                                                |
 +---------------------------------------------------------------+
 | Wire type                                                     |
 +---------------------------------------------------------------+
 | Message ID                                                    |
 + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
 | Message ID (continued)                                        |
 +---------------------------------------------------------------+
 | Payload data                                                  |
 + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
 :                    Payload data (continued) ...               :
 +---------------------------------------------------------------+
```

### Message Length (4 bytes)
Total length of the message (min/max range `16 / 4294967295`).

- 16 (byte) header length + payload (byte) length

### Wire Type (4 bytes)

- byte 1
  - `0x*0` - request message
  - `0x*1` - response message
  - `0x*?` - undefined / reserved
- byte 2
  - `0x00` - the message is unclassified
  - `0x01` - the message is related to TLS
  - `0x02` - the message is related to Ed25519
  - `0x??` - undefined / reserved
- byte 3
  - `0x??` - undefined / reserved
- byte 4
  - `0xff` - the message is initiated by Lair
  - `0x00` - the request is for Lair
  - `0x??` - undefined / reserved

### Message ID (8 bytes)
An identifier used to match a response to the intial request.

### Payload (0+ bytes)
Can be any number of bytes.  The payload format is determined by the wire type.


## Wire Types

### Unlock Passphrase

#### `4278190096` Request payload

- empty

#### `4278190097` Response payload

- `8+` byte - passphrase (string)
  - `8` bytes (unsigned-LE) for length
  - `+` bytes for `utf8` encoded passphrase

### Get Last Entry

#### `16` Request payload

- empty

#### `17` Response payload

- `4` byte (unsigned-LE) - last keystore index

### Get Entry Type

#### `32` Request payload

- `4` byte (unsigned-LE) - keystore index

#### `33` Response payload

- `4` byte (unsigned-LE) - entry type
  - `0` - Invalid
  - `256` - TLS Certificate
  - `512` - Ed25519

### Get Server Info

#### `48` Request payload

- empty

#### `49` Response payload

- `8+` byte - server name
  - `8` bytes (unsigned-LE) for length
  - `+` bytes for `utf8` encoded server name
- `8+` byte - server version
  - `8` bytes (unsigned-LE) for length
  - `+` bytes for `utf8` encoded server version

### TLS - Create Self-signed Certificate from Entropy

#### `272` Request payload

- `4` byte (unsigned-LE) - TLS certificate algorithm
  - `512` - Ed25519
  - `513` - EcDSA P-256
  - `514` - EcDSA P-384

#### `273` Response payload

- `4` byte (unsigned-LE) - keystore index
- `8+` byte - certificate SNI
  - `8` bytes (unsigned-LE) for length
  - `+` bytes for `utf8` encoded certificate SNI
- `32` byte - certificate digest

### TLS - Get Certificate

#### `288` Request payload

- `4` byte (unsigned-LE) - keystore index

#### `289` Response payload

- `8+` byte - certificate SNI
  - `8` bytes (unsigned-LE) for length
  - `+` bytes for `utf8` encoded certificate SNI
- `32` byte - certificate digest


### TLS - Get Certificate by Index

#### `304` Request payload

- `4` byte (unsigned-LE) - keystore index

#### `305` Response payload

- `8` byte (unsigned-LE) - certificate length
- `+` byte - certificate


### TLS - Get Certificate by Digest

#### `320` Request payload

- `32` byte - certificate digest

#### `321` Response payload

- `8` byte (unsigned-LE) - certificate length
- `+` byte - certificate


### TLS - Get Certificate by SNI

#### `336` Request payload

- `8+` byte - certificate SNI
  - `8` bytes (unsigned-LE) for length
  - `+` bytes for `utf8` encoded certificate SNI

#### `337` Response payload

- `8` byte (unsigned-LE) - certificate length
- `+` byte - certificate


### TLS - Get Private Key by Index

#### `352` Request payload

- `4` byte (unsigned-LE) - keystore index

#### `353` Response payload

- `8` byte (unsigned-LE) - certificate private key length
- `+` byte - certificate private key


### TLS - Get Private Key by Digest

#### `368` Request payload

- `32` byte - certificate digest

#### `369` Response payload

- `8` byte (unsigned-LE) - certificate private key length
- `+` byte - certificate private key


### TLS - Get Private Key by SNI

#### `384` Request payload

- `8+` byte - certificate SNI
  - `8` bytes (unsigned-LE) for length
  - `+` bytes for `utf8` encoded certificate SNI

#### `385` Response payload

- `8` byte (unsigned-LE) - certificate private key length
- `+` byte - certificate private key


### Ed25519 - Create a New Key from Entropy

#### `528` Request payload

- empty

#### `529` Response payload

- `4` byte (unsigned-LE) - keystore index
- `32` byte - public key


### Ed25519 - Get Public Key by Index

#### `544` Request payload

- `4` byte (unsigned-LE) - keystore index

#### `545` Response payload

- `32` byte - public key


### Ed25519 - Sign by Index

#### `560` Request payload

- `4` byte (unsigned-LE) - keystore index
- `8` byte (unsigned-LE) - message length
- `+` byte - message

#### `561` Response payload

- `64` byte - signature


### Ed25519 - Sign by Public Key

#### `576` Request payload

- `32` byte - public key
- `8` byte (unsigned-LE) - message length
- `+` byte - message

#### `577` Response payload

- `64` byte - signature
