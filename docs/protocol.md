
# Protocol
This section outlines the communication format and describes the payload byte order for each wire type.


## High-level overview of framing
The essential blocks of every message have 16 bytes of header information followed by the payload
bytes.

- Headers (16 bytes)
  - Message length (4 bytes - LE)
  - Wire type (4 bytes - LE)
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
  - `0xff` - the message is initiated by Lair
  - `0x00` - the request is for Lair
  - `0x??` - undefined / reserved
- byte 2
  - `0x??` - undefined / reserved
- byte 3
  - `0x00` - the message is unclassified
  - `0x01` - the message is related to TLS
  - `0x02` - the message is related to Ed25519
  - `0x??` - undefined / reserved
- byte 4
  - `0x*0` - request message
  - `0x*1` - response message
  - `0x*?` - undefined / reserved

### Message ID (8 bytes)
An identifier used to match a response to the intial request.

### Payload (0+ bytes)
Can be any number of bytes.  The payload format is determined by the wire type.


## Wire Types

### Unlock Passphrase

#### `0xff000010` Request payload

- empty

#### `0xff000011` Response payload

- `8+` byte - passphrase (string)
  - `8` bytes (LE) for length
  - `+` bytes for `utf8` encoded passphrase

### Get Last Entry

#### `0x00000010` Request payload

- empty

#### `0x00000011` Response payload

- `4` byte (LE) - last keystore index

### Get Entry Type

#### `0x00000020` Request payload

- `4` byte (LE) - keystore index

#### `0x00000021` Response payload

- `4` byte (LE) - entry type
  - `0x00000000` - Invalid
  - `0x00000100` - TLS Certificate
  - `0x00000200` - Ed25519

### Get Server Info

#### `0x00000030` Request payload

- empty

#### `0x00000031` Response payload

- `8+` byte - server name
  - `8` bytes (LE) for length
  - `+` bytes for `utf8` encoded server name
- `8+` byte - server version
  - `8` bytes (LE) for length
  - `+` bytes for `utf8` encoded server version

### TLS - Create Self-signed Certificate from Entropy

#### `0x00000110` Request payload

- `4` byte (LE) - TLS certificate algorithm
  - `0x00000200` - Ed25519
  - `0x00000201` - EcDSA P-256
  - `0x00000202` - EcDSA P-384

#### `0x00000111` Response payload

- `4` byte (LE) - keystore index
- `8+` byte - certificate SNI
  - `8` bytes (LE) for length
  - `+` bytes for `utf8` encoded certificate SNI
- `32` byte - certificate digest

### TLS - Get Certificate

#### `0x00000120` Request payload

- `4` byte (LE) - keystore index

#### `0x00000121` Response payload

- `8+` byte - certificate SNI
  - `8` bytes (LE) for length
  - `+` bytes for `utf8` encoded certificate SNI
- `32` byte - certificate digest


### TLS - Get Certificate by Index

#### `0x00000130` Request payload

- `4` byte (LE) - keystore index

#### `0x00000131` Response payload

- `8` byte (LE) - certificate length
- `+` byte - certificate


### TLS - Get Certificate by Digest

#### `0x00000140` Request payload

- `32` byte - certificate digest

#### `0x00000141` Response payload

- `8` byte (LE) - certificate length
- `+` byte - certificate


### TLS - Get Certificate by SNI

#### `0x00000150` Request payload

- `8+` byte - certificate SNI
  - `8` bytes (LE) for length
  - `+` bytes for `utf8` encoded certificate SNI

#### `0x00000151` Response payload

- `8` byte (LE) - certificate length
- `+` byte - certificate


### TLS - Get Private Key by Index

#### `0x00000160` Request payload

- `4` byte (LE) - keystore index

#### `0x00000161` Response payload

- `8` byte (LE) - certificate private key length
- `+` byte - certificate private key


### TLS - Get Private Key by Digest

#### `0x00000170` Request payload

- `32` byte - certificate digest

#### `0x00000171` Response payload

- `8` byte (LE) - certificate private key length
- `+` byte - certificate private key


### TLS - Get Private Key by SNI

#### `0x00000180` Request payload

- `8+` byte - certificate SNI
  - `8` bytes (LE) for length
  - `+` bytes for `utf8` encoded certificate SNI

#### `0x00000181` Response payload

- `8` byte (LE) - certificate private key length
- `+` byte - certificate private key


### Ed25519 - Create a New Key from Entropy

#### `0x00000210` Request payload

- empty

#### `0x00000211` Response payload

- `4` byte (LE) - keystore index
- `32` byte - public key


### Ed25519 - Get Public Key by Index

#### `0x00000220` Request payload

- `4` byte (LE) - keystore index

#### `0x00000221` Response payload

- `32` byte - public key


### Ed25519 - Sign by Index

#### `0x00000230` Request payload

- `4` byte (LE) - keystore index
- `8` byte (LE) - message length
- `+` byte - message

#### `0x00000231` Response payload

- `64` byte - signature


### Ed25519 - Sign by Public Key

#### `0x00000230` Request payload

- `32` byte - public key
- `8` byte (LE) - message length
- `+` byte - message

#### `0x00000231` Response payload

- `64` byte - signature
