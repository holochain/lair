-- version table to manage upgrade path
CREATE TABLE IF NOT EXISTS lair_db_version (version INTEGER PRIMARY KEY NOT NULL UNIQUE);

-- the main lair keystore table
CREATE TABLE IF NOT EXISTS lair_keystore (
  -- identity pk
  id INTEGER PRIMARY KEY NOT NULL UNIQUE,  --
  -- user-defined tag
  tag TEXT NOT NULL UNIQUE,  --
  -- signature public key for indexing
  -- (null for non-seed entries)
  ed25519_pub_key BLOB NULL UNIQUE,  --
  -- encryption public key for indexing
  -- (null for non-seed entries)
  x25519_pub_key BLOB NULL UNIQUE,  --
  -- msgpack encoded entry data
  data BLOB NOT NULL
);

-- index to speed lookups by tag
CREATE UNIQUE INDEX IF NOT EXISTS lair_keystore_tag_idx ON lair_keystore (tag);

-- index to speed lookups by signature pub key
CREATE UNIQUE INDEX IF NOT EXISTS lair_keystore_ed25519_pub_key_idx ON lair_keystore (ed25519_pub_key);

-- index to speed lookups by encryption pub key
CREATE UNIQUE INDEX IF NOT EXISTS lair_keystore_x25519_pub_key_idx ON lair_keystore (x25519_pub_key);

-- initialize the db version identifier if it is not set
INSERT INTO
  lair_db_version (version)
SELECT
  1
WHERE
  NOT EXISTS(
    SELECT
      1
    FROM
      lair_db_version
    LIMIT
      1
  );
