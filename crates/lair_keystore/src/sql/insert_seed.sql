-- insert entry into store with additional seed indexes
INSERT INTO
  lair_keystore (
    tag,
    ed25519_pub_key,
    x25519_pub_key,
    data
  )
VALUES
  (?1, ?2, ?3, ?4);
