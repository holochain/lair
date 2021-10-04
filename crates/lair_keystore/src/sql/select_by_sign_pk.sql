SELECT
  data
FROM
  lair_keystore
WHERE
  ed25519_pub_key = ?1;
