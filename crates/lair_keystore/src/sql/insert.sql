-- insert entry into store WITHOUT additional seed indexes
INSERT INTO
  lair_keystore (tag, data)
VALUES
  (?1, ?2);
