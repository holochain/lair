-- insert entry into store WITHOUT additional seed indexes
INSERT
  OR ROLLBACK INTO lair_keystore (tag, data)
VALUES
  (?1, ?2);
