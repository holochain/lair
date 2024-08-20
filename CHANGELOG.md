## 0.5.0

- breaking sqlcipher update for ios compatibility

## 0.4.1

- Add a way to migrate unencrypted databases to encrypted by providing an environment variable `LAIR_MIGRATE_UNENCRYPTED="true"`, Lair will detect databases which can't be opened and attempt migration. #121

# 0.4.0

- pin serde and rmp-serde #119

## 0.0.2
