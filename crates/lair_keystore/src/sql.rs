//! sql files

pub(crate) const SCHEMA: &str = include_str!("./sql/schema.sql");
pub(crate) const INSERT: &str = include_str!("./sql/insert.sql");
pub(crate) const INSERT_SEED: &str = include_str!("./sql/insert_seed.sql");
pub(crate) const SELECT_ALL: &str = include_str!("./sql/select_all.sql");
pub(crate) const SELECT_BY_TAG: &str = include_str!("./sql/select_by_tag.sql");
pub(crate) const SELECT_BY_SIGN_PK: &str =
    include_str!("./sql/select_by_sign_pk.sql");
