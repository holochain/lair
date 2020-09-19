cargo fmt -- --check
cargo clippy
cargo install --debug -f --path crates/lair_keystore
cargo test
