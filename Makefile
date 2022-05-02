# Lair Makefile

.PHONY: all test static docs tools tool_rust tool_fmt tool_readme

SHELL = /usr/bin/env sh

all: test

test: static tools
	RUST_BACKTRACE=1 cargo build --all-features --all-targets
	RUST_BACKTRACE=1 cargo test --all-features -- --test-threads 1

static: docs tools
	cargo fmt -- --check
	cargo clippy

docs: tools
	printf '### `lair-keystore --help`\n```text\n' > crates/lair_keystore/src/docs/help.md
	cargo run --manifest-path=crates/lair_keystore/Cargo.toml -- --help >> crates/lair_keystore/src/docs/help.md
	printf '\n```\n' >> crates/lair_keystore/src/docs/help.md
	printf '### `lair-keystore init --help`\n```text\n' > crates/lair_keystore/src/docs/init-help.md
	cargo run --manifest-path=crates/lair_keystore/Cargo.toml -- init --help >> crates/lair_keystore/src/docs/init-help.md
	printf '\n```\n' >> crates/lair_keystore/src/docs/init-help.md
	printf '### `lair-keystore url --help`\n```text\n' > crates/lair_keystore/src/docs/url-help.md
	cargo run --manifest-path=crates/lair_keystore/Cargo.toml -- url --help >> crates/lair_keystore/src/docs/url-help.md
	printf '\n```\n' >> crates/lair_keystore/src/docs/url-help.md
	printf '### `lair-keystore import-seed --help`\n```text\n' > crates/lair_keystore/src/docs/import-seed-help.md
	cargo run --manifest-path=crates/lair_keystore/Cargo.toml -- import-seed --help >> crates/lair_keystore/src/docs/import-seed-help.md
	printf '\n```\n' >> crates/lair_keystore/src/docs/import-seed-help.md
	printf '### `lair-keystore server --help`\n```text\n' > crates/lair_keystore/src/docs/server-help.md
	cargo run --manifest-path=crates/lair_keystore/Cargo.toml -- server --help >> crates/lair_keystore/src/docs/server-help.md
	printf '\n```\n' >> crates/lair_keystore/src/docs/server-help.md
	cargo readme -r crates/hc_seed_bundle -o README.md
	cargo readme -r crates/lair_keystore_api -o README.md
	cargo readme -r crates/lair_keystore -o README.md
	printf '\n' >> crates/lair_keystore/README.md
	cat crates/lair_keystore/src/docs/help.md >> crates/lair_keystore/README.md
	cat crates/lair_keystore/src/docs/init-help.md >> crates/lair_keystore/README.md
	cat crates/lair_keystore/src/docs/url-help.md >> crates/lair_keystore/README.md
	cat crates/lair_keystore/src/docs/import-seed-help.md >> crates/lair_keystore/README.md
	cat crates/lair_keystore/src/docs/server-help.md >> crates/lair_keystore/README.md
	cp crates/lair_keystore/README.md README.md
	@if [ "${CI}x" != "x" ]; then git diff --exit-code; fi

tools: tool_rust tool_fmt tool_clippy tool_readme

tool_rust:
	@if rustup --version >/dev/null 2>&1; then \
		echo "# Makefile # found rustup, setting override stable"; \
		rustup override set stable; \
	else \
		echo "# Makefile # rustup not found, hopefully we're on stable"; \
	fi;

tool_fmt: tool_rust
	@if ! (cargo fmt --version); \
	then \
		if rustup --version >/dev/null 2>&1; then \
			echo "# Makefile # installing rustfmt with rustup"; \
			rustup component add rustfmt; \
		else \
			echo "# Makefile # rustup not found, cannot install rustfmt"; \
			exit 1; \
		fi; \
	else \
		echo "# Makefile # rustfmt ok"; \
	fi;

tool_clippy: tool_rust
	@if ! (cargo clippy --version); \
	then \
		if rustup --version >/dev/null 2>&1; then \
			echo "# Makefile # installing clippy with rustup"; \
			rustup component add clippy; \
		else \
			echo "# Makefile # rustup not found, cannot install clippy"; \
			exit 1; \
		fi; \
	else \
		echo "# Makefile # clippy ok"; \
	fi;

tool_readme: tool_rust
	@if ! (cargo readme --version); \
	then \
		cargo install cargo-readme; \
	else \
		echo "# Makefile # readme ok"; \
	fi;
