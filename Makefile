# Lair Makefile

.PHONY: all publish test static docs tools tool_rust tool_fmt

SHELL = /usr/bin/env sh

ifeq ($(OS),Windows_NT)
	FEATURES = --no-default-features --features=rusqlite-bundled
else
	FEATURES = --no-default-features --features=rusqlite-bundled-sqlcipher-vendored-openssl
endif

all: static test

publish:
	@case "$(crate)" in \
		hc_seed_bundle) \
			export MANIFEST="./crates/hc_seed_bundle/Cargo.toml"; \
			;; \
		lair_keystore_api) \
			export MANIFEST="./crates/lair_keystore_api/Cargo.toml"; \
			;; \
		lair_keystore) \
			export MANIFEST="./crates/lair_keystore/Cargo.toml"; \
			;; \
		*) \
			echo "USAGE: make publish crate=hc_seed_bundle"; \
			echo "USAGE: make publish crate=lair_keystore_api"; \
			echo "USAGE: make publish crate=lair_keystore"; \
			exit 1; \
			;; \
	esac; \
	export VER="v$$(grep version $${MANIFEST} | head -1 | cut -d ' ' -f 3 | cut -d \" -f 2)"; \
	echo "publish $(crate) $${MANIFEST} $${VER}"; \
	git diff --exit-code; \
	cargo publish --manifest-path $${MANIFEST}; \
	git tag -a "$(crate)-$${VER}" -m "$(crate)-$${VER}"; \
	git push --tags;

test: tools
	RUST_BACKTRACE=1 cargo build $(FEATURES) --all-targets
	RUST_BACKTRACE=1 cargo test $(FEATURES) -- --test-threads 1

release: tools
	RUST_BACKTRACE=1 cargo build $(FEATURES) --release --all-targets

static: tools
	cargo fmt -- --check
	cargo clippy $(FEATURES) -- -Dwarnings

tools: tool_rust tool_fmt tool_clippy

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
