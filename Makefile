# OCEAN — Open Control Evidence Acquisition Normalizer
# Rust Makefile (v0.1.0)

BINARY = ocean

.PHONY: build release test test-verbose clippy fmt fmt-check \
        coverage coverage-html clean install check

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

build:
	cargo build

release:
	cargo build --release

install:
	cargo install --path .

# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------

test:
	cargo test

test-verbose:
	cargo test -- --nocapture

# ---------------------------------------------------------------------------
# Lint
# ---------------------------------------------------------------------------

clippy:
	cargo clippy -- -D warnings

fmt:
	cargo fmt

fmt-check:
	cargo fmt --check

check:
	cargo check

# ---------------------------------------------------------------------------
# Coverage (requires cargo-llvm-cov: cargo install cargo-llvm-cov)
# ---------------------------------------------------------------------------

coverage:
	cargo llvm-cov \
		--all-features \
		--ignore-filename-regex 'src/(api|config|eval|secrets|modules|main)' \
		--ignore-filename-regex 'src/scheduler/(cron|runner)' \
		--ignore-filename-regex 'src/control/(composite|evaluator|framework)' \
		--workspace

coverage-html:
	cargo llvm-cov \
		--all-features \
		--ignore-filename-regex 'src/(api|config|eval|secrets|modules|main)' \
		--ignore-filename-regex 'src/scheduler/(cron|runner)' \
		--ignore-filename-regex 'src/control/(composite|evaluator|framework)' \
		--workspace \
		--open

# Alternative: cargo-tarpaulin (Linux only — matches CI)
coverage-tarpaulin:
	cargo tarpaulin \
		--all-features \
		--timeout 120 \
		--exclude-files 'src/api/*' \
		--exclude-files 'src/config/*' \
		--exclude-files 'src/eval/*' \
		--exclude-files 'src/secrets/*' \
		--exclude-files 'src/modules/*' \
		--exclude-files 'src/scheduler/cron.rs' \
		--exclude-files 'src/scheduler/runner.rs' \
		--exclude-files 'src/control/composite.rs' \
		--exclude-files 'src/control/evaluator.rs' \
		--exclude-files 'src/control/framework.rs' \
		--exclude-files 'src/main.rs'

# ---------------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------------

clean:
	cargo clean
