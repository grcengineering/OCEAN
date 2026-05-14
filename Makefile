# OCEAN — Open Control Evidence Acquisition Normalizer
# Rust Makefile (v0.1.0)

BINARY = ocean

.PHONY: build release test test-verbose clippy fmt fmt-check \
        coverage coverage-html clean install check \
        test-unit test-integration test-e2e test-all coverage-check

# ---------------------------------------------------------------------------
# cargo-llvm-cov: auto-detect LLVM tool paths on Windows MSVC
# On Linux the tools are on PATH automatically; on Windows MSVC we must
# point cargo-llvm-cov at the rustup-managed binaries explicitly.
# ---------------------------------------------------------------------------
ifeq ($(OS),Windows_NT)
  RUSTUP_HOME    := $(shell rustup show home 2>/dev/null | sed 's|\\\\|/|g')
  ACTIVE_TC      := $(shell rustup show active-toolchain 2>/dev/null | cut -d' ' -f1)
  HOST_TRIPLE    := $(shell rustup show host 2>/dev/null)
  LLVM_BIN       := $(RUSTUP_HOME)/toolchains/$(ACTIVE_TC)/lib/rustlib/$(HOST_TRIPLE)/bin
  export LLVM_COV      ?= $(LLVM_BIN)/llvm-cov.exe
  export LLVM_PROFDATA ?= $(LLVM_BIN)/llvm-profdata.exe
endif

# Regex pattern of files to exclude from coverage.
# src/main.rs is the CLI entry point — not meaningfully unit-testable.
# src/secrets/* providers (Vault, AWS Secrets Manager) require live services.
STUB_REGEX := src/(main|secrets|dashboard/(ui|terminal)|api/server)

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
		--ignore-filename-regex '$(STUB_REGEX)'

coverage-html:
	cargo llvm-cov \
		--ignore-filename-regex '$(STUB_REGEX)' \
		--html --open

# Alternative: cargo-tarpaulin (Linux only — matches CI)
coverage-tarpaulin:
	cargo tarpaulin \
		--all-features \
		--timeout 120 \
		--exclude-files 'src/secrets/*' \
		--exclude-files 'src/main.rs'

# ---------------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------------

clean:
	cargo clean

# ---------------------------------------------------------------------------
# Targeted test tiers
# ---------------------------------------------------------------------------

test-unit:
	cargo test --lib --bins

test-integration:
	cargo test --test integration

test-e2e:
	cargo build --release
	cargo test --test e2e

test-all: test-unit test-integration test-e2e

coverage-check:
	cargo llvm-cov \
		--ignore-filename-regex '$(STUB_REGEX)' \
		--fail-under-lines 80
