# OCEAN Go → Rust Refactor Plan
**Version target:** v0.1.0
**Scope:** Full language migration — delete all Go, rewrite in idiomatic Rust

---

## Context

Justin requested a total refactor of the OCEAN codebase from Go to Rust, resetting to v0.1.0. The existing Go codebase is ~60 source files implementing a GRC evidence collection CLI with:
- 9 built-in modules (4 collectors, 5 testers) across AWS/GitHub/Okta/mock
- SQLite storage with 4 tables (evidence, control_status, schedules, schedule_runs — attestations table removed)
- CEL expression evaluation with presets
- Cron scheduler with runner
- REST API server
- Full CLI (13 commands/subcommands)

**NOTE: Cryptographic provenance (DSSE attestation, Ed25519 signing, in-toto format) is intentionally excluded.** That capability lives in Corsair (https://grcorsair.com). OCEAN is the collection + evaluation layer only.

---

## Architectural Decisions

### 1. Single-Crate Structure (not workspace)
For v0.1.0, use a single Cargo crate with both `[lib]` (public SDK) and `[[bin]]` (CLI). Mirrors the Go `pkg/ocean` (library) + `cmd/ocean` (binary) split. Workspace can be introduced later as the project grows.

### 2. Key Rust Dependencies
| Concern | Crate | Replaces |
|---|---|---|
| CLI | `clap 4` (derive) | `cobra` |
| Serialization | `serde` + `serde_json` + `serde_yaml` | `encoding/json` + `yaml.v3` |
| SQLite | `rusqlite 0.31` (bundled) | `modernc.org/sqlite` |
| UUID | `uuid 1` (v4 + serde) | `google/uuid` |
| Datetime | `chrono 0.4` (serde) | `time` stdlib |
| SHA-256 / HMAC | `sha2 0.10` + `hmac` | `crypto/sha256` + `crypto/hmac` |
| Base64 | `base64 0.22` | `encoding/base64` |
| Hex | `hex 0.4` | `encoding/hex` |
| HTTP (sync) | `ureq 2` (json) | `net/http` |
| Logging | `tracing` + `tracing-subscriber` | `rs/zerolog` |
| Errors | `anyhow 1` + `thiserror 1` | `fmt.Errorf` |
| Regex | `regex 1` | `regexp` |
| Cron | `cron 0.12` | `robfig/cron` |
| Async runtime | `tokio 1` (full) | stdlib goroutines |
| REST API | `axum 0.7` | `net/http` |
| CEL | native presets + `cel-interpreter` | `google/cel-go` |
| HMAC | `hmac` + `sha2` | `crypto/hmac` |

**CEL note:** Implement the 3 built-in presets (`all_effective`, `any_effective`, `active_verified`) natively in Rust without a CEL runtime. For arbitrary CEL expressions, use `cel-interpreter` crate. This eliminates the biggest portability risk.

### 3. Sync-First, Async Where Needed
- All CLI commands, modules, storage: sync (no tokio overhead)
- `ocean serve` (REST API): tokio + axum
- Scheduler: `std::thread` with `std::sync` channels

### 4. Module Registration
Use a function-based registration identical to Go pattern:
```rust
pub fn register_all(registry: &mut Registry) {
    registry.register_collector(Box::new(MockCollector::new()));
    // ...
}
```

---

## Directory Structure

```
ocean/
├── Cargo.toml              ← workspace + [lib] + [[bin]] + all deps
├── Cargo.lock
├── src/
│   ├── main.rs             ← CLI entry point (delegates to cli::run())
│   ├── lib.rs              ← Public SDK re-exports (Client, Evidence, etc.)
│   ├── cli/                ← CLI commands
│   │   ├── mod.rs
│   │   ├── collect.rs
│   │   ├── test_cmd.rs
│   │   ├── verify.rs
│   │   ├── evaluate.rs
│   │   ├── history.rs
│   │   ├── schedule.rs
│   │   ├── modules.rs
│   │   ├── report.rs
│   │   ├── serve.rs
│   │   └── output.rs
│   ├── evidence/           ← Evidence types
│   │   ├── mod.rs          ← Evidence struct, enums (StatusId, ConfidenceLevel)
│   │   ├── transcript.rs   ← TestTranscript, TranscriptRecorder
│   │   ├── redaction.rs    ← RedactionConfig
│   │   └── validator.rs    ← schema validation
│   ├── module/             ← Module traits + registry
│   │   ├── mod.rs          ← Module, CredentialReq, SafetyClassification, etc.
│   │   ├── collector.rs    ← Collector trait
│   │   ├── tester.rs       ← Tester trait
│   │   ├── registry.rs     ← Registry (RwLock<HashMap>)
│   │   ├── executor.rs     ← Executor (collect/test with config)
│   │   ├── safety.rs       ← Authorizer trait, AutoAuthorizer
│   │   └── validation.rs   ← validate module metadata
│   ├── storage/
│   │   ├── mod.rs          ← Store trait, EvidenceQuery
│   │   └── sqlite.rs       ← SqliteStore impl
│   ├── eval/
│   │   ├── mod.rs
│   │   ├── engine.rs       ← CEL engine wrapper (native presets first)
│   │   └── presets.rs      ← all_effective, any_effective, active_verified
│   ├── control/
│   │   ├── mod.rs
│   │   ├── definition.rs   ← Control, FrameworkMapping, EvaluationLogic
│   │   ├── evaluator.rs    ← ControlStatus, UptimeResult
│   │   ├── composite.rs    ← ComponentResult
│   │   └── framework.rs    ← Framework, FrameworkControl
│   ├── scheduler/
│   │   ├── mod.rs
│   │   ├── types.rs        ← Schedule, ScheduleRun, ModuleRunResult
│   │   ├── cron.rs         ← Scheduler (cron entry management)
│   │   └── runner.rs       ← Runner (executes scheduled module runs)
│   ├── secrets/
│   │   ├── mod.rs          ← Provider trait
│   │   ├── env.rs          ← EnvProvider
│   │   ├── aws.rs          ← AwsSecretsProvider (raw HTTP + SigV4)
│   │   └── vault.rs        ← VaultProvider
│   ├── api/
│   │   ├── mod.rs
│   │   ├── server.rs       ← axum Router + Server struct
│   │   └── handlers.rs     ← all HTTP handlers
│   ├── config/
│   │   ├── mod.rs          ← Config, ServerConfig
│   │   └── loader.rs       ← load from file / env / defaults
│   └── modules/            ← Built-in modules
│       ├── mod.rs          ← register_all_collectors(), register_all_testers()
│       ├── collectors/
│       │   ├── mod.rs
│       │   ├── mock.rs           ← MockCollector, MockNetworkCollector
│       │   ├── aws/mod.rs        ← IamCollector (SigV4)
│       │   ├── github/mod.rs     ← BranchProtectionCollector
│       │   └── okta/mod.rs       ← MfaPolicyCollector
│       └── testers/
│           ├── mod.rs
│           ├── mock.rs           ← MockTester
│           ├── aws/mod.rs        ← S3PublicAccessTester
│           ├── github/mod.rs     ← SecretPushTester
│           └── okta/mod.rs       ← MfaBypassTester
├── tests/
│   ├── fixtures/           ← kept as-is (JSON/YAML test data)
│   └── integration.rs      ← replaces tests/integration/pipeline_test.go
├── controls/               ← kept as-is (YAML control definitions)
├── schemas/                ← kept as-is (JSON schemas)
├── docs/                   ← kept as-is
├── Makefile                ← rewritten for Cargo commands
├── .github/workflows/ci.yml ← rewritten for Rust/Cargo
├── .gitignore              ← updated for Rust
└── README.md               ← updated
```

---

## Files to Delete (all Go artifacts)

```
cmd/                        ← entire directory
internal/                   ← entire directory
modules/                    ← entire directory (Go source)
pkg/                        ← entire directory
go.mod
go.sum
.golangci.yml
```

---

## Cargo.toml Key Structure

```toml
[package]
name = "ocean"
version = "0.1.0"
edition = "2021"
description = "Open Control Evidence Assessment Normalizer"
license = "Apache-2.0"

[lib]
name = "ocean"
path = "src/lib.rs"

[[bin]]
name = "ocean"
path = "src/main.rs"

[dependencies]
# (all deps listed in Architectural Decisions above)
```

---

## Implementation Sequence (Phased)

### Phase 1 — Foundation Types (src/evidence/, src/module/)
- Evidence struct with all fields (serde_json::Value for RawData)
- All enums: SafetyClassification, EnvironmentScope, ConfidenceLevel, StatusId
- Module, Collector, Tester traits
- Registry with RwLock<HashMap>

### Phase 2 — Storage (src/storage/)
- Store trait (identical methods to Go interface)
- SqliteStore with bundled rusqlite
- Same 5 tables, same JSON blob pattern for complex fields
- Migration runs on Open()

### Phase 3 — Eval + Control (src/eval/, src/control/)
- Native presets (pure Rust, no external CEL runtime)
- cel-interpreter for arbitrary expressions
- Control YAML loader, ControlStatus, UptimeResult
- Framework YAML loader

### Phase 4 — Modules (src/modules/)
- All 4 collectors + 5 testers
- Keep the same raw HTTP + SigV4 pattern (ureq instead of net/http)
- register_all() functions

### Phase 5 — CLI (src/cli/)
- 13 commands with clap derive (provenance/keys commands removed)
- Same flag names and behavior as Go version
- output.rs for JSON/YAML/table formatting

### Phase 6 — Scheduler + API + Config (src/scheduler/, src/api/, src/config/)
- Cron scheduler with std::thread
- axum REST API (9 endpoints — attestation endpoints removed)
- Config loading from YAML/env

### Phase 7 — Infrastructure
- Makefile rewrite (cargo build/test/clippy targets + cross-compile)
- CI/CD rewrite for Cargo
- .gitignore update
- README update (v0.1.0)
- Delete all .go files + go.mod/go.sum

---

## Version Handling

In `src/cli/mod.rs`, version constant:
```rust
pub const VERSION: &str = env!("CARGO_PKG_VERSION"); // → "0.1.0"
```

Build metadata (replaces Go ldflags):
```rust
pub const BUILD_TIME: &str = env!("VERGEN_BUILD_TIMESTAMP"); // via vergen crate
```

Or simpler for v0.1.0: hardcode build time via `build.rs`.

---

## Verification

After implementation:
1. `cargo build` — compiles without errors
2. `cargo test` — all unit tests pass
3. `./target/debug/ocean version` → `OCEAN v0.1.0`
4. `./target/debug/ocean modules list` → lists all 9 modules
5. `./target/debug/ocean collect mock.test` → produces evidence in SQLite
6. `cargo clippy -- -D warnings` — no warnings
