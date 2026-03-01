# OCEAN Go → Rust Refactor Plan
**Version target:** v0.1.0
**Scope:** Full language migration — delete all Go, rewrite in idiomatic Rust

---

## Context

Justin requested a total refactor of the OCEAN codebase from Go to Rust, resetting to v0.1.0. The existing Go codebase is ~60 source files implementing a GRC evidence collection CLI with:
- 9 built-in modules (4 observers, 5 testers) across AWS/GitHub/Okta/mock
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
    registry.register_observer(Box::new(MockObserver::new()));
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
│   │   ├── observe.rs
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
│   │   ├── observer.rs    ← Observer trait
│   │   ├── tester.rs       ← Tester trait
│   │   ├── registry.rs     ← Registry (RwLock<HashMap>)
│   │   ├── executor.rs     ← Executor (observe/test with config)
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
│       ├── mod.rs          ← register_all_observers(), register_all_testers()
│       ├── observers/
│       │   ├── mod.rs
│       │   ├── mock.rs           ← MockObserver, MockNetworkObserver
│       │   ├── aws/mod.rs        ← IamObserver (SigV4)
│       │   ├── github/mod.rs     ← BranchProtectionObserver
│       │   └── okta/mod.rs       ← MfaPolicyObserver
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
- Module, Observer, Tester traits
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
- All 4 observers + 5 testers
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
5. `./target/debug/ocean observe mock.test` → produces evidence in SQLite
6. `cargo clippy -- -D warnings` — no warnings

---

---

# CLI UX Redesign — Target + Control Path Paradigm

**Status:** DONE — committed da8728b
**Scope:** New `evaluate -t TARGET -c PATH` and `test -t TARGET -c PATH` commands with unified pipeline

---

## Context

The current `ocean evaluate <control>` command only reads stored evidence — it doesn't run observers or testers. Users must manually run `ocean observe <module>` and `ocean test <module>` first. This is unintuitive. The new paradigm makes `ocean evaluate` a single-command pipeline: specify a target integration and a control domain path, and OCEAN automatically collects evidence, runs active tests, evaluates CEL, and outputs a clean results table.

**New UX examples:**
```
ocean evaluate -t okta -c iam                       # all IAM controls for Okta
ocean evaluate -t okta -c iam.mfa                   # MFA-domain controls for Okta
ocean evaluate -t okta -c iam.mfa.phishing_resistant # exact control, Okta only
ocean evaluate -t * -c iam.mfa                      # MFA controls across ALL configured targets
ocean test -t okta -c iam.mfa.phishing_resistant    # active testers only
```

**Backward compatibility:** `ocean observe <module>`, `ocean test <module>`, and `ocean evaluate <control>` (legacy positional) remain fully functional.

---

## Architectural Decisions

### 1. Control Path Resolution (no YAML changes needed)
Control IDs already use dot notation (`iam.mfa_enforcement`, `iam.timely_termination`). Path matching is prefix-based:
- `-c iam` → all controls where `id.starts_with("iam.")`
- `-c iam.mfa` → all controls where `id.starts_with("iam.mfa")`
- `-c iam.mfa.phishing_resistant` → exact match `id == "iam.mfa.phishing_resistant"`

Implementation: `fn resolve_controls(controls_dir: &str, path: &str) -> Vec<Control>` globs `controls/*.yaml`, deserializes, filters by prefix.

### 2. Target → Module Resolution (convention-based, no YAML changes needed)
Module IDs already follow `source_system.module_name` format. Target name = source system prefix:
- `-t okta` → only run modules where `module_id.starts_with("okta.")`
- `-t aws` → only run modules where `module_id.starts_with("aws.")`
- `-t *` → run ALL modules listed in the control (let each module handle its own credential check)

The existing `observers:` and `testers:` fields in control YAML need to be **parsed** (currently they are metadata-only / ignored by the Control struct). We add `observers: Vec<ModuleRef>` and `testers: Vec<ModuleRef>` to the `Control` struct.

### 3. Control Struct Extension
Add to `src/control/definition.rs`:
```rust
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ModuleRef {
    pub module_id: String,
    #[serde(default = "default_true")]
    pub required: bool,
}

// Add to Control:
#[serde(default)]
pub observers: Vec<ModuleRef>,
#[serde(default)]
pub testers: Vec<ModuleRef>,
```
`#[serde(default)]` ensures existing control YAMLs without these fields still parse fine.

### 4. CLI Flag Design

**Flag conflict:** The existing `Test` variant has `#[arg(long, default_value = "production")] target: String` for environment scope (production/staging/isolated). This conflicts with the new `-t/--target` for integration name. Resolution: rename the existing `--target` env-scope flag to `--env` on the `Test` variant. This is a minor breaking change on an obscure flag.

Extend the existing `Evaluate` and `Test` clap variants with optional `-t`/`-c` flags. `control: String` becomes `control: Option<String>` on Evaluate so it's optional when using the new flags:

```rust
Evaluate {
    /// Legacy: evaluate stored evidence for a specific control ID
    control: Option<String>,
    /// Target integration (okta, aws, github, or * for all configured)
    #[arg(short = 't', long = "target")]
    target: Option<String>,
    /// Control path (iam, iam.mfa, iam.mfa.phishing_resistant)
    #[arg(short = 'c', long = "control-path")]
    control_path: Option<String>,
    // existing flags preserved:
    #[arg(long)]
    cel: Option<String>,
    #[arg(long, default_value = "controls")]
    controls_dir: String,
}

Test {
    module: Option<String>,                       // was required, now optional
    #[arg(short = 't', long = "target")]
    target: Option<String>,                       // new: integration name or *
    #[arg(short = 'c', long = "control-path")]
    control_path: Option<String>,                 // new: control domain path
    #[arg(long, default_value = "production")]
    env: String,                                  // was `--target`, renamed to `--env`
    #[arg(long)]
    no_store: bool,
}
```

Mode dispatch in `cmd_evaluate()` / `cmd_test()`:
- `target` or `control_path` present → new pipeline mode → `cmd_evaluate_path()` / `cmd_test_path()`
- `control`/`module` positional present → legacy mode (existing behavior preserved)
- Neither → error with helpful "use -t TARGET -c PATH or specify a module/control ID" message

### 5. Unified Pipeline (`cmd_evaluate_path`)
```
1. resolve_controls(controls_dir, control_path) → Vec<Control>
   Error if none found.

2. For each control:
   a. Filter observers: control.observers where target matches module_id prefix
   b. Filter testers:   control.testers   where target matches module_id prefix
   c. Run each observer via Executor (same as existing cmd_collect)
      → observe evidence, optionally store in SQLite
   d. Run each tester via Executor (same as existing cmd_test)
      → observe test evidence, optionally store
   e. Query stored evidence for control_id, run evaluate_control()
   f. Observe EvaluationResult { control, module_runs, status }

3. print_evaluation_table(results, format)
```

### 6. Table Output Format
```
Control                       Target  Status     Confidence  Framework
─────────────────────────────────────────────────────────────────────────
iam.mfa_enforcement           okta    EFFECTIVE  HIGH        SOC2 CC6.1
  ↳ [observe] okta.mfa_policy                   OK
  ↳ [observe] okta.mfa_enrollment_population    OK
  ↳ [test]    okta.mfa_bypass                   PASS
  ↳ [test]    okta.pr_mfa_downgrade             PASS

iam.mfa_phishing_resistant    okta    EFFECTIVE  HIGH        SOC2 CC6.6
  ↳ [observe] okta.mfa_policy                   OK
  ↳ [test]    okta.pr_mfa_downgrade             PASS
```

Findings detail (shown for INEFFECTIVE/FINDING status controls):
```
FINDINGS for iam.access_review:
  • sla_breaches: 3 (threshold: 0)
  • oldest_open_revocation_days: 19
```

`print_evaluation_table()` goes in `src/cli/output.rs`.

### 7. `test -t TARGET -c PATH` (testers-only)
Same as evaluate pipeline but skips CEL evaluation step and observers step — runs only active testers for the matched control+target pair. Useful for quick active verification without full collection pass.

---

## Files to Modify

| File | Change |
|------|--------|
| `src/control/definition.rs` | Add `ModuleRef` struct + `observers`/`testers` fields to `Control` |
| `src/cli/mod.rs` | Extend `Evaluate` + `Test` variants with `-t`/`-c` flags; add `cmd_evaluate_path()`, `cmd_test_path()`, `resolve_controls()`, `target_matches_module()` |
| `src/cli/output.rs` | Add `print_evaluation_table()` |

No changes to control YAML files, `Cargo.toml`, or storage layer.

---

## New Functions

```rust
// src/cli/mod.rs
fn resolve_controls(controls_dir: &str, path: &str) -> anyhow::Result<Vec<Control>>
fn target_matches_module(target: &str, module_id: &str) -> bool
fn cmd_evaluate_path(target: &str, path: &str, controls_dir: &str, db: &str, format: &str) -> anyhow::Result<()>
fn cmd_test_path(target: &str, path: &str, controls_dir: &str, format: &str) -> anyhow::Result<()>

// src/cli/output.rs
pub fn print_evaluation_table<W: Write>(w: &mut W, results: &[EvaluationResult]) -> anyhow::Result<()>

// src/control/definition.rs
pub struct ModuleRef { pub module_id: String, pub required: bool }
```

---

## Verification

After implementation:
1. `cargo build` — no errors
2. `cargo test` — all tests pass (existing tests unaffected)
3. `ocean evaluate mock.test` — legacy mode still works
4. `ocean observe mock.test` + `ocean test mock.safety_test` — primitives unchanged
5. `ocean evaluate -t mock -c iam` — resolves controls with mock modules, runs pipeline, outputs table
6. `ocean test -t mock -c iam` — runs only mock testers, shows pass/fail
7. `cargo clippy -- -D warnings` — no warnings
