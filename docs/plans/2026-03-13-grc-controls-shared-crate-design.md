# GRC Controls Shared Crate Architecture

**Date:** 2026-03-13
**Status:** Approved
**Scope:** OCEAN + HTH shared library design

## Problem

OCEAN and HTH are both Rust CLI tools for GRC security assessment. They share the same target platforms (GitHub, Okta, future: AWS/Azure/GCP/K8s), make the same API calls, and produce overlapping result types. Today they duplicate API clients, credential handling, and scanning logic independently.

## Decision

Create a Cargo workspace with 4 shared crates under the `grc-controls-` prefix. Both `ocean` and `hth` binaries consume these crates as library dependencies.

## Architecture

### Workspace Structure

```
grc-controls/
├── Cargo.toml                        # [workspace]
├── grc-controls-models/              # Domain types + evidence normalization
├── grc-controls-apis/                # Platform API clients + credentials
├── grc-controls-observers/           # Passive scanning (all platforms)
├── grc-controls-testers/             # Active control testing (all platforms)
├── ocean/                            # OCEAN binary
└── hth/                              # HTH binary
```

### Dependency Graph

```
grc-controls-models          ← pure types + normalization (no deps)
        ↑
grc-controls-apis            ← platform API clients + credential mgmt
      ↑       ↑
observers    testers          ← siblings, never depend on each other
   ↑    ↑    ↑    ↑
  ocean      hth              ← binaries pick what they need
```

### Crate Responsibilities

#### `grc-controls-models`

Pure domain types and evidence normalization. No external dependencies beyond serde/chrono/uuid.

Contents:
- `ControlResult` — outcome of a single control assessment
- `CheckResult` — outcome of a single check within a control
- `ControlStatus` — Pass / Fail / Skip / Error
- `Evidence` — OCSF-aligned normalized evidence record
- `StatusId` — Effective / Ineffective / Unknown
- `ConfidenceLevel` — PassiveObservation / ActiveTest / etc.
- `Finding`, `Observable`, `Metadata` — evidence substructures
- `Severity` — severity levels and mappings
- Compliance framework mappings (SOC2, NIST, CIS, ISO)
- **Normalization functions** — `ControlResult → Evidence` transformation

This crate is the shared vocabulary. Every other crate speaks these types.

#### `grc-controls-apis`

Authenticated HTTP clients for target platforms and credential management.

Contents:
- `PlatformCredentials` — typed credential struct per platform
- Credential resolution (env vars, config files)
- `GitHubClient` — typed GitHub REST API client
  - Authenticated GET/PUT/DELETE with typed responses
  - Rate limiting, error handling
- `OktaClient` — typed Okta API client
- Future: `AwsClient`, `AzureClient`, `GcpClient`

Depends on: `grc-controls-models` (for typed response models)

#### `grc-controls-observers`

Passive scanning implementations. Each observer reads API/system state and produces `ControlResult`.

Contents:
- `Observer` trait definition + observer registry
- Platform submodules gated by Cargo features:
  - `github/` — branch_protection, dependabot, code_scanning, secret_scanning, repo_security, actions_permissions, workflow_permissions, etc.
  - `okta/` — mfa_policy, password_policy, admin_roles, etc.
  - Future: `aws/`, `azure/`, `gcp/`

Internal organization: one file per observer, platform module handles registration.

Depends on: `grc-controls-apis`, `grc-controls-models`

#### `grc-controls-testers`

Active control testing implementations. Each tester attempts to defeat a control, records a transcript, and cleans up.

Contents:
- `Tester` trait definition + tester registry
- `SafetyClassification` — Observable / Destructive
- `EnvironmentScope` — Production / Staging
- `TestTranscript` — step-by-step recording of test actions
- Cleanup protocol (rollback on success)
- Platform submodules gated by Cargo features:
  - `github/` — branch_bypass, secret_push, etc.
  - `okta/` — password_bypass, mfa_bypass, etc.

Depends on: `grc-controls-apis`, `grc-controls-models`

### What Stays in Each Binary

| Binary | Keeps |
|--------|-------|
| **OCEAN** | `Store` trait (SQLite persistence), CEL evaluation engine, control YAML loader, OCEAN CLI commands (`ocean run`, `ocean report`), evidence persistence and querying |
| **HTH** | Pack YAML loader, jq evaluation engine, `hth scan`/`remediate`/`validate`/`report`/`analyze` CLI commands, ScanReport rendering (JSON/SARIF/CSV/table), remediation workflows |

### Platform Feature Flags

Each observer/tester crate uses Cargo features for platform selection:

```toml
[features]
default = ["github", "okta"]
github = []
okta = []
aws = []
azure = []
gcp = []
```

This allows:
- `hth` to compile with only `github` + `okta`
- `ocean` to compile with all platforms
- Future tools to pick exactly what they need

### Migration Path

Per-platform crate splitting (e.g., `grc-controls-observers-github`) is deferred. Cargo features handle selective compilation. Split only when compile time or dependency divergence makes it necessary.

## Precedent

This architecture follows established patterns in security tooling:

| Tool | Language | Pattern | Analog |
|------|----------|---------|--------|
| RustSec | Rust | `rustsec` library crate + `cargo-audit` CLI | `grc-controls-*` + `ocean`/`hth` |
| Trivy | Go | `pkg/scanner` + `pkg/types` as importable packages | `grc-controls-observers` + `grc-controls-models` |
| Prowler | Python | SDK core + provider modules + CLI/SaaS consumers | Full stack analog |
| Semgrep | OCaml | Shared engine + multiple frontends | Shared crates + two CLIs |

## Key Design Principles

1. **`grc-controls-models` has no external coupling.** It's pure types and transformations. Any Rust project can depend on it.
2. **Observers and testers are siblings, never parent-child.** No circular dependencies.
3. **Evaluation stays tool-specific.** HTH uses jq, OCEAN uses CEL. The shared crates provide facts, not policy.
4. **Evidence normalization is first-class.** The `ControlResult → Evidence` mapping is a core capability of `grc-controls-models`, not an afterthought.
5. **Credential resolution lives with API clients.** The purpose of credentials is to authenticate API calls.
