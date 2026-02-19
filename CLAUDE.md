# OCEAN Project Context

This file provides context for Claude Code sessions working on OCEAN (Open Control Evidence Acquisition Normalizer).

## Project Overview

OCEAN is the **"Metasploit for GRC"** — an open-source CLI tool and Go library for evidence acquisition, active control testing, and normalization powering continuous compliance monitoring. It is the backend for a **"StatusPage for Compliance"** — radically transparent dashboards showing historical control operating effectiveness metrics.

OCEAN operates across four pillars:
1. **Passive Control Monitoring** — Query system APIs to observe configuration state, store as evidence
2. **Active Control Testing** — Attempt what controls should prevent (like Atomic Red Team for GRC)
3. **Flexible Evaluation Logic** — CEL expressions + YAML presets for user-defined compliance conditions
4. **Cryptographic Provenance** — in-toto DSSE attestations proving the full chain from data to verdict

OCEAN is **NOT** a full GRC platform. It is the specialized evidence and verification layer that GRC platforms consume.

## Key Design Principles (from Constitution v2.0.0)

1. **Evidence-First Architecture**: All data has provenance, is immutable, reproducible, with confidence levels
2. **OCSF-Inspired Schema**: Hierarchical taxonomy (Domains → Classes → Attributes)
3. **Metasploit-Style Extensibility**: Dual-mode modules — Collectors (passive) + Testers (active)
4. **Cross-Platform Portability**: Single Go binary, zero dependencies
5. **Control-Centric Organization**: CEL evaluation logic, composite controls, framework mappings
6. **Continuous Monitoring Native**: Scheduling, time-series, uptime calculations
7. **Radical Transparency**: Show failures alongside successes
8. **Security & Privacy by Design**: Mandatory signing, test authorization, no credential storage
9. **Active Control Verification**: Safety classifications (safe/observable/reversible/destructive), pre-flight validation, cleanup, test transcripts
10. **Cryptographic Provenance Chain**: Two-layer attestation (Collection + Evaluation), in-toto DSSE, content-addressable references

## Spec-Kit Artifacts Location

All specification work is in `.specify/`:

```
.specify/
├── memory/
│   └── constitution.md      # Core principles v2.0.0 (COMPLETE)
├── specs/
│   └── ocean-core/
│       ├── spec.md          # Full specification v2.0.0 (COMPLETE - 11 user stories)
│       ├── checklists/
│       │   └── requirements.md  # Spec quality validation (COMPLETE)
│       ├── plan.md          # Implementation plan v2.0.0 (COMPLETE - 8 phases)
│       ├── data-model.md    # Entity definitions (COMPLETE - 8 entities)
│       ├── quickstart.md    # CLI usage guide (COMPLETE)
│       ├── contracts/
│       │   └── api.yaml     # OpenAPI 3.0 spec (COMPLETE - 11 endpoints)
│       ├── research.md      # Technical research (COMPLETE - v2.0.0 updated)
│       └── tasks.md         # Implementation tasks (COMPLETE - 193 tasks, 15 phases)
└── templates/               # Spec-kit templates
```

## Technology Stack

- **Language**: Go 1.22+
- **Storage**: SQLite (default), PostgreSQL (enterprise), ClickHouse (analytics)
- **Schema**: JSON with JSON Schema validation
- **Expression Engine**: CEL (Common Expression Language) via `github.com/google/cel-go`
- **Attestation Format**: in-toto DSSE (Dead Simple Signing Envelope)
- **License**: Apache 2.0

## Important Research Sources

When working on OCEAN, reference these sources for context:

1. **Problem Statement**: https://blog.grc.engineering/p/soc-2-is-dead-long-live-soc-2
2. **Schema Inspiration**: https://schema.ocsf.io/ (OCSF)
3. **Related Project**: https://github.com/grcengineering/gigachad-grc
4. **Architecture Model**: Metasploit's module system

## Commands

The project uses GitHub Spec-Kit. Key commands:
- `/speckit.constitution` - Update project principles
- `/speckit.specify` - Create/update specifications
- `/speckit.plan` - Generate implementation plans
- `/speckit.tasks` - Break down into implementation tasks

## Current Status

- [x] Research complete (v2.0.0 — CEL, DSSE, active testing)
- [x] Constitution created (v2.0.0 — 10 principles)
- [x] Specification written (v2.0.0 — 11 user stories across 4 pillars)
- [x] Implementation plan (v2.0.0 — 8 phases, 7 technical decisions)
- [x] Design artifacts (data-model, API contracts, quickstart)
- [x] Tasks generated (v2.0.0 — 193 tasks across 15 phases)
- [x] Implementation complete (v2.0.0 — all 193 tasks across 15 phases)

## Modules

9 modules registered (3 source systems + mock):
- **Mock**: mock.test (collector), mock.network (collector), mock.safety_test (tester)
- **Okta**: okta.mfa_policy (collector), okta.mfa_bypass (tester)
- **AWS**: aws.iam (collector), aws.s3_public_access (tester)
- **GitHub**: github.branch_protection (collector), github.secret_push (tester)

## Testing Rules

### 1. Always Run Tests After Code Changes

After completing ANY feature, bug fix, or refactoring work:

1. Run `make test-unit` and verify exit code 0. Do NOT claim work is complete if tests fail.
2. Run `make coverage-check` and verify coverage meets the threshold. If coverage dropped, write additional tests before proceeding.
3. If you modified or created integration-level code (database interactions, multi-package pipelines, module registration), also run `make test-integration`.
4. Run `go vet ./...` to catch static analysis issues.

Never skip these steps. Never say "tests should be run" — actually run them and report the results.

### 2. Every Code Change Requires Corresponding Test Changes

- **New feature/function:** Write unit tests in the same package (`foo_test.go` alongside `foo.go`). Test the happy path, at least one error path, and edge cases.
- **Bug fix:** Write a regression test FIRST that reproduces the bug (red), then fix the bug (green). The regression test prevents the bug from returning. Name it `TestBugfix_<description>` or include a comment referencing the issue.
- **Refactoring:** Existing tests must still pass. If you change a function signature or behavior, update the affected tests to match. Do not delete tests to make refactoring "pass."
- **New module (collector or tester):** Use the contract test templates: call `testutil.RunCollectorTests(t, collector, config)` or `testutil.RunTesterTests(t, tester, config)` in addition to module-specific tests. Use `testutil.NewMockAPIServer(t)` for HTTP mocking — never call real external APIs in tests.

### 3. Test Type Selection

Use this decision tree to pick the right test type:

| What you're testing | Test type | Build tag | Command |
|---|---|---|---|
| A single function, method, or struct in isolation | **Unit test** | None (default) | `make test-unit` |
| Functions that call external HTTP APIs | **Unit test with httptest mock** | None | `make test-unit` |
| Cross-package interactions, SQLite storage, multi-module pipelines | **Integration test** | `//go:build integration` | `make test-integration` |
| Full CLI invocation, end-to-end user workflows | **E2E test** | `//go:build e2e` | `make test-e2e` |
| A bug that was reported/discovered | **Regression test** (unit or integration, depends on scope) | Depends on scope | Whichever tier is appropriate |
| Quick "does the binary start and respond" check | **Smoke test** (subset of e2e) | `//go:build e2e` | `make test-e2e` |

**Rules for test placement:**
- Unit tests go in the same package directory as the code under test: `foo/bar_test.go`
- Integration tests go in `tests/integration/` with the `//go:build integration` tag
- E2E tests go in `tests/e2e/` with the `//go:build e2e` tag
- Test fixtures (canned API responses, sample YAML) go in `tests/fixtures/`
- Use `internal/testutil` helpers (EvidenceBuilder, MockAPIServer, MemoryStore, assertions) to reduce test boilerplate

### 4. Test Quality Standards

- Tests must not depend on external network calls. Use `testutil.NewMockAPIServer(t)` for HTTP dependencies.
- Tests must not leave state on disk. Use `t.TempDir()` for any file I/O.
- Tests must be deterministic — no time-dependent flakiness, no random failures.
- Include `-race` flag (already in Makefile targets) to catch data races.
- When a test fails, fix the root cause. Do not skip, delete, or comment out the test.

## Session Notes

See `docs/SESSION-2026-01-17.md` for detailed session log including issues encountered.
