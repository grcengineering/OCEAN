# OCEAN Examination — 2026-08-09

A ground-truth architectural examination of OCEAN as it exists in this repository today,
written from direct source reads (file paths cited throughout), the `.specify/` spec
corpus, and semantic queries against the Serena (LSP) and CocoIndex indexes built over
this tree. Its purpose: establish the accurate current state before the HTH-parity
work, and correct documentation drift (the pre-existing CLAUDE.md described a Go
implementation; this codebase is Rust).

## 1. What OCEAN is

**OCEAN (Open Control Evidence Assessment Normalizer) is the "Metasploit for GRC":**
an open-source Rust CLI + library for evidence acquisition, active control testing,
remediation, and normalization, powering continuous compliance monitoring — the
backend for a "StatusPage for Compliance" (spec: `.specify/specs/ocean-core/spec.md`).

Four pillars (spec Executive Summary):

1. **Passive Control Monitoring** — query system APIs, observe configuration state, store as evidence
2. **Active Control Testing** — attempt what controls should prevent (Atomic-Red-Team-style), record whether it was blocked
3. **Flexible Evaluation Logic** — CEL expressions + YAML presets over collected evidence
4. **Evidence Integrity** — structured, provenance-carrying JSON evidence; cryptographic attestation is **delegated to Corsair** (ADR-001 addendum), not implemented here

It is deliberately **not** a GRC platform — it is the evidence/verification layer platforms consume.

## 2. The governing architectural decision: ADR-001

`.specify/specs/ocean-core/adr-001-unified-check-architecture.md` (Accepted,
2026-03-28, author: Justin Pagano) merges HTH into OCEAN:

- **`.check.yaml` meta-code is the single source of truth** for all check logic; OCEAN interprets it at runtime and compiles it into standalone code packs (`ocean build`). "Nuclei for GRC."
- **Four module types**, all expressible in one check file: Observer (passive), Tester (active), Remediator (`remediation:` block), Reporter (`references:` block).
- HTH's capabilities (remediation, code-pack generation, fleet ops, compliance reporting, profile tiers) become OCEAN subcommands.

**Status: implemented.** Every planned subcommand exists in the CLI (verified against
`ocean --help`): observe, test, harden, build, modules, evaluate, history, report,
schedule, serve, dashboard, compliance.

## 3. Architecture as built (Rust, workspace member of `grc-controls` siblings)

| Layer | Source | What it does |
|---|---|---|
| Check definitions | `src/check/definition.rs` (1,014 ln) | `.check.yaml` schema: id/name/source/profile, credentials, inputs, steps, assertions, remediation, references |
| Check loader | `src/check/loader.rs` (649 ln) | Loads/validates `checks/**/*.check.yaml` against `schemas/check.schema.json` |
| Check interpreter | `src/check/interpreter.rs` (1,388 ln) | `YamlObserver`/`YamlTester`: template resolution (`{{var}}`), HTTP via ureq, JSONPath extraction, CEL assertion evaluation, wraps results as Evidence |
| Native modules | `src/modules/` (observers/, testers/, github_common.rs) | Hand-written Rust observers/testers pre-dating the YAML path; registered via `src/modules/mod.rs` |
| Module framework | `src/module/` | Registry, executor, observer/tester traits, safety classifications (safe/observable/reversible/destructive), validation |
| Evidence | `src/evidence/` | OCSF-inspired evidence schema: StatusId (Effective/Ineffective/Unknown), ConfidenceLevel (passive_observation vs active_verification), findings, observables, test transcripts |
| Evaluation | `src/eval/` + `src/control/` | CEL engine, YAML presets, composite controls, framework mappings |
| Remediation | `src/harden/mod.rs` (1,416 ln) | `ocean harden` — API-call and Terraform remediation from the check's `remediation:` block |
| Codegen | `src/codegen/mod.rs` (970 ln) | `ocean build` — compiles checks to 7 targets: **api-script (bash+curl), gh-cli, python-sdk, go-sdk, opa-rego, terraform, sigma-rule** |
| Storage | `src/storage/sqlite.rs` | SQLite evidence store (4 tables), history/uptime queries |
| Fleet | `src/fleet/` | `fleet-manifest.schema.json`-driven multi-target execution |
| API server | `src/api/handlers.rs` | Axum REST: /api/v1/health, /evidence, /controls/:id/status, … |
| Dashboard | `src/dashboard/` | Interactive TUI with real-time control monitoring |
| Scheduler | `src/scheduler/` | Cron-style recurring observations |
| Secrets | `src/secrets/` | Credential resolution for checks (env-based; no credential storage by design) |

Site: `site/` (howtoharden-style static site adopting the GRCE Design System, commit 5b5eede).

## 4. Check inventory (current coverage)

`checks/`: **72 `.check.yaml` files** across 4 real vendors + test fixtures:

- **github/**: 38 (33 observers GH-1.01…GH-8.03 + 5 testers GH-TEST-01…05)
- **okta/**: 15
- **aws/**: 10 (CloudTrail, IAM, KMS, S3)
- **azure/**: 8
- `controls/`: control definitions (frameworks, iam, network, scm, mock) for CEL evaluation

Native Rust modules additionally cover the original 9 (mock ×3, okta ×2, aws ×2, github ×2)
plus a larger observer set under `src/modules/observers/` (github_* families, aws, azure).

## 5. Current vs. future features

**Working now** (exercised by the 960-test suite, green as of this examination after
one time-bomb fixture fix — `src/modules/observers/aws.rs` test pinned a "fresh"
key CreateDate that aged past the 90-day window):

- Full check lifecycle: load → validate → observe/test → evidence → CEL evaluate → history/uptime → report/compliance
- Codegen to all 7 targets; harden (API + Terraform); fleet execution; REST server; TUI dashboard; scheduling
- Safety gates for testers (classification + environment scoping + pre-flight + cleanup transcripts)
- CI: coverage gate ≥70% line (cargo-llvm-cov, GRC-144), SHA-pinned actions, fuzz targets (`fuzz/`), semgrep — now hardened further by sscsb (see §7)

**Future / gaps** (from spec + this examination):

- **Vendor coverage is the gap**: 4 vendors vs HTH's 125 guides / 71 pack-vendor sets (see `docs/PARITY-HTH.md`, Stage 3)
- Spec's user stories reference `ocean collect` / `ocean scan` verbs — CLI ships `observe` / fleet execution instead (naming drift between spec and implementation)
- Attestation/signing: intentionally delegated to Corsair; `schemas/attestation.schema.json` remains as the interface shape
- `docs/modules.md`, `docs/api.md`, `docs/quickstart.md` predate ADR-001 in places (Go-era references) — same drift class this file corrects for CLAUDE.md

## 6. Intended use cases

1. **Continuous control monitoring** — scheduled observers feeding the evidence store; uptime math over 180-day audit windows (spec User Story 2)
2. **Control efficacy proof** — active testers proving controls block what they claim to (US-8)
3. **Dual-mode verification** — policy-exists (passive) + policy-works (active) per control (US-11)
4. **Remediation** — `ocean harden` closing failed checks via API/Terraform
5. **Code-pack distribution** — `ocean build` emitting standalone artifacts for teams that can't run OCEAN directly (the HTH consumption model)
6. **Compliance reporting** — framework-mapped posture (SOC 2, NIST, ISO 27001, CIS, STIG) from the `references:` blocks

## 7. Environment governance added 2026-08-09 (Stage 1 of this program)

- ADE Bootstrapper governs the repo (`ade.json`, `.ade/` policy layer, managed instruction blocks in CLAUDE.md, lockfile, tamper-evident audit chain); `ade verify` PASS
- sscsb supply-chain control plane (`.sscsb/`, 13 SHA-pinned workflows incl. CodeQL/scorecard/SBOM/SLSA/secrets-scan; harden-runner + persist-credentials + --locked across pre-existing workflows); gitleaks+trufflehog pre-commit gate (proven live — it blocked the ADE lockfile commit until its SHA-256 digests were explicitly allowlisted)
- Context tooling: Serena MCP (LSP-semantic retrieval, registered in `.mcp.json`), CocoIndex semantic search (keyless local embeddings), OpenWiki installed (generation pending a model-provider credential)

## 8. Examination provenance

Direct reads: spec.md, adr-001, constitution.md, lib.rs, check/{definition,interpreter,loader}.rs,
codegen/mod.rs, harden/mod.rs, api/handlers.rs, modules/mod.rs, checks/ inventory,
schemas/. Tool-assisted: serena (127-file LSP index), ccc semantic search, `ocean --help`,
`ocean modules list`, full `cargo test --release` run (960 passed / 0 failed).
