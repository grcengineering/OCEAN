# Implementation Plan: OCEAN Core v2.0.0

**Branch**: `main` | **Date**: 2026-02-12 | **Spec**: `.specify/specs/ocean-core/spec.md`
**Constitution**: `.specify/memory/constitution.md` v2.0.0

## Summary

OCEAN is the "Metasploit for GRC" — an open-source CLI tool and Go library for evidence acquisition, active control testing, and normalization powering continuous compliance monitoring. The v2.0.0 plan expands the architecture from passive-only collection to a dual-mode system with:

1. **Core Engine**: Go-based CLI with dual-mode module architecture (Collectors + Testers)
2. **Evidence Schema**: JSON Schema-validated data model inspired by OCSF with confidence levels and test transcripts
3. **Storage Layer**: SQLite for local storage with optional PostgreSQL and ClickHouse
4. **Module System**: Well-defined Go interfaces for Collectors (passive) and Testers (active) with shared Module base
5. **Evaluation Engine**: CEL (Common Expression Language) for user-defined compliance conditions plus YAML presets
6. **Attestation Layer**: in-toto DSSE envelopes for cryptographic provenance (Collection + Evaluation attestations)
7. **Scheduling**: Built-in cron-style scheduler for continuous monitoring and testing with safety-aware scheduling

## Technical Context

**Language/Version**: Go 1.22+ (latest stable)
**Primary Dependencies**:
- `cobra` — CLI framework
- `modernc.org/sqlite` — CGO-free SQLite driver (pure Go)
- `pgx` — PostgreSQL driver (optional)
- `santhosh-tekuri/jsonschema` — JSON Schema validation
- `robfig/cron` — Scheduling
- `rs/zerolog` — Structured logging
- `stretchr/testify` — Testing assertions
- `google/cel-go` — CEL expression evaluation engine
- `in-toto/in-toto-golang` — in-toto attestation framework
- `secure-systems-lab/go-securesystemslib` — DSSE envelope signing/verification
- `crypto/ed25519` — Default signing (Go stdlib)

**Storage**: SQLite (default), PostgreSQL (enterprise), ClickHouse (analytics, optional)
**Testing**: Go standard testing + testify, table-driven tests
**Target Platform**: Windows, macOS (Intel/ARM), Linux (amd64/arm64)
**Project Type**: Single monorepo with internal packages
**Performance Goals**:
- CLI response < 1s for queries on < 100K records
- Evidence collection throughput: 1000 records/minute
- CEL evaluation: < 10ms per expression per evidence record
- API response < 100ms for single-control queries
- Active test overhead: < 30s beyond direct API interaction

**Constraints**:
- Single binary < 50MB
- Memory < 256MB typical usage
- Zero runtime dependencies
- Offline-capable
- Signing mandatory for all stored evidence

**Scale/Scope**:
- Support 1M+ evidence records
- 50+ modules (collectors + testers) over time
- 100+ control definitions
- Attestation chain depth: unlimited (collection → evaluation → re-evaluation)

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Status | Notes |
|-----------|--------|-------|
| I. Evidence-First Architecture | ✅ PASS | All data structures center on Evidence with provenance, confidence levels, immutability |
| II. OCSF-Inspired Schema | ✅ PASS | Hierarchical taxonomy (Categories → Classes → Attributes), shared dictionary, profiles |
| III. Metasploit-Style Extensibility | ✅ PASS | Dual-mode modules: Collector + Tester interfaces with shared Module base |
| IV. Cross-Platform Portability | ✅ PASS | Go single binary, CGO-free SQLite, no cloud deps, zero runtime deps |
| V. Control-Centric Organization | ✅ PASS | CEL evaluation logic, composite controls, framework mappings, content-addressed expressions |
| VI. Continuous Monitoring Native | ✅ PASS | Built-in scheduler, time-series queries, safety-aware scheduling |
| VII. Radical Transparency | ✅ PASS | No hiding failures, complete audit trail, test transcripts |
| VIII. Security & Privacy by Design | ✅ PASS | Mandatory signing, secret providers, test authorization, no credential storage |
| IX. Active Control Verification | ✅ PASS | Safety classifications, pre-flight validation, cleanup, environment scoping, test transcripts |
| X. Cryptographic Provenance Chain | ✅ PASS | Two-layer attestation (Collection + Evaluation), in-toto DSSE, content-addressable references, Ed25519 default |

## Project Structure

### Documentation

```text
.specify/
├── memory/
│   └── constitution.md          # Project principles v2.0.0 (complete)
├── specs/
│   └── ocean-core/
│       ├── spec.md              # Feature specification v2.0.0 (complete)
│       ├── plan.md              # This file
│       ├── research.md          # Technical research (updated for v2.0.0)
│       ├── data-model.md        # Entity definitions (new)
│       ├── quickstart.md        # Getting started guide (new)
│       ├── contracts/           # API contracts (new)
│       │   └── api.yaml         # OpenAPI 3.0 specification
│       ├── checklists/
│       │   └── requirements.md  # Spec quality validation (complete)
│       └── tasks.md             # Implementation tasks (to regenerate)
└── templates/                   # Spec-kit templates
```

### Source Code

```text
ocean/
├── cmd/
│   └── ocean/
│       └── main.go                  # CLI entrypoint
├── internal/
│   ├── cli/                         # CLI commands (cobra)
│   │   ├── root.go
│   │   ├── collect.go               # ocean collect <module>
│   │   ├── test.go                  # ocean test <module>
│   │   ├── verify.go                # ocean verify <control>
│   │   ├── evaluate.go              # ocean evaluate <control>
│   │   ├── history.go               # ocean history
│   │   ├── schedule.go              # ocean schedule
│   │   ├── modules.go               # ocean modules list/validate
│   │   ├── report.go                # ocean report
│   │   ├── provenance.go            # ocean verify-provenance
│   │   └── serve.go                 # ocean serve (server mode)
│   ├── module/                      # Module framework (shared base)
│   │   ├── module.go                # Module base interface + metadata
│   │   ├── collector.go             # Collector interface definition
│   │   ├── tester.go                # Tester interface definition
│   │   ├── registry.go              # Module discovery/registration
│   │   ├── executor.go              # Collection/test orchestration
│   │   ├── validation.go            # Output validation against schema
│   │   └── safety.go                # Safety classification types + enforcement
│   ├── control/                     # Control evaluation
│   │   ├── definition.go            # Control structure + YAML parsing
│   │   ├── evaluator.go             # Effectiveness calculation
│   │   ├── composite.go             # Multi-source controls
│   │   ├── framework.go             # Framework mappings (SOC2/ISO/NIST/CIS)
│   │   └── verifier.go              # Dual-mode verify orchestrator
│   ├── eval/                        # Evaluation engine
│   │   ├── cel.go                   # CEL expression compilation + execution
│   │   ├── presets.go               # YAML preset expansion to CEL
│   │   ├── version.go               # Content-addressed expression versioning
│   │   └── types.go                 # CEL custom types for evidence data
│   ├── evidence/                    # Evidence handling
│   │   ├── schema.go                # Evidence data structures
│   │   ├── validator.go             # JSON Schema validation
│   │   ├── observable.go            # Observable extraction
│   │   ├── confidence.go            # Confidence level types
│   │   └── transcript.go            # Test transcript structures
│   ├── attestation/                 # Cryptographic provenance
│   │   ├── dsse.go                  # DSSE envelope creation/verification
│   │   ├── collection.go            # Collection attestation predicate
│   │   ├── evaluation.go            # Evaluation attestation predicate
│   │   ├── signer.go                # Signing interface (Ed25519/KMS/OIDC)
│   │   ├── verifier.go              # Attestation chain verification
│   │   └── content.go               # Content-addressable digest utilities
│   ├── storage/                     # Persistence layer
│   │   ├── interface.go             # Storage interface
│   │   ├── sqlite.go                # SQLite implementation
│   │   ├── postgres.go              # PostgreSQL implementation
│   │   └── migrations/              # Schema migrations
│   ├── scheduler/                   # Automated collection + testing
│   │   ├── cron.go                  # Cron scheduling
│   │   ├── runner.go                # Job execution with safety checks
│   │   └── state.go                 # State persistence
│   ├── api/                         # REST API (server mode)
│   │   ├── server.go
│   │   ├── handlers.go
│   │   └── middleware.go
│   ├── secrets/                     # Credential providers
│   │   ├── interface.go
│   │   ├── env.go
│   │   ├── vault.go
│   │   └── aws.go
│   └── config/                      # Configuration
│       ├── config.go
│       └── loader.go
├── modules/                         # Built-in modules
│   ├── collectors/                  # Passive evidence gathering
│   │   ├── okta/
│   │   │   ├── collector.go
│   │   │   └── mfa.go
│   │   ├── aws/
│   │   │   ├── collector.go
│   │   │   └── iam.go
│   │   └── github/
│   │       ├── collector.go
│   │       └── branch_protection.go
│   └── testers/                     # Active control verification
│       ├── okta/
│       │   ├── tester.go
│       │   └── mfa_bypass.go        # [safe] Attempt auth without MFA
│       ├── github/
│       │   ├── tester.go
│       │   └── secret_push.go       # [observable] Attempt secret push
│       └── aws/
│           ├── tester.go
│           └── public_access.go     # [safe] Attempt unauthenticated access
├── pkg/                             # Public API for library consumers
│   ├── ocean/                       # Library interface
│   │   ├── client.go
│   │   └── types.go
│   └── schema/                      # Evidence schema types
│       ├── evidence.go
│       └── control.go
├── schemas/                         # JSON Schema definitions
│   ├── evidence.schema.json
│   ├── control.schema.json
│   ├── module.schema.json
│   └── attestation.schema.json
├── controls/                        # Default control library
│   ├── iam/
│   │   └── mfa_enforcement.yaml
│   └── network/
│       └── waf_protection.yaml
├── tests/
│   ├── integration/
│   ├── e2e/
│   └── fixtures/
├── docs/
│   ├── quickstart.md
│   ├── modules.md                   # Module development guide (collectors + testers)
│   └── api.md
├── go.mod
├── go.sum
├── Makefile
├── Dockerfile
└── README.md
```

**Structure Decision**: Single monorepo with clear internal/pkg separation. `modules/` split into `collectors/` and `testers/` subdirectories reflecting the dual-mode architecture. `internal/attestation/` is new for v2.0.0. `internal/eval/` is new for CEL engine. Internal packages are implementation details; `pkg/` exposes stable public API for library consumers (GRC platforms embedding OCEAN).

## Phased Implementation

### Phase 0: Foundation (US1 partial)

**Goal**: Basic CLI skeleton, evidence schema, and in-memory collection with mock module.

**Deliverables**:
1. Go module initialized with all dependencies
2. CLI framework with `ocean --help`, `ocean version`
3. Evidence schema v2.0.0 JSON Schema definition (including `confidence_level`, `attestation`, `test_transcript`)
4. Evidence Go types with validation
5. Module base interface + Collector interface
6. In-memory evidence store (no persistence yet)
7. Mock collector for testing
8. Ed25519 key generation (`ocean keys generate`)
9. Basic DSSE envelope creation for collected evidence
10. `ocean collect mock.test` working end-to-end with signed attestation

**Exit Criteria**: `ocean collect mock.test` returns valid, schema-compliant, signed evidence to stdout with a Collection Attestation.

### Phase 1: Storage & History (US2)

**Goal**: Persistent storage, historical queries, and uptime calculations.

**Deliverables**:
1. SQLite storage implementation (with attestation storage)
2. Migration framework
3. `ocean history` command with time-range queries
4. Time-series queries with uptime percentage calculation
5. Configuration file support (YAML)
6. Content-addressable artifact storage (digests for raw_data, attestations)

**Exit Criteria**: Evidence persists across CLI invocations; `ocean history --control mock.test --days 7` returns stored data with uptime percentage; attestation chain is stored and retrievable.

### Phase 2: Active Testing Framework (US8)

**Goal**: Tester interface and active control verification with safety system.

**Deliverables**:
1. Tester interface definition (extends Module base)
2. Safety classification types (safe/observable/reversible/destructive)
3. Pre-flight validation framework (scope, authorization, rollback check)
4. Post-execution cleanup framework
5. Test transcript capture (actions, observations, cleanup)
6. Environment scoping enforcement (production/staging/isolated)
7. Authorization prompt system (appropriate to safety level)
8. Mock tester for testing
9. `ocean test mock.safety_test` working end-to-end with transcript and attestation

**Exit Criteria**: `ocean test mock.safety_test` executes pre-flight, runs mock test, captures transcript, performs cleanup, stores signed evidence with `confidence_level: active_verification`.

### Phase 3: Evaluation Engine (US10, US11)

**Goal**: CEL-based evaluation, YAML presets, dual-mode verification, and composite controls.

**Deliverables**:
1. CEL environment setup with custom evidence types
2. CEL expression compilation, validation, and execution
3. YAML preset system (common patterns expand to CEL)
4. Content-addressed expression versioning (SHA-256 of expression text)
5. Evaluation Attestation creation (references evidence digests + expression version)
6. Control definition YAML schema (referencing collectors + testers + evaluation logic)
7. Composite control support (multi-source aggregation)
8. `ocean evaluate` command with CEL expressions
9. `ocean verify` command (dual-mode: collect + test + evaluate)
10. Confidence level aggregation (passive-only vs passive+active)
11. Framework mapping structure (SOC 2 ↔ ISO 27001 ↔ NIST CSF ↔ CIS Controls)

**Exit Criteria**: `ocean verify control.mock_mfa` collects passive evidence, runs active test, evaluates CEL expression, and produces unified control status with Evaluation Attestation.

### Phase 4: Real Modules (US1, US5, US8 complete)

**Goal**: First real-world integrations — both collectors and testers.

**Deliverables**:
1. Module registry and runtime discovery
2. Secret provider interface (env vars, Vault)
3. `ocean modules list` and `ocean module validate` commands
4. Okta collector (MFA policies, user lifecycle)
5. AWS IAM collector (MFA status, access keys age)
6. GitHub collector (branch protection, secret scanning config)
7. Okta MFA bypass tester [safe] (attempt auth without MFA)
8. GitHub secret push tester [observable] (attempt to push test secret)
9. AWS public access tester [safe] (attempt unauthenticated S3 access)
10. Module development documentation

**Exit Criteria**: `ocean collect okta.mfa_policy` returns real evidence from Okta API; `ocean test okta.mfa_bypass` attempts and records MFA bypass result; `ocean verify control.mfa_enforcement` runs both.

### Phase 5: Scheduling & Provenance Verification (US4, US9)

**Goal**: Continuous monitoring with safety-aware scheduling and provenance verification.

**Deliverables**:
1. Cron-style scheduler for collectors and testers
2. Safety-aware scheduling (pre-authorized tests only)
3. Schedule state persistence across restarts
4. Failure alerting (stdout/webhook)
5. `ocean schedule` commands (add/list/remove/status)
6. Catch-up collection for missed runs
7. `ocean verify-provenance --evidence <id>` command
8. Full attestation chain verification (Collection → Evaluation)
9. Tamper detection (digest mismatch reporting)
10. Third-party verification support (public key + attestation chain export)

**Exit Criteria**: Scheduled collections and safe tests run automatically; `ocean verify-provenance --evidence <id>` validates the complete attestation chain; tampered evidence is detected.

### Phase 6: Server Mode & API (US7)

**Goal**: Enable external system integration via REST API.

**Deliverables**:
1. HTTP server with REST API
2. Authentication middleware
3. Evidence query endpoints (with confidence level filtering)
4. Control status endpoints
5. Attestation export endpoints (DSSE envelopes)
6. OpenAPI 3.0 specification
7. Cursor-based pagination

**Exit Criteria**: External system can query `/api/v1/evidence?min_confidence=active_verification` and receive JSON response with attestations.

### Phase 7: Reports & Polish (US6)

**Goal**: Human-readable reports and production-ready distribution.

**Deliverables**:
1. Markdown report generation (passive + active evidence distinguished)
2. CSV export
3. Provenance verification in reports (`--verify-provenance` flag)
4. Cross-platform builds (Windows, macOS, Linux)
5. Docker image
6. Homebrew formula
7. Comprehensive documentation
8. Default control library (10+ controls with framework mappings)
9. Performance optimization
10. Security audit

**Exit Criteria**: `ocean report --format markdown --verify-provenance` generates a complete report; users can install via `brew install ocean` and complete quickstart in < 5 minutes.

## Key Technical Decisions

### Decision 1: CGO-Free SQLite

**Choice**: Use `modernc.org/sqlite` (pure Go SQLite)
**Rationale**: Enables single-binary cross-compilation without CGO complexity. Performance is sufficient for target scale (< 1M records).
**Trade-off**: Slightly slower than CGO SQLite; acceptable given portability benefits.

### Decision 2: Modules as Interfaces, Not Plugins

**Choice**: Collectors and Testers implement Go interfaces, compiled into binary
**Rationale**: Simpler than dynamic plugin loading; Go plugin system has portability issues. External modules can use CLI subprocess protocol.
**Trade-off**: Adding new modules requires recompilation; mitigated by frequent release cadence and subprocess protocol for external modules.

### Decision 3: YAML for Human Config, JSON for Machine

**Choice**: Control definitions, schedules, and config in YAML; evidence and API in JSON
**Rationale**: YAML is more readable for practitioners authoring controls and CEL expressions. JSON is standard for programmatic interchange.
**Trade-off**: Two formats to support; mitigated by robust YAML↔JSON conversion.

### Decision 4: CEL Over OPA/Rego

**Choice**: CEL (Common Expression Language) for user-defined evaluation logic
**Rationale**: Non-Turing-complete (guaranteed termination), Go-native (`google/cel-go`), simple expression syntax familiar to developers, no external runtime needed. Rego/OPA is more powerful but heavier and Turing-complete.
**Trade-off**: Less expressive than Rego; acceptable because compliance conditions are typically simple boolean expressions over evidence fields.

### Decision 5: in-toto DSSE Over Raw Signing

**Choice**: in-toto Statement + DSSE envelope for attestation format
**Rationale**: Standards-based, well-defined predicate model, content-addressable subjects, ecosystem compatibility (Sigstore, SLSA). Raw Ed25519 signatures lack the structured predicate that captures what-was-signed-and-why.
**Trade-off**: More complex than raw signatures; justified by the provenance chain requirements in Principle X.

### Decision 6: Two-Layer Attestation Model

**Choice**: Separate Collection Attestations and Evaluation Attestations
**Rationale**: Enables independent verification of "what was gathered" vs "how it was evaluated". An auditor can verify evidence collection without understanding evaluation logic, and vice versa.
**Trade-off**: More attestation records to store/manage; justified by Constitution Principle X requirement for complete provenance chain.

### Decision 7: Tester Interface Separate from Collector

**Choice**: Separate Collector and Tester Go interfaces with shared Module base
**Rationale**: Safety classification, pre-flight validation, cleanup, and test transcripts are specific to active testing. Separate interfaces keep the Collector contract simple while enabling the full safety framework for Testers. A module MAY implement both.
**Trade-off**: Two interface contracts to maintain; justified by fundamentally different operational modes and safety requirements.

## Risk Mitigation

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| API rate limiting from sources | Collection/test fails | High | Built-in rate limiting, exponential backoff, configurable delays |
| Schema changes in source APIs | Module breaks | Medium | Version detection, graceful degradation, automated schema tests |
| Evidence volume overwhelms SQLite | Performance degrades | Low | Retention policies, archival, PostgreSQL migration path |
| Credential exposure | Security incident | Medium | Secret provider abstraction, audit trail, no credential logging |
| Active test causes unintended damage | Operational incident | Medium | Safety classification, pre-flight validation, environment scoping, authorization gates |
| Cleanup failure after active test | Orphaned test resources | Medium | Cleanup retry, operator alerting, manual cleanup documentation |
| CEL expression abuse (resource exhaustion) | Service degradation | Low | Complexity limits on CEL expressions, non-Turing-complete guarantee |
| Key compromise for signing | Trust in attestations lost | Low | Key rotation support, KMS integration for enterprise, old attestations remain verifiable |
| Community doesn't contribute modules | Limited adoption | Medium | Comprehensive module docs, example templates, maintainer support |

## Dependencies on Research

1. **CEL Go Library**: Best practices for `cel-go` integration, custom type adapters, performance characteristics
2. **in-toto DSSE Go**: DSSE envelope creation/verification patterns with `in-toto-golang`
3. **Active Testing Patterns**: Atomic Red Team test definition structure, safety classification systems
4. **OCSF Schema Review**: Deep dive into OCSF event classes to finalize OCEAN evidence categories
5. **Cloud Provider APIs**: Okta MFA endpoints, AWS IAM APIs, GitHub API for branch protection and secret scanning

## Complexity Tracking

No constitution violations requiring justification. All 10 principles are directly addressed in the architecture.

| Decision | Principle Alignment | Justification |
|----------|-------------------|---------------|
| Dual module interfaces | III, IX | Separate safety concerns for Collectors vs Testers |
| Mandatory DSSE signing | VIII, X | Constitution requires mandatory signing, not optional |
| CEL evaluation engine | V | Constitution specifies non-Turing-complete expression language |
| Content-addressed expressions | V, X | Constitution requires reproducible historical evaluations |
| Safety classification system | IX | Constitution defines 4 levels with specific requirements |

## Next Steps

1. Complete research.md with v2.0.0 technology findings (CEL, DSSE, active testing)
2. Create data-model.md with complete entity definitions
3. Create contracts/api.yaml with OpenAPI 3.0 specification
4. Create quickstart.md with end-to-end usage guide
5. Run `/speckit.tasks` to generate implementation tasks from this plan
