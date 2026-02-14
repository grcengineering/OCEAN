# Tasks: OCEAN Core v2.0.0

**Input**: Design documents from `.specify/specs/ocean-core/`
**Prerequisites**: plan.md (required), spec.md (required), data-model.md, contracts/api.yaml, quickstart.md, research.md
**Constitution**: `.specify/memory/constitution.md` v2.0.0

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (US1, US2, US3, US4, US5, US6, US7, US8, US9, US10, US11)
- Exact file paths included in descriptions

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Project initialization, Go module structure, build tooling

- [X] T001 Initialize Go module: `go mod init github.com/grcengineering/ocean` in project root
- [X] T002 Create directory structure per plan.md: cmd/ocean/, internal/cli/, internal/module/, internal/control/, internal/eval/, internal/evidence/, internal/attestation/, internal/storage/, internal/scheduler/, internal/api/, internal/secrets/, internal/config/, modules/collectors/, modules/testers/, pkg/ocean/, pkg/schema/, schemas/, controls/, tests/integration/, tests/e2e/, tests/fixtures/, docs/
- [X] T003 [P] Add core dependencies to go.mod: cobra, modernc.org/sqlite, rs/zerolog, stretchr/testify, santhosh-tekuri/jsonschema, google/cel-go, in-toto/in-toto-golang, secure-systems-lab/go-securesystemslib, robfig/cron
- [X] T004 [P] Create Makefile with targets: build, test, lint, run, install, clean, cross-compile
- [X] T005 [P] Create .gitignore for Go project (binaries, vendor, .ocean/, *.key)
- [X] T006 [P] Create Dockerfile for container builds (multi-stage, scratch final image)
- [X] T007 [P] Configure golangci-lint with .golangci.yml (errcheck, govet, staticcheck, unused)
- [X] T008 Create cmd/ocean/main.go entrypoint (minimal, calls internal/cli root command)

**Checkpoint**: `go build ./cmd/ocean` succeeds, `./ocean --help` shows version placeholder

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core types, interfaces, and infrastructure that ALL user stories depend on

**CRITICAL**: No user story work can begin until this phase is complete

### Core Types

- [X] T009 [P] Define Evidence struct and JSON tags in internal/evidence/schema.go per data-model.md (id, control_id, class_uid, category_uid, activity_id, time, confidence_level, metadata, observables, status_id, status, raw_data, findings, test_transcript, attestation, enrichments)
- [X] T010 [P] Define Metadata, Observable, Finding, Enrichment, AttestationRef substructures in internal/evidence/schema.go per data-model.md
- [X] T011 [P] Define ConfidenceLevel enum type (passive_observation, active_verification) in internal/evidence/confidence.go
- [X] T012 [P] Define StatusID enum constants (Unknown=0, Effective=1, Ineffective=2, Other=99) in internal/evidence/schema.go
- [X] T013 [P] Define TestTranscript struct with TranscriptAction, TranscriptObservation, TranscriptCleanup in internal/evidence/transcript.go per data-model.md
- [X] T014 [P] Define Control struct in internal/control/definition.go per data-model.md (id, name, description, threat_mitigated, framework_mappings, evidence_requirements, collectors, testers, evaluation_logic, evaluation_expression_hash)
- [X] T015 [P] Define EvaluationLogic, FrameworkMapping, ModuleRef substructures in internal/control/definition.go
- [X] T016 [P] Define ControlStatus struct in internal/control/evaluator.go per data-model.md (id, control_id, timestamp, status, confidence, evidence_ids, evaluation_details, evaluation_attestation_ref)
- [X] T017 [P] Define Schedule struct with SafetyAuth in internal/scheduler/state.go per data-model.md
- [X] T018 [P] Define Framework and FrameworkControl structs in internal/control/framework.go per data-model.md
- [X] T019 [P] Define SafetyClassification enum (safe, observable, reversible, destructive) in internal/module/safety.go
- [X] T020 [P] Define EnvironmentScope enum (production, staging, isolated) in internal/module/safety.go

### Module Interfaces

- [X] T021 Define Module base interface in internal/module/module.go: ID(), Name(), Version(), SourceSystem(), EvidenceTypes(), CredentialRequirements()
- [X] T022 [P] Define Collector interface extending Module in internal/module/collector.go: Collect(ctx, config) ([]Evidence, error)
- [X] T023 [P] Define Tester interface extending Module in internal/module/tester.go: SafetyClassification(), EnvironmentScope(), PreFlightChecks(), CleanupProcedures(), Test(ctx, config) ([]Evidence, error)
- [X] T024 Define ModuleRegistry in internal/module/registry.go: Register(), Get(), List(), ListByType() methods
- [X] T025 Define ModuleExecutor in internal/module/executor.go: ExecuteCollector(), ExecuteTester() with error handling and evidence validation

### Storage Interface

- [X] T026 Define Store interface in internal/storage/interface.go: StoreEvidence(), GetEvidence(), QueryEvidence(), StoreControlStatus(), GetControlStatus(), QueryHistory(), StoreAttestation(), GetAttestation(), Close()

### Configuration

- [X] T027 Define Config struct in internal/config/config.go: storage path, log level, key paths, secret provider config
- [X] T028 Implement config loader in internal/config/loader.go: YAML file + env vars + CLI flags (twelve-factor)

### CLI Framework

- [X] T029 Create root command in internal/cli/root.go with global flags (--config, --verbose, --output-format)
- [X] T030 [P] Create version command in internal/cli/root.go showing build info
- [X] T031 [P] Create placeholder commands for all subcommands: collect, test, verify, evaluate, history, schedule, modules, report, verify-provenance, keys, serve in internal/cli/

### JSON Schema

- [X] T032 [P] Create evidence.schema.json in schemas/ defining the OCEAN Evidence Schema v2.0.0 per spec.md
- [X] T033 [P] Create control.schema.json in schemas/ defining control definition format
- [X] T034 [P] Create module.schema.json in schemas/ defining module metadata format
- [X] T035 [P] Create attestation.schema.json in schemas/ defining attestation envelope format
- [X] T036 Implement JSON Schema validator in internal/evidence/validator.go using santhosh-tekuri/jsonschema

### Evidence Validation

- [X] T037 Implement observable extraction in internal/evidence/observable.go: extract key indicators (user, ip, resource, domain) from nested evidence data
- [X] T038 Implement evidence validation logic in internal/evidence/validator.go: verify required fields, confidence_level/test_transcript consistency, attestation presence

### Secret Provider

- [X] T039 Define SecretProvider interface in internal/secrets/interface.go: Get(name string) (string, error)
- [X] T040 [P] Implement EnvSecretProvider in internal/secrets/env.go (reads from environment variables)

### Logging

- [X] T041 Configure structured logging with zerolog in internal/config/config.go (JSON output, level from config)

**Checkpoint**: All core types compile, interfaces defined, `ocean --help` shows all subcommands, JSON schemas validate test fixtures

---

## Phase 3: User Story 1 — Collect Evidence for a Single Control (Priority: P1) MVP

**Goal**: Passive evidence collection from a source system with schema validation, signing, and Collection Attestation

**Independent Test**: `ocean collect mock.test` returns signed, schema-compliant evidence with DSSE Collection Attestation

### Cryptographic Signing (prerequisite for evidence storage)

- [X] T042 [US1] Implement Ed25519 key generation in internal/attestation/signer.go: GenerateKeyPair() returning public/private key pair, saved to ~/.ocean/keys/
- [X] T043 [US1] Create `ocean keys generate` CLI command in internal/cli/keys.go calling signer.GenerateKeyPair()
- [X] T044 [US1] Implement Ed25519Signer satisfying a Signer interface in internal/attestation/signer.go: Sign(payload []byte) (signature, keyID)
- [X] T045 [US1] Implement content-addressable digest utilities in internal/attestation/content.go: DigestOf(data []byte) string returning sha256:<hex>

### DSSE Attestation

- [X] T046 [US1] Implement DSSE envelope creation in internal/attestation/dsse.go using go-securesystemslib: CreateEnvelope(statement, signer) returning signed DSSE envelope
- [X] T047 [US1] Implement Collection Attestation predicate in internal/attestation/collection.go: NewCollectionAttestation(moduleID, moduleVersion, source, evidenceDigest, rawDataDigest, transcriptDigest) returning in-toto Statement with OCEAN collection predicate type
- [X] T048 [US1] Implement attestation wrapping: given Evidence + Signer, create DSSE-signed Collection Attestation and attach ref to evidence in internal/attestation/collection.go

### Mock Collector

- [X] T049 [US1] Implement MockCollector in modules/collectors/mock/collector.go: returns hardcoded MFA-style evidence with all required fields, confidence_level=passive_observation
- [X] T050 [US1] Register MockCollector in module registry (internal/module/registry.go default registrations)

### Collection Pipeline

- [X] T051 [US1] Implement collection pipeline in internal/module/executor.go ExecuteCollector(): call collector → validate schema → sign → create Collection Attestation → return evidence with attestation ref
- [X] T052 [US1] Wire `ocean collect <module>` CLI command in internal/cli/collect.go: parse module name, lookup in registry, execute collection pipeline, output JSON to stdout

### Output Formatting

- [X] T053 [P] [US1] Implement JSON output formatter in internal/cli/output.go (pretty-print with --format json)
- [X] T054 [P] [US1] Implement YAML output formatter in internal/cli/output.go (--format yaml)

**Checkpoint**: `ocean keys generate` creates Ed25519 keypair; `ocean collect mock.test` outputs schema-valid, DSSE-signed evidence with Collection Attestation

---

## Phase 4: User Story 2 — Store and Query Historical Evidence (Priority: P1) MVP

**Goal**: SQLite persistence, historical queries, and uptime calculations

**Independent Test**: Evidence persists across invocations; `ocean history --control mock.test --days 7` returns stored data with uptime percentage

### SQLite Storage

- [X] T055 [US2] Implement SQLite storage backend in internal/storage/sqlite/sqlite.go using modernc.org/sqlite: Open(), Close(), all Store interface methods
- [X] T056 [US2] Create inline migration in internal/storage/sqlite/sqlite.go: evidence table, control_status table, attestation table, indexes on control_id+time
- [X] T057 [US2] Implement migration runner in internal/storage/sqlite/sqlite.go: apply migrations on Open()
- [X] T058 [US2] Implement StoreEvidence in internal/storage/sqlite/sqlite.go: serialize evidence JSON fields, store with indexed columns
- [X] T059 [US2] Implement GetEvidence and QueryEvidence in internal/storage/sqlite/sqlite.go: filter by control_id, time range, source, confidence_level
- [X] T060 [US2] Implement StoreAttestation and GetAttestation in internal/storage/sqlite/sqlite.go: store DSSE envelopes by content-addressable reference

### History Queries

- [X] T061 [US2] Implement StoreControlStatus in internal/storage/sqlite/sqlite.go: store point-in-time evaluation results
- [X] T062 [US2] Implement QueryHistory in internal/storage/sqlite/sqlite.go: time-series query with bucketing (daily/weekly/monthly), gap detection
- [X] T063 [US2] Implement uptime percentage calculation in internal/control/evaluator.go: count effective vs total buckets, handle gaps as unknown (not effective)

### CLI Integration

- [X] T064 [US2] Wire `ocean collect` to store evidence in SQLite after collection pipeline (update internal/cli/collect.go to open storage, persist)
- [X] T065 [US2] Implement `ocean history` command in internal/cli/history.go: --control, --days, --from, --to, --format flags; output time-series with uptime percentage
- [X] T066 [US2] Implement gap indication in history output: clearly mark periods with no evidence as "gap" (not interpolated)

### Configuration Integration

- [X] T067 [US2] Wire config loader to storage initialization: storage.path from config file, default to ~/.ocean/ocean.db

**Checkpoint**: `ocean collect mock.test` persists to SQLite; `ocean history --control mock.test --days 7` shows time-series with uptime percentage; gaps are clearly indicated

---

## Phase 5: User Story 8 — Run an Active Control Test (Priority: P1) MVP

**Goal**: Tester interface with full safety system, pre-flight validation, cleanup, and test transcript

**Independent Test**: `ocean test mock.safety_test` executes with pre-flight, captures transcript, performs cleanup, stores signed evidence with active_verification confidence

### Safety System

- [X] T068 [US8] Implement safety classification enforcement in internal/module/safety.go: ValidateSafetyLevel(), CanRunInEnvironment(classification, scope) bool
- [X] T069 [US8] Implement authorization prompt system in internal/module/safety.go: RequiredAuthLevel(), Authorizer interface, AutoAuthorizer
- [X] T070 [US8] Implement environment scope validation in internal/module/safety.go: EnforceScope(tester, targetEnvironment) error — refuse if scope violated

### Pre-Flight & Cleanup

- [X] T071 [US8] Implement pre-flight validation framework in internal/module/executor.go: RunPreFlight(tester, config) checking authorization, scope, rollback readiness sequentially
- [X] T072 [US8] Implement cleanup execution framework in internal/module/executor.go: RunCleanup(tester) with transcript recording

### Test Transcript Capture

- [X] T073 [US8] Implement transcript recorder in internal/evidence/transcript.go: NewTranscriptRecorder() with RecordAction(), RecordObservation(), RecordCleanup(), Finalize() methods building TestTranscript struct

### Test Execution Pipeline

- [X] T074 [US8] Implement test execution pipeline in internal/module/executor.go ExecuteTester(): pre-flight → authorization → test → transcript capture → cleanup → sign → Collection Attestation → return evidence with confidence_level=active_verification
- [X] T075 [US8] Ensure test transcript is embedded in evidence and its digest included in Collection Attestation (already handled by collection.go)

### Mock Tester

- [X] T076 [US8] Implement MockTester in modules/testers/mock/tester.go: safety_classification=safe, simulates MFA bypass attempt blocked, returns evidence with test transcript
- [X] T077 [US8] Register MockTester in module registry

### CLI Integration

- [X] T078 [US8] Wire `ocean test <module>` CLI command in internal/cli/test.go: parse module, --target flag for environment, execute test pipeline, display pre-flight results, output evidence JSON
- [X] T079 [US8] Store test evidence in SQLite with confidence_level=active_verification (reuse storage from US2)

**Checkpoint**: `ocean test mock.safety_test` runs pre-flight, executes mock test, captures transcript, performs cleanup, stores DSSE-signed evidence with active_verification confidence

---

## Phase 6: User Story 11 — Dual-Mode Control Verification (Priority: P1) MVP

**Goal**: Combined passive+active verification producing unified control status with confidence levels

**Independent Test**: `ocean verify control.mock_mfa` triggers both collection and testing, then displays unified status with high confidence

### Control Definition Loading

- [X] T080 [US11] Implement YAML control definition parser in internal/control/definition.go: LoadControl(path) parsing control YAML with collectors, testers, evaluation_logic
- [X] T081 [US11] Implement control discovery in internal/control/definition.go: LoadAllControls(dir) scanning controls/ directory for YAML files
- [X] T082 [US11] Create mock control definition in controls/mock/mfa_enforcement.yaml referencing mock.test collector and mock.safety_test tester

### Basic Evaluation (prerequisite for dual-mode)

- [X] T083 [US11] Implement basic evaluator in internal/control/evaluator.go: EvaluateControl(control, evidences) returning ControlStatus with status and confidence based on evidence types present
- [X] T084 [US11] Implement confidence rules in internal/control/evaluator.go: high (both passive+active agreeing), medium (single type), low (stale/incomplete); active takes precedence when disagreeing

### Dual-Mode Verifier

- [X] T085 [US11] Implement dual-mode verify orchestrator in internal/control/verifier.go: VerifyControl() → load control → execute all collectors → execute authorized testers → evaluate → return unified ControlStatus
- [X] T086 [US11] Handle partial verification: when tester not authorized, proceed with passive-only and note skipped test in evaluation_details
- [X] T087 [US11] Handle discrepancy: when passive=effective but active=ineffective, set status=ineffective with active taking precedence, highlight discrepancy in evaluation_details

### CLI Integration

- [X] T088 [US11] Wire `ocean verify <control>` CLI command in internal/cli/verify.go: parse control ID, load definition, run verifier, display unified status (status, confidence, evidence summary)
- [X] T089 [US11] Store ControlStatus in SQLite with evidence_ids linking to both passive and active evidence records

**Checkpoint**: `ocean verify control.mock_mfa` collects mock evidence + runs mock test + evaluates + displays unified "effective" with "high" confidence

---

## Phase 7: User Story 10 — Custom Evaluation Logic with CEL (Priority: P2)

**Goal**: CEL expression compilation, validation, execution, content-addressing, and YAML presets

**Independent Test**: Control definition with custom CEL expression evaluates correctly; expression is content-addressed in Evaluation Attestation

### CEL Engine

- [X] T090 [US10] Implement CEL environment setup in internal/eval/cel.go: NewCELEnvironment() with evidence and control variables, custom types for evidence map access
- [X] T091 [US10] Implement CEL custom types in internal/eval/types.go: type adapters for Evidence struct fields accessible in CEL expressions
- [X] T092 [US10] Implement CEL expression compilation in internal/eval/cel.go: CompileExpression(expr string) → (CompiledExpression, error) with syntax and type checking at compile time
- [X] T093 [US10] Implement CEL expression evaluation in internal/eval/cel.go: Evaluate(compiled, evidenceMap) → (bool, error)
- [X] T094 [US10] Implement expression content-addressing in internal/eval/version.go: ContentAddress(expression string) → sha256 hash; store mapping expression_hash → compiled program

### YAML Presets

- [X] T095 [US10] Define preset registry in internal/eval/presets.go: map of preset_name → CEL expression string (e.g., "all_users_mfa_enforced" → CEL)
- [X] T096 [US10] Implement preset expansion in internal/eval/presets.go: ExpandPreset(name) → CEL expression string; error if unknown preset
- [X] T097 [US10] Wire presets into control evaluation: when control uses preset instead of CEL, expand to CEL before evaluation

### Evaluation Attestation

- [X] T098 [US10] Implement Evaluation Attestation predicate in internal/attestation/evaluation.go: NewEvaluationAttestation(controlID, evidenceDigests, expressionDigest, expressionText, verdict) returning in-toto Statement with OCEAN evaluation predicate type
- [X] T099 [US10] Wire evaluation attestation creation into control evaluator: after evaluation, create signed Evaluation Attestation and link to ControlStatus

### CEL Integration

- [X] T100 [US10] Wire CEL engine into control evaluator: replace basic evaluation with CEL-based evaluation when expression is defined
- [X] T101 [US10] Implement `ocean evaluate <control>` CLI command in internal/cli/evaluate.go: load control, compile CEL, evaluate against stored evidence, display result with expression hash
- [X] T102 [US10] Support --cel flag on evaluate command for ad-hoc expression evaluation (overrides control definition)

### Error Handling

- [X] T103 [US10] Handle CEL compilation errors: report parsing errors with line/column position
- [X] T104 [US10] Handle missing evidence fields in CEL: return status=unknown with message about missing data (not crash or false positive)

**Checkpoint**: Control with CEL expression evaluates correctly; `ocean evaluate control.mock_mfa --cel 'evidence.mfa_policy.enforcement == "required"'` works; expression hash appears in Evaluation Attestation

---

## Phase 8: User Story 3 — Multi-Source Composite Controls (Priority: P2)

**Goal**: Controls that aggregate evidence from multiple collectors and testers across different source systems

**Independent Test**: Composite control referencing 3 collectors and 1 tester evaluates with per-component breakdown

### Composite Control Support

- [X] T105 [US3] Implement composite control evaluation in internal/control/composite.go: aggregate evidence from multiple collectors and testers, run CEL expression against combined evidence map
- [X] T106 [US3] Implement per-component breakdown in evaluation_details: show each collector/tester result individually with status and confidence
- [X] T107 [US3] Handle partial source availability: if one source unreachable, status=unknown for that component; overall status reflects available data
- [X] T108 [US3] Handle mixed safety classifications in composite: authorization requirement is the highest (most restrictive) classification among all included testers

### Mock Composite Control

- [X] T109 [US3] Create mock composite control definition in controls/mock/waf_protection.yaml referencing multiple mock collectors and tester with composite CEL expression
- [X] T110 [US3] Add second mock collector in modules/collectors/mock/collector_b.go returning different evidence type for composite testing

### CLI Integration

- [X] T111 [US3] Verify `ocean verify control.mock_waf_protection` handles composite control correctly with per-component breakdown in output

**Checkpoint**: `ocean verify control.mock_waf_protection` aggregates evidence from multiple sources, shows per-component breakdown, handles partial failures

---

## Phase 9: User Story 5 — Extend with Custom Modules (Priority: P2)

**Goal**: Module validation, listing, and documentation for community contribution

**Independent Test**: `ocean modules list` shows all modules with capabilities; `ocean module validate mock.test` validates interface compliance

### Module Discovery

- [X] T112 [US5] Implement module listing in internal/module/registry.go: ListModules() returning all registered modules with metadata, type (collector/tester/dual), safety classifications for testers
- [X] T113 [US5] Implement module filtering in registry: ListByType(type), ListBySourceSystem(system)

### Module Validation

- [X] T114 [US5] Implement module validation in internal/module/validation.go: ValidateModule(module) checking interface compliance, required metadata fields, evidence type declarations
- [X] T115 [US5] Implement tester-specific validation: verify safety classification is declared, cleanup procedures exist for non-safe classifications, environment scope declared
- [X] T116 [US5] Fail module loading if tester has no safety classification (per FR-020); log clear error message

### CLI Integration

- [X] T117 [US5] Implement `ocean modules list` command in internal/cli/modules.go: show table of modules with ID, version, type, source system, safety classification (testers)
- [X] T118 [US5] Implement `ocean modules list --type tester` filtering
- [X] T119 [US5] Implement `ocean module validate <module_id>` command in internal/cli/modules.go: run validation and report pass/fail with details

### Schema Validation for Custom Modules

- [X] T120 [US5] Implement output schema validation in internal/module/validation.go: after collection/test, validate produced evidence against evidence.schema.json

**Checkpoint**: `ocean modules list` shows all modules with type and safety info; `ocean module validate mock.test` passes; module without safety classification fails to load with clear error

---

## Phase 10: User Story 4 — Scheduled Collection and Testing (Priority: P2)

**Goal**: Cron-style automated collection and testing with safety-aware scheduling

**Independent Test**: Schedule runs collector and safe tester at configured interval; `ocean schedule status` shows next run and results

### Scheduler Core

- [X] T121 [US4] Implement cron scheduler in internal/scheduler/cron.go using robfig/cron: Add(), Remove(), List() schedules
- [X] T122 [US4] Implement job runner in internal/scheduler/runner.go: execute configured modules (collectors + authorized testers) per schedule, store results
- [X] T123 [US4] Implement safety-aware scheduling in internal/scheduler/runner.go: enforce safety_authorization.max_safety_level, refuse destructive tests in scheduled mode, respect environment_scope

### State Persistence

- [X] T124 [US4] Create migration in internal/storage/migrations/002_schedules.sql: schedule table, schedule_run_history table
- [X] T125 [US4] Implement schedule CRUD in internal/storage/sqlite.go: StoreSchedule(), GetSchedule(), ListSchedules(), DeleteSchedule()
- [X] T126 [US4] Implement schedule state persistence: last_run, next_run, enabled flag survive restarts

### Failure Handling

- [X] T127 [US4] Implement failure alerting in internal/scheduler/runner.go: log failures, continue with remaining modules, configurable webhook notification
- [X] T128 [US4] Implement catch-up execution: when system was offline during scheduled time, execute missed run on restart (configurable)

### CLI Integration

- [X] T129 [US4] Implement `ocean schedule add` command in internal/cli/schedule.go: --cron, --control, --modules, --safety-authorization flags
- [X] T130 [US4] Implement `ocean schedule list` command in internal/cli/schedule.go: show all schedules with next run time and safety info
- [X] T131 [US4] Implement `ocean schedule remove` command in internal/cli/schedule.go
- [X] T132 [US4] Implement `ocean schedule status` command in internal/cli/schedule.go: show last run, next run, recent results, safety classifications

**Checkpoint**: Schedule runs mock collector + mock safe tester at configured interval; `ocean schedule status` shows results; destructive tests refuse to schedule

---

## Phase 11: User Story 9 — Verify Evidence Provenance (Priority: P2)

**Goal**: Full attestation chain verification with tamper detection and third-party verification support

**Independent Test**: `ocean verify-provenance --evidence <id>` validates Collection and Evaluation attestation chain; tampered evidence detected

### Attestation Verification

- [X] T133 [US9] Implement DSSE envelope verification in internal/attestation/verifier.go: VerifyEnvelope(envelope, publicKey) verifying signature(s) against payload
- [X] T134 [US9] Implement content digest verification in internal/attestation/verifier.go: VerifyDigest(data, expectedDigest) comparing SHA-256 of data against attestation subject digest
- [X] T135 [US9] Implement Collection Attestation chain verification in internal/attestation/verifier.go: verify evidence content → digest match → envelope signature → signer identity
- [X] T136 [US9] Implement Evaluation Attestation chain verification in internal/attestation/verifier.go: verify evidence input digests → expression digest → verdict → envelope signature

### Full Chain Verification

- [X] T137 [US9] Implement full provenance chain verification in internal/attestation/verifier.go VerifyProvenanceChain(evidenceID): Collection Attestation → Evaluation Attestation (if exists), report each step pass/fail
- [X] T138 [US9] Implement tamper detection: when evidence content digest doesn't match attestation, report "evidence content does not match attestation digest"
- [X] T139 [US9] Implement test transcript verification: for active test evidence, verify transcript digest in Collection Attestation matches actual transcript content

### Third-Party Verification

- [X] T140 [US9] Implement public key export in internal/attestation/signer.go: ExportPublicKey(path) for sharing with third parties
- [X] T141 [US9] Implement standalone verification: VerifyWithPublicKey(attestationChainJSON, publicKeyPath) — third party can validate without OCEAN installation context

### CLI Integration

- [X] T142 [US9] Implement `ocean verify-provenance --evidence <id>` command in internal/cli/provenance.go: load evidence, load attestations, run chain verification, display step-by-step results (Collection Attestation valid, Evaluation Attestation valid, digests match, expression version)
- [X] T143 [US9] Implement `ocean verify-provenance --export <id>` to export attestation chain + public key for third-party verification

**Checkpoint**: `ocean verify-provenance --evidence <id>` validates chain; manually modifying stored evidence triggers tamper detection; third-party can verify with exported chain

---

## Phase 12: User Story 7 — REST API for External Systems (Priority: P3)

**Goal**: HTTP server mode exposing evidence, controls, and attestations via REST API per contracts/api.yaml

**Independent Test**: `ocean serve` starts server; GET `/api/v1/evidence` returns paginated evidence with attestations

### HTTP Server

- [X] T144 [US7] Implement HTTP server setup in internal/api/server.go: net/http with configurable port, graceful shutdown
- [X] T145 [US7] Implement Bearer token authentication middleware in internal/api/middleware.go
- [X] T146 [US7] Implement request logging middleware in internal/api/middleware.go using zerolog
- [X] T147 [US7] Implement error response helper in internal/api/handlers.go: ErrorResponse JSON format per contracts/api.yaml

### Evidence Endpoints

- [X] T148 [US7] Implement GET /api/v1/evidence handler in internal/api/handlers.go: query params (control_id, source, from_time, to_time, min_confidence, cursor, limit), cursor-based pagination
- [X] T149 [US7] Implement GET /api/v1/evidence/{id} handler in internal/api/handlers.go: return full evidence with attestation ref
- [X] T150 [US7] Implement GET /api/v1/evidence/{id}/provenance handler in internal/api/handlers.go: return ProvenanceChain (collection + evaluation attestations)

### Control Endpoints

- [X] T151 [US7] Implement GET /api/v1/controls handler in internal/api/handlers.go: list all control definitions
- [X] T152 [US7] Implement GET /api/v1/controls/{id} handler in internal/api/handlers.go: single control definition
- [X] T153 [US7] Implement GET /api/v1/controls/{id}/status handler in internal/api/handlers.go: latest ControlStatus with confidence
- [X] T154 [US7] Implement GET /api/v1/controls/{id}/history handler in internal/api/handlers.go: time-series with uptime_pct and bucketed data, granularity parameter

### Other Endpoints

- [X] T155 [P] [US7] Implement GET /api/v1/attestations/{id} handler in internal/api/handlers.go: return full DSSE envelope
- [X] T156 [P] [US7] Implement GET /api/v1/modules handler in internal/api/handlers.go: list modules with type and safety classification
- [X] T157 [P] [US7] Implement GET /api/v1/health handler in internal/api/handlers.go: status, version, storage health

### CLI Integration

- [X] T158 [US7] Implement `ocean serve` CLI command in internal/cli/serve.go: --port, --auth-token flags; start HTTP server with all routes mounted

**Checkpoint**: `ocean serve` starts; `curl localhost:8080/api/v1/evidence` returns paginated evidence; `?min_confidence=active_verification` filters correctly; auth required on all endpoints except /health

---

## Phase 13: User Story 6 — Compliance Reports (Priority: P3)

**Goal**: Human-readable compliance reports distinguishing passive and active evidence with optional provenance verification

**Independent Test**: `ocean report --format markdown --period 2026-01-01:2026-06-30` generates readable report with control summaries

### Report Generation

- [X] T159 [US6] Implement Markdown report generator in internal/cli/report.go: control status summaries, per-control breakdown, passive vs active evidence distinguished, failure prominence
- [X] T160 [US6] Implement CSV export in internal/cli/report.go: tabular evidence export for spreadsheet analysis
- [X] T161 [US6] Implement report provenance verification with --verify-provenance flag: validate each evidence record's attestation chain, include verification status in report
- [X] T162 [US6] Implement active test transcript summaries in reports: for each active test evidence, show what was tested and what was observed

### Report Formatting

- [X] T163 [US6] Implement data quality disclaimers: when evidence is sparse, include gaps analysis and coverage percentage
- [X] T164 [US6] Implement failure prominence: failures displayed prominently per Radical Transparency principle, not hidden or minimized

### CLI Integration

- [X] T165 [US6] Wire `ocean report` CLI command: --format (markdown|csv), --period, --control, --verify-provenance flags

**Checkpoint**: `ocean report --format markdown --verify-provenance` generates complete report distinguishing passive and active evidence, showing failures prominently, with verified provenance status

---

## Phase 14: Real-World Modules (US1, US5, US8 complete)

**Goal**: First real-world integrations replacing mock modules

**Independent Test**: `ocean collect okta.mfa_policy` returns real evidence; `ocean test okta.mfa_bypass` records real MFA bypass attempt

### Secret Provider Enhancement

- [X] T166 [P] Implement HashiCorp Vault secret provider in internal/secrets/vault.go: VaultSecretProvider with path-based secret retrieval
- [X] T167 [P] Implement AWS Secrets Manager provider in internal/secrets/aws.go: AWSSecretProvider with secret name lookup

### Okta Modules

- [X] T168 [P] Implement Okta base client in modules/collectors/okta/collector.go: HTTP client with rate limiting, auth, error handling for Okta API
- [X] T169 Implement Okta MFA policy collector in modules/collectors/okta/mfa.go: GET /api/v1/policies?type=MFA_ENROLL, normalize to Evidence schema with findings for policy gaps
- [X] T170 Implement Okta MFA bypass tester in modules/testers/okta/mfa_bypass.go: safety=safe, attempt POST /api/v1/authn without MFA token, record 401 response in transcript

### AWS Modules

- [X] T171 [P] Implement AWS base client in modules/collectors/aws/collector.go: AWS SDK credential chain, rate limiting
- [X] T172 Implement AWS IAM collector in modules/collectors/aws/iam.go: ListUsers + GetUser MFA status, access key age, normalize to Evidence schema
- [X] T173 Implement AWS public access tester in modules/testers/aws/public_access.go: safety=safe, attempt unauthenticated S3 GetObject, record response in transcript

### GitHub Modules

- [X] T174 [P] Implement GitHub base client in modules/collectors/github/collector.go: GitHub API v4 (GraphQL) with rate limiting
- [X] T175 Implement GitHub branch protection collector in modules/collectors/github/branch_protection.go: query branch protection rules, normalize to Evidence schema
- [X] T176 Implement GitHub secret push tester in modules/testers/github/secret_push.go: safety=observable, attempt to push test secret string via API, record whether push-protection blocks it, document audit trail impact in pre-flight

### Module Registration

- [X] T177 Register all real modules in internal/module/registry.go: okta.mfa_policy, aws.iam, github.branch_protection, okta.mfa_bypass, aws.public_access, github.secret_push

**Checkpoint**: Real collectors return actual evidence from live APIs; real testers execute safely with proper transcripts; `ocean modules list` shows all modules with correct safety classifications

---

## Phase 15: Polish & Cross-Cutting Concerns

**Purpose**: Production readiness, documentation, distribution, and performance

### Framework Mappings

- [X] T178 [P] Create default control library in controls/iam/mfa_enforcement.yaml: real control definition with CEL expression, mapped to SOC2 CC6.1, ISO27001 A.9.4.2, NIST CSF PR.AC-7, CIS Controls
- [X] T179 [P] Create WAF protection control in controls/network/waf_protection.yaml: composite control definition
- [X] T180 [P] Implement framework mapping loader in internal/control/framework.go: load framework definitions from embedded YAML

### Documentation

- [X] T181 [P] Write module development guide in docs/modules.md: how to create collectors and testers, interface requirements, safety classification guide, example module walkthrough
- [X] T182 [P] Write API documentation in docs/api.md: reference to contracts/api.yaml, authentication, examples
- [X] T183 [P] Update docs/quickstart.md with real commands and expected output
- [X] T184 [P] Write README.md: project overview, installation, quickstart, architecture diagram, contributing guide

### Distribution

- [X] T185 [P] Create cross-platform build targets in Makefile: windows/amd64, darwin/amd64, darwin/arm64, linux/amd64, linux/arm64
- [X] T186 [P] Update Dockerfile for production: multi-stage build, scratch base, labels, health check
- [X] T187 [P] Create Homebrew formula template in dist/homebrew/ocean.rb

### Public Library API

- [X] T188 Implement public client API in pkg/ocean/client.go: NewClient(config), Collect(), Test(), Verify(), Evaluate(), History() for embedding in GRC platforms
- [X] T189 Implement public schema types in pkg/schema/evidence.go and pkg/schema/control.go: exported types mirroring internal types for library consumers

### Performance & Security

- [X] T190 Implement evidence retention policy in internal/storage/sqlite.go: configurable max age, prune old evidence while preserving attestation chain validity
- [X] T191 Implement evidence redaction in internal/evidence/schema.go: RedactEvidence(evidence, config) with PII masking, resource ID hashing, configurable field removal
- [X] T192 Implement CEL expression complexity limits in internal/eval/cel.go: maximum AST depth, reject overly complex expressions
- [X] T193 Run quickstart.md validation: execute all quickstart commands against mock modules, verify output matches documentation

---

## Dependencies & Execution Order

### Phase Dependencies

```
Phase 1: Setup ──────────────┐
                              ▼
Phase 2: Foundational ───────┐
         (BLOCKS ALL)        │
                              ▼
Phase 3: US1 (Collect) ──────┐
                              ▼
Phase 4: US2 (History) ──────┐
                              ▼
Phase 5: US8 (Test) ─────────┤── These can start after US2
                              ▼   (need storage)
Phase 6: US11 (Dual-Mode) ──┤── Needs US1 + US8
                              │
                              ├── Phase 7: US10 (CEL) ──── Needs US11 evaluator
                              │
                              ├── Phase 8: US3 (Composite) ── Needs US10 CEL engine
                              │
                              ├── Phase 9: US5 (Custom Modules) ── Can start after US1
                              │
                              ├── Phase 10: US4 (Schedule) ── Needs US1 + US8
                              │
                              ├── Phase 11: US9 (Provenance) ── Needs US10 eval attestation
                              │
                              ├── Phase 12: US7 (API) ── Needs US2 storage
                              │
                              └── Phase 13: US6 (Reports) ── Needs US2 history

Phase 14: Real Modules ────── Needs Phases 3-9 complete
Phase 15: Polish ─────────── Needs all user stories complete
```

### User Story Dependencies

- **US1 (P1)**: Foundational only — first story to implement
- **US2 (P1)**: Depends on US1 (needs evidence to store)
- **US8 (P1)**: Depends on US2 (needs storage for test evidence)
- **US11 (P1)**: Depends on US1 + US8 (orchestrates both modes)
- **US10 (P2)**: Depends on US11 (needs evaluator to add CEL)
- **US3 (P2)**: Depends on US10 (needs CEL for composite evaluation)
- **US5 (P2)**: Can start after US1 (module validation, listing)
- **US4 (P2)**: Depends on US1 + US8 (schedules both modes)
- **US9 (P2)**: Depends on US10 (needs Evaluation Attestation for full chain)
- **US7 (P3)**: Depends on US2 (needs storage layer for queries)
- **US6 (P3)**: Depends on US2 (needs history for reports)

### Within Each User Story

- Types/models before services
- Services before CLI commands
- Core implementation before integration
- Story complete before moving to next priority

### Parallel Opportunities

- All T009-T020 (core types) can run in parallel
- All T021-T023 (module interfaces) can run in parallel
- All T032-T035 (JSON schemas) can run in parallel
- Within each user story, tasks marked [P] can run in parallel
- US5 (Custom Modules) and US4 (Schedule) can develop in parallel once their prerequisites are met
- US7 (API) and US6 (Reports) can develop in parallel
- All real-world modules (T168-T176) can develop in parallel per source system
- All Phase 15 documentation tasks can run in parallel

---

## Parallel Example: Foundational Phase

```bash
# Launch all core types in parallel (T009-T020):
Task: "Define Evidence struct in internal/evidence/schema.go"
Task: "Define TestTranscript struct in internal/evidence/transcript.go"
Task: "Define Control struct in internal/control/definition.go"
Task: "Define SafetyClassification enum in internal/module/safety.go"
# ... (all independent, different files)

# Launch all JSON schemas in parallel (T032-T035):
Task: "Create evidence.schema.json in schemas/"
Task: "Create control.schema.json in schemas/"
Task: "Create module.schema.json in schemas/"
Task: "Create attestation.schema.json in schemas/"
```

## Parallel Example: Real-World Modules

```bash
# Launch all base clients in parallel (different source systems):
Task: "Implement Okta base client in modules/collectors/okta/collector.go"
Task: "Implement AWS base client in modules/collectors/aws/collector.go"
Task: "Implement GitHub base client in modules/collectors/github/collector.go"

# Then launch specific modules per system in parallel:
Task: "Implement Okta MFA policy collector"
Task: "Implement AWS IAM collector"
Task: "Implement GitHub branch protection collector"
```

---

## Implementation Strategy

### MVP First (P1 Stories: US1 + US2 + US8 + US11)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational (CRITICAL — blocks all stories)
3. Complete Phase 3: US1 (Collect) — first working command
4. Complete Phase 4: US2 (History) — persistent storage
5. Complete Phase 5: US8 (Test) — active testing
6. Complete Phase 6: US11 (Dual-Mode) — the "wow" feature
7. **STOP and VALIDATE**: All P1 stories independently testable with mock modules

### Incremental Delivery

1. Setup + Foundational → Foundation ready
2. US1 → `ocean collect mock.test` works → Demo (passive collection)
3. US2 → `ocean history` works → Demo (historical queries)
4. US8 → `ocean test mock.safety_test` works → Demo (active testing)
5. US11 → `ocean verify control.mock_mfa` works → Demo (dual-mode MVP!)
6. US10 → CEL evaluation → Demo (custom evaluation)
7. US3 → Composite controls → Demo (multi-source)
8. US4 + US5 → Scheduling + extensibility → Demo (automation)
9. US9 → Provenance verification → Demo (audit capability)
10. US7 + US6 → API + Reports → Demo (integration + output)
11. Real modules → Production-ready integrations
12. Polish → Release candidate

### Task Count Summary

| Phase | Description | Tasks |
|-------|-------------|-------|
| Phase 1 | Setup | 8 |
| Phase 2 | Foundational | 33 |
| Phase 3 | US1 - Collect (P1) | 13 |
| Phase 4 | US2 - History (P1) | 13 |
| Phase 5 | US8 - Active Test (P1) | 12 |
| Phase 6 | US11 - Dual-Mode (P1) | 10 |
| Phase 7 | US10 - CEL Eval (P2) | 15 |
| Phase 8 | US3 - Composite (P2) | 7 |
| Phase 9 | US5 - Custom Modules (P2) | 9 |
| Phase 10 | US4 - Schedule (P2) | 12 |
| Phase 11 | US9 - Provenance (P2) | 11 |
| Phase 12 | US7 - API (P3) | 15 |
| Phase 13 | US6 - Reports (P3) | 7 |
| Phase 14 | Real Modules | 12 |
| Phase 15 | Polish | 16 |
| **TOTAL** | | **193** |

---

## Notes

- [P] tasks = different files, no dependencies on incomplete tasks
- [Story] label maps task to specific user story for traceability
- Each user story is independently completable and testable at its checkpoint
- Commit after each task or logical group
- Stop at any checkpoint to validate story independently
- Mock modules enable full development without external API access
- Real modules (Phase 14) can be added incrementally per source system
- All tasks include exact file paths per plan.md project structure
