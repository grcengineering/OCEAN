# Feature Specification: OCEAN Core

**Feature Branch**: `main`
**Created**: 2026-01-17
**Updated**: 2026-02-12
**Status**: Draft
**Constitution Reference**: `.specify/memory/constitution.md` v2.0.0

## Executive Summary

OCEAN (Open Control Evidence Assessment Normalizer) is the **"Metasploit for GRC"** — an open-source CLI tool and Go library for evidence acquisition, active control testing, and normalization powering continuous compliance monitoring. It serves as the backend for a **"StatusPage for Compliance"** — a radically transparent, shareable dashboard showing historical control operating effectiveness metrics.

OCEAN operates across four pillars:

1. **Passive Control Monitoring** — Query system APIs to observe configuration state, store as evidence, and evaluate against compliance conditions
2. **Active Control Testing** — Attempt what controls should prevent (like Atomic Red Team but for any compliance control) and record whether the control blocked it
3. **Flexible Evaluation Logic** — User-defined compliance conditions using CEL expressions alongside structured YAML presets
4. **Cryptographic Provenance** — Tamper-resistant proof chain using in-toto DSSE attestations proving exactly what was collected, tested, evaluated, and concluded

OCEAN is **NOT** a full GRC platform. It is the specialized evidence and verification layer that GRC platforms consume.

## User Scenarios & Testing

### User Story 1 - Collect Evidence for a Single Control (Priority: P1) 🎯 MVP

A GRC practitioner wants to verify that MFA is enforced for all users in their Okta tenant. They run OCEAN with the Okta collector module to passively gather MFA policy evidence, which is normalized, signed, and stored with full provenance.

**Why this priority**: This is the fundamental operation — passively collecting evidence from a source system. Everything else builds on this capability.

**Independent Test**: Can be fully tested by running `ocean collect okta.mfa_policy` with valid credentials and receiving structured, signed evidence output with a collection attestation.

**Acceptance Scenarios**:

1. **Given** valid Okta API credentials configured, **When** user runs `ocean collect okta.mfa_policy`, **Then** system outputs JSON evidence containing MFA policy configuration for all users, normalized to the OCEAN Evidence Schema
2. **Given** invalid credentials, **When** user runs `ocean collect okta.mfa_policy`, **Then** system returns clear error message with remediation guidance (e.g., "check API token permissions")
3. **Given** valid credentials but rate limited, **When** user runs `ocean collect`, **Then** system implements backoff and retries, logging progress
4. **Given** successful collection, **When** evidence is stored, **Then** evidence includes provenance metadata (timestamp, collector version, source system, query parameters) and a signed Collection Attestation (in-toto DSSE envelope)
5. **Given** successful collection, **When** evidence is returned, **Then** `confidence_level` is set to `passive_observation`

---

### User Story 2 - Store and Query Historical Evidence (Priority: P1) 🎯 MVP

A compliance analyst wants to verify that a control was effective throughout the audit period (last 180 days). They query OCEAN's evidence store to retrieve historical data, calculate uptime metrics, and identify any gaps or failures.

**Why this priority**: Historical evidence is essential for proving continuous effectiveness — the core differentiator from point-in-time audit tools. This enables the "StatusPage for Compliance" vision.

**Independent Test**: Can be tested by storing evidence over time and querying `ocean history --control mfa.enforcement --days 180`.

**Acceptance Scenarios**:

1. **Given** evidence has been collected daily for 180 days, **When** user runs `ocean history --control mfa.enforcement --days 180`, **Then** system returns time-series data showing daily status
2. **Given** historical data exists, **When** user requests uptime calculation, **Then** system returns percentage (e.g., "99.94% effective over 180 days")
3. **Given** gaps in collection, **When** user queries history, **Then** gaps are clearly indicated in output (not interpolated or hidden)
4. **Given** historical query, **When** output requested in JSON format, **Then** evidence includes original provenance from collection time (not query time)
5. **Given** evidence from both collectors and testers exists, **When** history is queried, **Then** both evidence types are included with their respective `confidence_level` values

---

### User Story 8 - Run an Active Control Test (Priority: P1) 🎯 MVP

A security engineer wants to prove that their organization's MFA enforcement actually works — not just that the policy exists. They run an active test that attempts to authenticate without MFA and verifies the attempt is blocked.

**Why this priority**: This is the core "Metasploit for GRC" differentiator. Passive observation proves policy exists; active testing proves it works. This is the dual-mode value proposition.

**Independent Test**: Can be fully tested by running `ocean test okta.mfa_bypass --target staging` and verifying the test transcript shows the attempt was blocked.

**Acceptance Scenarios**:

1. **Given** a tester module `okta.mfa_bypass` with safety classification `safe`, **When** user runs `ocean test okta.mfa_bypass --target staging`, **Then** system executes pre-flight validation, attempts authentication without MFA, records whether it was blocked, and outputs a test transcript
2. **Given** a tester classified as `observable`, **When** user runs the test, **Then** system prompts for explicit authorization before execution, citing the safety classification and expected audit trail impact
3. **Given** a tester classified as `reversible`, **When** user runs the test, **Then** system executes the test, automatically reverses state changes (e.g., deletes test resources), and documents cleanup actions in the transcript
4. **Given** a tester classified as `destructive`, **When** user runs the test, **Then** system requires explicit confirmation with a warning describing potential permanent changes and manual cleanup needed
5. **Given** successful active test execution, **When** evidence is stored, **Then** `confidence_level` is set to `active_verification` and the full test transcript (what was attempted, what was observed, what was cleaned up) is preserved
6. **Given** a test targeting a production environment, **When** the tester's environment scoping declares `staging-only`, **Then** the system refuses to execute and returns an error explaining the scope restriction
7. **Given** pre-flight validation fails (e.g., cleanup rollback not available), **When** test execution is requested, **Then** system aborts before any test action and reports what prerequisite failed

---

### User Story 11 - Dual-Mode Control Verification (Priority: P1) 🎯 MVP

A compliance lead wants comprehensive assurance that their MFA control is effective. They run both a passive collector (to verify the policy configuration exists) and an active tester (to verify the policy actually blocks unauthorized access), then see a unified control status with both evidence types.

**Why this priority**: This is the complete dual-mode value proposition — combining passive and active evidence for the highest confidence assessment. It demonstrates why OCEAN is "Metasploit for GRC" and not just another configuration scanner.

**Independent Test**: Can be tested by running `ocean verify control.mfa_enforcement` which triggers both collection and testing, then displays unified results.

**Acceptance Scenarios**:

1. **Given** a control definition that references both a collector (`okta.mfa_policy`) and a tester (`okta.mfa_bypass`), **When** user runs `ocean verify control.mfa_enforcement`, **Then** system executes both the collector and tester, stores both evidence records, and displays a unified control status
2. **Given** passive evidence shows policy is configured correctly AND active test shows bypass was blocked, **When** evaluation runs, **Then** control status is `effective` with confidence `high` (both passive and active evidence agree)
3. **Given** passive evidence shows policy is configured correctly BUT active test shows bypass succeeded, **When** evaluation runs, **Then** control status is `ineffective` with the active test result taking precedence for the behavioral assertion, and the discrepancy is highlighted
4. **Given** only passive evidence exists (no tester module available), **When** evaluation runs, **Then** control status is reported with confidence `medium` (passive-only) and a note indicating active verification is available/recommended
5. **Given** active test is available but user hasn't authorized it, **When** `ocean verify` runs, **Then** system collects passive evidence, notes that active test was skipped due to missing authorization, and reports passive-only confidence

---

### User Story 3 - Define Multi-Source Composite Control (Priority: P2)

A security engineer wants to verify their WAF control is fully implemented. This requires passive evidence from Cloudflare (WAF rules), DNS (Cloudflare proxy enabled), and AWS (Security Groups only allow Cloudflare IPs), plus optionally an active test that attempts direct server access bypassing the WAF.

**Why this priority**: Real-world controls span multiple systems. Composite control support differentiates OCEAN from single-source tools.

**Independent Test**: Can be tested by defining a control YAML that aggregates evidence from 3 collectors and optionally 1 tester, then running `ocean verify control.waf_protection`.

**Acceptance Scenarios**:

1. **Given** a composite control definition with 3 evidence sources and 1 tester, **When** user runs `ocean verify control.waf_protection`, **Then** system collects from all sources, runs authorized tests, and aggregates status
2. **Given** one source returns "effective" and one returns "ineffective", **When** evaluation runs, **Then** overall control status is "ineffective" with breakdown showing which component failed
3. **Given** one source is unreachable, **When** evaluation runs, **Then** status is "unknown" (not assumed effective or ineffective) with error details
4. **Given** successful evaluation, **When** output generated, **Then** each component's evidence is linked with full provenance and its own attestation

---

### User Story 4 - Schedule Recurring Collection and Testing (Priority: P2)

An operations team wants OCEAN to automatically collect evidence and run safe/observable active tests for all controls on a configurable schedule, storing results for historical trending.

**Why this priority**: Continuous monitoring requires automation. Manual collection and testing don't scale.

**Independent Test**: Can be tested by configuring a schedule and verifying evidence appears in store at expected intervals.

**Acceptance Scenarios**:

1. **Given** a schedule configured for daily collection at 02:00 UTC, **When** 02:00 UTC occurs, **Then** all configured collectors execute and store evidence with signed attestations
2. **Given** an active test marked `safe` in the schedule, **When** scheduled time occurs, **Then** test runs automatically with pre-configured authorization
3. **Given** an active test marked `reversible` in the schedule, **When** scheduled time occurs, **Then** test requires pre-authorized approval (configured at schedule creation time) and respects environment scoping
4. **Given** a collector fails during scheduled run, **When** run completes, **Then** failure is logged with details, other collectors continue, and alert is generated
5. **Given** schedule is running, **When** user queries `ocean schedule status`, **Then** system shows last run time, next run time, recent results, and safety classification of any scheduled tests
6. **Given** system was offline during scheduled time, **When** system comes back online, **Then** missed collection is executed immediately (configurable catch-up behavior)

---

### User Story 5 - Extend OCEAN with Custom Modules (Priority: P2)

A developer wants to add support for their organization's custom internal tool. They create either a collector module (passive evidence gathering), a tester module (active control verification), or a dual-mode module implementing both interfaces.

**Why this priority**: Extensibility is core to the Metasploit-style architecture. Without it, OCEAN is limited to built-in integrations.

**Independent Test**: Can be tested by creating a minimal collector or tester module and running `ocean collect custom.my_tool` or `ocean test custom.my_control`.

**Acceptance Scenarios**:

1. **Given** a collector module following the Collector interface, **When** module is placed in the modules directory, **Then** `ocean modules list` shows the new collector with its capabilities
2. **Given** a tester module following the Tester interface, **When** module is placed in the modules directory, **Then** `ocean modules list` shows the new tester with its safety classification
3. **Given** a dual-mode module implementing both Collector and Tester, **When** module is loaded, **Then** system recognizes both capabilities and allows `ocean collect` and `ocean test` for that module
4. **Given** a tester module without a declared safety classification, **When** OCEAN loads modules, **Then** module loading fails with clear error requiring safety classification
5. **Given** a module, **When** developer runs `ocean module validate my_module`, **Then** system validates interface compliance, schema mapping, and (for testers) safety classification and cleanup procedures
6. **Given** a custom module produces evidence, **When** evidence is stored, **Then** evidence passes schema validation, carries proper attestation, and integrates with storage/querying

---

### User Story 9 - Verify Evidence Provenance Cryptographically (Priority: P2)

An auditor wants to independently verify that compliance evidence hasn't been tampered with. They use OCEAN's verification command to validate the cryptographic provenance chain from raw evidence through evaluation to verdict.

**Why this priority**: Cryptographic provenance transforms compliance from trust-based to verification-based. Auditors can independently prove evidence integrity without trusting the operator.

**Independent Test**: Can be tested by running `ocean verify-provenance --evidence <id>` and confirming the attestation chain validates.

**Acceptance Scenarios**:

1. **Given** stored evidence with a signed Collection Attestation, **When** user runs `ocean verify-provenance --evidence <id>`, **Then** system validates the DSSE envelope signature, confirms content-addressable digests match, and reports "provenance valid"
2. **Given** an evaluation verdict referencing evidence, **When** user verifies the Evaluation Attestation, **Then** system confirms the exact CEL/YAML logic version used, the evidence inputs referenced by digest, and the resulting verdict
3. **Given** someone tampers with stored evidence (modifies raw_data), **When** provenance verification runs, **Then** digest mismatch is detected and reported: "evidence content does not match attestation digest"
4. **Given** a third party with only the public key and attestation chain, **When** they run verification, **Then** they can independently validate any verdict without trusting the OCEAN operator
5. **Given** evidence collected by an active test, **When** provenance is verified, **Then** the test transcript (actions attempted, system responses, cleanup actions) is included in the verified attestation chain

---

### User Story 10 - Define Custom Evaluation Logic Using CEL (Priority: P2)

A compliance engineer wants to define custom compliance conditions for their controls beyond the built-in YAML presets. They write CEL expressions that evaluate evidence against organization-specific requirements.

**Why this priority**: Different organizations have different compliance requirements. CEL provides a safe, non-Turing-complete way to express arbitrary compliance conditions without modifying OCEAN's code.

**Independent Test**: Can be tested by writing a CEL expression in a control definition and running `ocean evaluate control.custom_mfa`.

**Acceptance Scenarios**:

1. **Given** a control definition with a CEL expression `evidence.mfa_policy.enforcement == "required" && evidence.mfa_policy.user_exceptions.size() == 0`, **When** user runs `ocean evaluate control.custom_mfa`, **Then** system evaluates the expression against collected evidence and returns the boolean result
2. **Given** a CEL expression with a syntax error, **When** control is loaded, **Then** system reports the parsing error with line/column position before any evaluation occurs
3. **Given** a CEL expression that references fields not present in the evidence, **When** evaluation runs, **Then** system returns `unknown` status with a clear message about missing data (not a crash or false positive)
4. **Given** a YAML preset for a common pattern (e.g., `preset: all_users_mfa_enforced`), **When** evaluation runs, **Then** preset expands to the equivalent CEL expression and evaluates identically
5. **Given** a CEL expression used in an evaluation, **When** the evaluation attestation is created, **Then** the exact expression version is content-addressed and stored so the same logic can be reproduced for any historical evaluation
6. **Given** a user updates a CEL expression, **When** re-evaluation runs, **Then** new evaluation uses the new expression version while historical evaluations remain linked to the expression version that produced them

---

### User Story 6 - Generate Compliance Report (Priority: P3)

An auditor wants a human-readable report showing control effectiveness over the audit period, including both passive and active evidence, provenance verification status, and suitability for audit documentation.

**Why this priority**: While evidence is machine-first, human-readable output is needed for audit workflows. Lower priority than core collection and testing.

**Independent Test**: Can be tested by running `ocean report --format markdown --period 2025-01-01:2025-12-31`.

**Acceptance Scenarios**:

1. **Given** historical evidence for controls (both passive and active), **When** user runs `ocean report --format markdown`, **Then** system generates readable report with control status summaries, distinguishing passive observations from active test results
2. **Given** controls with failures, **When** report generated, **Then** failures are prominently displayed (not hidden or minimized) per the Radical Transparency principle
3. **Given** active tests were run, **When** report generated, **Then** report includes test transcript summaries showing what was tested and what was observed
4. **Given** report request, **When** evidence is sparse, **Then** report includes data quality disclaimers and gaps analysis
5. **Given** report request with `--verify-provenance` flag, **When** report generated, **Then** each evidence record's provenance chain is validated and verification status is included in the report

---

### User Story 7 - Export Evidence for External Systems (Priority: P3)

A GRC platform wants to consume OCEAN evidence via API to display in their compliance dashboard, including provenance attestations for independent verification.

**Why this priority**: OCEAN's value multiplies when integrated with GRC platforms, but core functionality comes first.

**Independent Test**: Can be tested by running OCEAN in server mode and querying `/api/v1/evidence` endpoint.

**Acceptance Scenarios**:

1. **Given** OCEAN running in server mode, **When** external system calls GET `/api/v1/evidence?control=mfa`, **Then** system returns JSON evidence array with provenance attestations
2. **Given** API request, **When** authentication is invalid, **Then** system returns 401 with clear error
3. **Given** evidence query, **When** pagination requested, **Then** system supports cursor-based pagination for large result sets
4. **Given** external system requests attestation chains, **When** API returns evidence, **Then** each evidence record includes its DSSE-envelope attestation for independent verification by the consumer
5. **Given** evidence with `confidence_level` field, **When** API query includes `?min_confidence=active_verification`, **Then** only active test evidence is returned

---

### Edge Cases

- **API Schema Changes**: When a collector's target API schema changes, version mismatch is detected and collection degrades gracefully with warnings. The collector declares its supported API versions.
- **Clock Skew**: Both local and remote timestamps are recorded where available. Evidence time is normalized to UTC.
- **Storage Full**: Configurable retention policy — oldest evidence pruned with warning, or collection paused. Attestation chain remains valid for retained evidence.
- **Concurrent Collection**: Deduplication based on timestamp + source. Last-write-wins with full history preserved.
- **Credential Rotation**: Retry with fresh credential fetch from secret provider. Clear error if rotation is in progress.
- **Partial API Responses**: Evidence marked as incomplete with partial data. Attestation notes incomplete collection.
- **Active Test Cleanup Failure**: If post-test cleanup fails, system alerts the operator immediately, logs the failure in the test transcript, and marks the test evidence with a cleanup warning. Cleanup failure does NOT invalidate the test result — it's a separate operational concern.
- **Key Rotation for Signing**: When signing keys are rotated, old attestations remain verifiable with old public keys. Key metadata in attestation identifies which key was used.
- **CEL Expression Timeout**: CEL is non-Turing-complete so expressions terminate, but evaluation has a configurable maximum complexity limit to prevent resource abuse.
- **Mixed Safety Classifications in Composite Controls**: When a composite control includes testers with different safety classifications, the overall authorization requirement is the highest (most restrictive) classification among all included testers.

## Requirements

### Functional Requirements - Core

- **FR-001**: System MUST collect evidence from configured source systems via their APIs (passive collection)
- **FR-002**: System MUST normalize all evidence to the OCEAN Evidence Schema
- **FR-003**: System MUST attach provenance metadata to all evidence (source, timestamp, module version, query parameters)
- **FR-004**: System MUST store evidence in local storage (SQLite by default)
- **FR-005**: System MUST support querying historical evidence by control, time range, source, and confidence level
- **FR-006**: System MUST calculate control effectiveness percentage from historical data (uptime metrics)
- **FR-007**: System MUST distinguish between `passive_observation` and `active_verification` confidence levels on all evidence

### Functional Requirements - Modules

- **FR-010**: System MUST support pluggable Collector modules (passive evidence gathering) loaded at runtime
- **FR-011**: System MUST support pluggable Tester modules (active control verification) loaded at runtime
- **FR-012**: Collectors MUST implement the standard Collector interface (metadata, collection logic, schema mapping, credential requirements, rate limiting)
- **FR-013**: Testers MUST implement the standard Tester interface (metadata, test logic, schema mapping, credential requirements, safety classification, pre-flight validation, cleanup procedures)
- **FR-014**: A single module MAY implement both Collector and Tester interfaces (dual-mode)
- **FR-015**: System MUST validate module output against Evidence Schema before storage
- **FR-016**: System MUST handle module failures gracefully without crashing
- **FR-017**: Modules MUST declare their capabilities and evidence types they produce

### Functional Requirements - Active Testing

- **FR-020**: All Tester modules MUST declare a Safety Classification: `safe`, `observable`, `reversible`, or `destructive`
- **FR-021**: Active tests MUST implement pre-flight validation (target scope, authorization, rollback readiness)
- **FR-022**: Active tests MUST implement post-execution cleanup procedures
- **FR-023**: System MUST NOT execute active tests without explicit authorization appropriate to the safety level
- **FR-024**: System MUST enforce environment scoping (production-safe, staging-only, isolated-only) declared by each tester
- **FR-025**: Active test results MUST include the full test transcript: what was attempted, what was observed, what was cleaned up
- **FR-026**: Safety-first classification: when safety level is uncertain, system MUST classify at the HIGHER risk level

### Functional Requirements - Controls & Evaluation

- **FR-030**: System MUST support control definitions that map evidence to effectiveness assertions
- **FR-031**: System MUST support composite controls aggregating multiple evidence sources (collectors and testers)
- **FR-032**: Control definitions MUST be declarative (YAML configuration with optional CEL expressions)
- **FR-033**: System MUST support framework-agnostic control mappings (SOC 2 ↔ ISO 27001 ↔ NIST CSF ↔ CIS Controls)
- **FR-034**: System MUST support user-defined evaluation logic using CEL (Common Expression Language) expressions
- **FR-035**: System MUST provide structured YAML presets for common evaluation patterns
- **FR-036**: CEL expressions MUST be content-addressed and versioned; historical evaluations MUST be reproducible with the exact logic that produced them

### Functional Requirements - Cryptographic Provenance

- **FR-040**: System MUST create signed Collection Attestations for all stored evidence (in-toto DSSE format)
- **FR-041**: System MUST create signed Evaluation Attestations for all control evaluations
- **FR-042**: Attestations MUST use content-addressable references (artifacts identified by cryptographic digest)
- **FR-043**: Signing MUST be mandatory for all stored evidence
- **FR-044**: System MUST support Ed25519 signing keys (default), KMS-backed keys (enterprise), and keyless OIDC binding (advanced)
- **FR-045**: Provenance chain MUST be independently verifiable by third parties with only the public key and attestation chain
- **FR-046**: Collection transcripts (API calls made, parameters used, responses received) MUST be preserved as content-addressed artifacts
- **FR-047**: For active tests, test transcripts MUST be captured in the collection attestation

### Functional Requirements - Scheduling

- **FR-050**: System MUST support cron-style scheduling for automated collection and testing
- **FR-051**: System MUST persist schedule state across restarts
- **FR-052**: System MUST support per-control collection/testing intervals
- **FR-053**: System MUST alert on collection or test failures (configurable notification channels)
- **FR-054**: Scheduled active tests MUST respect safety classifications and environment scoping

### Functional Requirements - Output

- **FR-060**: System MUST output evidence in JSON format
- **FR-061**: System MUST support YAML output for human readability
- **FR-062**: System MUST support Markdown report generation
- **FR-063**: System MUST support CSV export for spreadsheet analysis
- **FR-064**: Server mode MUST expose REST API for external integrations
- **FR-065**: Reports MUST distinguish passive observations from active test results

### Functional Requirements - Security

- **FR-070**: System MUST NOT store credentials in evidence records
- **FR-071**: System MUST support external secret providers (env vars, HashiCorp Vault, AWS Secrets Manager, Azure Key Vault)
- **FR-072**: System MUST support evidence redaction for sharing (PII masking, resource ID hashing)
- **FR-073**: Server mode MUST require authentication for API access
- **FR-074**: System MUST log all collection and testing activities for audit trail
- **FR-075**: Active test modules MUST undergo safety classification review

### Non-Functional Requirements

- **NFR-001**: Single binary distribution with zero runtime dependencies
- **NFR-002**: Support Windows, macOS (Intel + ARM), Linux (amd64 + arm64)
- **NFR-003**: CLI response time < 1 second for local queries on datasets < 100K records
- **NFR-004**: Memory usage < 256MB for typical workloads
- **NFR-005**: Storage efficiency: < 1KB per evidence record (compressed, excluding raw_data)
- **NFR-006**: API response time < 100ms for single-control queries

### Key Entities

- **Evidence**: A single record proving a fact about a control. Key attributes: id, control_id, source, timestamp, module_version, status, raw_data, normalized_data, provenance, confidence_level (passive_observation | active_verification), attestation_ref
- **Control**: A security/compliance requirement that can be evaluated. Key attributes: id, name, description, threat_mitigated, framework_mappings, evidence_requirements, evaluation_logic (CEL expression or YAML preset), collectors (list), testers (list)
- **Module**: Base concept for Collectors and Testers. Key attributes: id, name, version, source_system, evidence_types, credential_requirements, rate_limits
  - **Collector** (extends Module): Passive evidence gathering. Additional: collection_logic, schema_mapping
  - **Tester** (extends Module): Active control verification. Additional: safety_classification (safe|observable|reversible|destructive), environment_scope (production|staging|isolated), pre_flight_checks, cleanup_procedures, test_logic
- **ControlStatus**: Point-in-time effectiveness determination. Key attributes: control_id, timestamp, status (effective|ineffective|unknown|partial), evidence_ids, confidence (high|medium|low based on evidence types), evaluation_details
- **Schedule**: Configuration for automated collection/testing. Key attributes: id, cron_expression, modules (collectors + testers), controls, last_run, next_run, enabled, safety_authorization
- **Framework**: A compliance standard. Key attributes: id, name, version, controls (references)
- **Attestation**: Cryptographic provenance record. Key attributes: dsse_envelope, predicate_type (collection|evaluation), subject_digests, signer_identity, timestamp
  - **CollectionAttestation**: References raw API responses/test transcripts by digest
  - **EvaluationAttestation**: References input evidence by digest, evaluation logic by content-address, and resulting verdict
- **TestTranscript**: Record of active test execution. Key attributes: actions_attempted, observations, cleanup_actions, timestamps, environment_info

## Evidence Schema Overview

```yaml
# OCEAN Evidence Schema v2.0.0 (inspired by OCSF)
evidence:
  id: uuid                    # Unique evidence identifier
  class_uid: integer          # Evidence class (e.g., 1001 = IAM Policy)
  category_uid: integer       # Control domain (e.g., 1 = Identity & Access)
  activity_id: integer        # What was observed/tested (e.g., 1 = Config Check, 2 = Active Test)
  time: timestamp             # Normalized collection/test time (UTC)

  confidence_level: enum      # passive_observation | active_verification

  metadata:
    module:
      name: string
      version: semver
      type: enum              # collector | tester | dual
    source:
      system: string          # e.g., "okta", "aws", "cloudflare"
      api_version: string
      endpoint: string
    original_time: timestamp  # Source system's timestamp if different
    processed_time: timestamp # When OCEAN processed this
    safety_classification: enum  # safe | observable | reversible | destructive (testers only)

  observables:                # Key indicators extracted for search
    - type: string            # e.g., "user", "ip", "resource"
      value: string

  status_id: integer          # 0=Unknown, 1=Effective, 2=Ineffective, 99=Other
  status: string              # Human-readable status

  raw_data: object            # Original API response (preserved)
  findings: array             # Specific observations supporting status
    - title: string
      description: string
      severity_id: integer

  test_transcript:            # Active tests only
    actions_attempted: array
      - action: string
        timestamp: timestamp
        parameters: object
    observations: array
      - observation: string
        timestamp: timestamp
        expected: boolean     # Was this the expected result?
    cleanup_actions: array
      - action: string
        timestamp: timestamp
        success: boolean

  attestation:
    type: enum                # collection | evaluation
    dsse_envelope_ref: string # Content-addressable reference to DSSE envelope
    digest: string            # SHA-256 of this evidence record
    signer: string            # Key identifier

  enrichments: array          # Post-collection additions
    - type: string
      data: object
      enriched_time: timestamp
```

## Control Domain Categories

| Category UID | Domain | Example Evidence Classes |
|-------------|--------|-------------------------|
| 1 | Identity & Access Management | MFA Policy, SSO Config, User Provisioning, MFA Bypass Test |
| 2 | Network Security | WAF Rules, Firewall Config, DNS Security, WAF Bypass Test |
| 3 | Data Protection | Encryption Config, DLP Policy, Backup Status, Data Exfil Test |
| 4 | Endpoint Security | EDR Status, Patch Level, Device Compliance |
| 5 | Cloud Security | IAM Policies, Security Groups, Logging Config, Privilege Escalation Test |
| 6 | Application Security | Secret Scanning, Dependency Vulnerabilities, Code Review, Secret Push Test |
| 7 | Operations | Change Management, Incident Response, Monitoring |
| 8 | Compliance | Policy Acceptance, Training Completion, Audit Findings |

## Module Roadmap

### Phase 1 - Foundation (MVP)

**Collectors:**
- **okta** - MFA policies, user lifecycle, SSO configuration
- **aws.iam** - IAM policies, MFA status, access keys age
- **github** - Branch protection, secret scanning, code review requirements

**Testers:**
- **okta.mfa_bypass** [safe] - Attempt authentication without MFA, verify rejection
- **github.secret_push** [observable] - Attempt to push a test secret to a repo, verify it's blocked by secret scanning
- **aws.public_access** [safe] - Attempt to access S3 buckets/resources without credentials, verify denial

### Phase 2 - Network & Infrastructure

**Collectors:**
- **cloudflare** - WAF rules, DNS config, SSL/TLS settings
- **aws.vpc** - Security groups, NACLs, flow logs
- **aws.config** - Config rules compliance status

**Testers:**
- **cloudflare.waf_bypass** [safe] - Send test payloads through WAF, verify blocking
- **aws.sg_probe** [safe] - Attempt connections to ports that should be blocked

### Phase 3 - Endpoints & Apps

**Collectors:**
- **jamf** - Device compliance, encryption status, patch levels
- **crowdstrike** - EDR status, detection events
- **snyk** - Vulnerability scan results, dependency risks

### Phase 4 - Collaboration & GRC

**Collectors:**
- **google-workspace** - Admin roles, sharing settings, DLP
- **azure-ad** - Conditional access, PIM status
- **jira** - Change tickets, incident tracking

## Success Criteria

### Measurable Outcomes

- **SC-001**: User can collect evidence from 3+ systems within 5 minutes of installation
- **SC-002**: Historical query for 180 days of data returns in < 2 seconds
- **SC-003**: Control effectiveness calculation matches manual verification 100% (no false positives/negatives in logic)
- **SC-004**: New collector module can be developed following documentation in < 4 hours
- **SC-005**: New tester module can be developed following documentation in < 6 hours (includes safety classification and cleanup)
- **SC-006**: Single binary size < 50MB (including all built-in modules)
- **SC-007**: Community contributes 5+ modules within 6 months of public release
- **SC-008**: Active test execution adds < 30 seconds overhead compared to direct API interaction (pre-flight, transcript, cleanup)

### User Satisfaction

- **SC-010**: 90% of users successfully complete first evidence collection on first attempt
- **SC-011**: Error messages lead to successful resolution without external help 80% of the time
- **SC-012**: Documentation rated "clear and comprehensive" by 80% of surveyed users

### Business/Mission Impact

- **SC-020**: Reduce time to gather audit evidence by 80% compared to manual collection
- **SC-021**: Enable continuous monitoring where only point-in-time was previously possible
- **SC-022**: At least 3 GRC platforms integrate OCEAN as evidence backend within 12 months
- **SC-023**: Provenance verification enables auditor self-service — auditors can independently verify evidence without operator involvement

## Resolved Design Decisions

These items were open questions in v1.0.0 and are now resolved:

1. **Evidence Signing**: Ed25519 default signing with in-toto DSSE envelope format. Signing is mandatory for all stored evidence. KMS-backed keys for enterprise, keyless OIDC binding for advanced use cases.
2. **Control Library Source**: Ship with default controls mapped to common frameworks (SOC 2, ISO 27001, NIST CSF, CIS Controls) plus community contribution model for additional controls.
3. **Schema Versioning**: Breaking schema changes require major version bump with migration tooling and documentation per the Constitution's Quality Gates.
4. **Multi-tenancy**: Consuming platform's responsibility. OCEAN is the evidence and verification engine, not the platform.
5. **Offline Collectors**: Out of scope for initial release. Agent-based collection can be considered as a future module type if demand materializes.
