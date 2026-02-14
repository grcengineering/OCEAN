# Data Model: OCEAN Core v2.0.0

**Spec Reference**: `.specify/specs/ocean-core/spec.md`
**Constitution Reference**: `.specify/memory/constitution.md` v2.0.0
**Created**: 2026-02-13
**Status**: Draft

This document defines the entity relationships for OCEAN (Open Control Evidence Acquisition Normalizer). All entities follow the principles established in the Constitution: evidence-first architecture, OCSF-inspired schema design, dual-mode modules, and cryptographic provenance.

---

## Table of Contents

1. [Evidence](#evidence)
2. [Control](#control)
3. [Module](#module)
4. [ControlStatus](#controlstatus)
5. [Schedule](#schedule)
6. [Framework](#framework)
7. [Attestation](#attestation)
8. [TestTranscript](#testtranscript)
9. [Entity Relationships](#entity-relationships)
10. [Enumerations Reference](#enumerations-reference)

---

## Evidence

The foundational entity of the entire system. Every piece of data OCEAN produces is an Evidence record -- a structured, immutable, cryptographically signed record proving a fact about a control's implementation or operating effectiveness.

Evidence is produced by Modules (either Collectors or Testers) and consumed by the Evaluation Engine to determine ControlStatus. All Evidence carries provenance metadata and a cryptographic attestation.

### Fields

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `id` | uuid | Unique evidence identifier | Required. Immutable after creation. |
| `control_id` | string | Reference to the Control this evidence supports | Required. Must reference a valid Control. |
| `class_uid` | integer | Evidence class identifier (e.g., 1001 = IAM Policy) | Required. From the OCEAN evidence class taxonomy. |
| `category_uid` | integer | Control domain category (e.g., 1 = Identity & Access) | Required. Values 1-8 per Control Domain Categories. |
| `activity_id` | integer | What was observed or tested (e.g., 1 = Config Check, 2 = Active Test) | Required. |
| `time` | timestamp | Normalized collection or test time | Required. UTC. ISO 8601 format. |
| `confidence_level` | enum | Whether evidence is passively observed or actively verified | Required. Values: `passive_observation`, `active_verification`. |
| `metadata` | object | Provenance metadata about the module, source, and timestamps | Required. See Metadata substructure below. |
| `observables` | array of Observable | Key indicators extracted for unified search | Required. May be empty array. |
| `status_id` | integer | Machine-readable effectiveness status | Required. Values: 0=Unknown, 1=Effective, 2=Ineffective, 99=Other. |
| `status` | string | Human-readable status description | Required. Free-form string corresponding to status_id. |
| `raw_data` | JSON object | Original API response or test output, preserved verbatim | Required. Immutable. |
| `findings` | array of Finding | Specific observations supporting the status determination | Required. May be empty array. |
| `enrichments` | array of Enrichment | Post-collection additions (threat intel, context, cross-references) | Optional. Each enrichment creates a derived record linked to the original. |
| `test_transcript` | TestTranscript | Full record of active test execution | Conditional. Required when confidence_level = `active_verification`. Null for passive evidence. |
| `attestation` | AttestationRef | Cryptographic provenance reference for this evidence record | Required. Signing is mandatory per Constitution VIII and X. |

### Metadata Substructure

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `metadata.module.name` | string | Module that produced this evidence | Required. |
| `metadata.module.version` | semver | Semantic version of the module | Required. Format: MAJOR.MINOR.PATCH. |
| `metadata.module.type` | enum | Module operational mode | Required. Values: `collector`, `tester`, `dual`. |
| `metadata.source.system` | string | Source system identifier (e.g., "okta", "aws", "github") | Required. |
| `metadata.source.api_version` | string | API version of the source system used during collection | Required. |
| `metadata.source.endpoint` | string | Specific API endpoint queried or tested | Required. |
| `metadata.original_time` | timestamp | Source system's own timestamp, if different from collection time | Optional. UTC. |
| `metadata.processed_time` | timestamp | When OCEAN processed and normalized this evidence | Required. UTC. |
| `metadata.safety_classification` | enum | Safety classification of the test that produced this evidence | Conditional. Required when module.type = `tester` or `dual` and activity is an active test. Values: `safe`, `observable`, `reversible`, `destructive`. |

### Observable Substructure

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `type` | string | Observable category (e.g., "user", "ip", "resource", "domain") | Required. |
| `value` | string | The observed value | Required. |

### Finding Substructure

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `title` | string | Short description of the finding | Required. |
| `description` | string | Detailed explanation | Required. |
| `severity_id` | integer | Finding severity level | Required. |

### Enrichment Substructure

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `type` | string | Enrichment type identifier | Required. |
| `data` | JSON object | Enrichment payload | Required. |
| `enriched_time` | timestamp | When enrichment was applied | Required. UTC. |

### AttestationRef Substructure

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `type` | enum | Attestation type | Required. Values: `collection`, `evaluation`. |
| `dsse_envelope_ref` | string | Content-addressable reference to the DSSE envelope | Required. |
| `digest` | string | SHA-256 digest of this evidence record | Required. Hex-encoded. |
| `signer` | string | Key identifier of the signer | Required. |

### Invariants

- Evidence is immutable once created. No updates, only enrichments that create new derived records.
- `confidence_level` must be `active_verification` if and only if the evidence was produced by a Tester module.
- `test_transcript` must be present if and only if `confidence_level` = `active_verification`.
- `attestation.digest` must match the SHA-256 of the evidence record content (excluding the attestation field itself).
- Every stored Evidence record must have a corresponding signed Attestation (mandatory per Constitution).

---

## Control

A Control represents a security or compliance requirement that can be evaluated for operating effectiveness. Controls are defined declaratively in YAML and map evidence to effectiveness assertions. A single Control may reference multiple Collectors (passive observation) and Testers (active verification) to build a complete picture.

### Fields

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `id` | string | Unique control identifier (e.g., "mfa.enforcement") | Required. Dot-separated namespace. |
| `name` | string | Human-readable control name | Required. |
| `description` | string | Detailed description of what this control protects | Required. |
| `threat_mitigated` | string | The specific threat this control addresses | Required. Controls are defined by threats they mitigate, not vague criteria. |
| `framework_mappings` | array of FrameworkMapping | Cross-framework references for this control | Optional. May be empty for custom controls. |
| `evidence_requirements` | array of string | List of required evidence types (class_uids or named types) | Required. Defines what evidence is needed to evaluate this control. |
| `collectors` | array of ModuleRef | References to Collector modules that produce passive evidence | Required. At least one collector or tester must be specified. |
| `testers` | array of ModuleRef | References to Tester modules that produce active verification evidence | Optional. When absent, control evaluates with passive-only confidence. |
| `evaluation_logic` | EvaluationLogic | How to determine control effectiveness from evidence | Required. Exactly one of `cel_expression` or `preset` must be set. |
| `evaluation_expression_hash` | string | SHA-256 content-address of the evaluation logic | Computed. Automatically derived from `cel_expression` or expanded preset. Used for reproducible historical evaluations. |

### FrameworkMapping Substructure

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `framework_id` | string | Reference to a Framework entity (e.g., "soc2", "iso27001") | Required. Must reference a valid Framework. |
| `control_ref` | string | The control identifier within that framework (e.g., "CC6.1", "A.9.4.2") | Required. |

### ModuleRef Substructure

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `module_id` | string | Reference to a Module (e.g., "okta.mfa_policy") | Required. Must reference a registered Module. |

### EvaluationLogic Substructure

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `cel_expression` | string | CEL expression evaluated against collected evidence | Conditional. Mutually exclusive with `preset`. |
| `preset` | string | Named preset that expands to a CEL expression (e.g., "all_users_mfa_enforced") | Conditional. Mutually exclusive with `cel_expression`. |

### Invariants

- A Control must reference at least one module (collector or tester). A control with zero module references is invalid.
- `evaluation_expression_hash` is a computed field: SHA-256 of the resolved CEL expression text (presets are expanded before hashing).
- When a CEL expression or preset is updated, the hash changes. Historical evaluations retain the hash of the expression version that produced them.
- Composite controls (those referencing multiple collectors/testers across different source systems) aggregate evidence using the evaluation logic. If any required evidence source returns `ineffective`, the overall status is `ineffective` unless the CEL expression defines otherwise.

---

## Module

Module is the base entity for all pluggable integrations. It defines shared metadata and capabilities. Concrete behavior is determined by the subtype: Collector (passive evidence gathering) or Tester (active control verification). A single Module implementation may fulfill both subtypes (dual-mode).

### Base Fields (shared by all subtypes)

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `id` | string | Unique module identifier (e.g., "okta.mfa_policy") | Required. Dot-separated namespace: `<system>.<capability>`. |
| `name` | string | Human-readable module name | Required. |
| `version` | semver | Module version, independent of OCEAN core version | Required. |
| `source_system` | string | Target system this module integrates with (e.g., "okta", "aws", "github") | Required. |
| `evidence_types` | array of integer | Evidence class_uids this module can produce | Required. At least one. |
| `credential_requirements` | array of CredentialReq | Credentials needed to operate | Required. May be empty for modules that need no auth. |
| `rate_limits` | RateLimitConfig | Rate limiting configuration for API interactions | Optional. Recommended for all API-based modules. |

### CredentialReq Substructure

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `name` | string | Credential identifier (e.g., "OKTA_API_TOKEN") | Required. |
| `type` | string | Credential type (e.g., "api_token", "oauth2", "aws_role") | Required. |
| `description` | string | What the credential is used for and minimum permissions needed | Required. |
| `required` | boolean | Whether the module can operate without this credential | Required. |

### RateLimitConfig Substructure

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `requests_per_second` | float | Maximum requests per second to the source API | Optional. |
| `burst` | integer | Maximum burst size | Optional. |
| `backoff_strategy` | string | Backoff strategy when rate limited (e.g., "exponential") | Optional. Default: "exponential". |

### Subtype: Collector

Collectors perform passive evidence gathering -- they read configuration state from source systems without modifying anything. All evidence produced by Collectors carries `confidence_level: passive_observation`.

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `collection_logic` | string | Description of what data is collected and how | Required. |
| `schema_mapping` | object | Maps raw API response fields to OCEAN evidence schema fields | Required. |

### Subtype: Tester

Testers perform active control verification -- they attempt actions that controls should prevent and record the outcome. All evidence produced by Testers carries `confidence_level: active_verification`. Testers have additional safety requirements.

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `safety_classification` | enum | Risk level of this test | Required. Values: `safe`, `observable`, `reversible`, `destructive`. Safety-first: when uncertain, classify at the HIGHER risk level. |
| `environment_scope` | enum | Environments where this test may execute | Required. Values: `production`, `staging`, `isolated`. |
| `pre_flight_checks` | array of string | Validations that must pass before test execution (scope, authorization, rollback readiness) | Required. At least one check. |
| `cleanup_procedures` | array of string | Steps to reverse any state changes after test execution | Required. May be empty only for `safe` classification. |
| `test_logic` | string | Description of what the test attempts and what constitutes pass/fail | Required. |

### Invariants

- A module declaring subtype Tester without a `safety_classification` fails validation and will not load (FR-014).
- Modules with `safety_classification: destructive` must have non-empty `cleanup_procedures` with manual cleanup documentation.
- Modules with `environment_scope: production` must have `safety_classification: safe` with documented evidence of safety.
- A dual-mode module implements both Collector and Tester fields and can be invoked via either `ocean collect` or `ocean test`.

---

## ControlStatus

A point-in-time determination of a Control's operating effectiveness. Produced by the Evaluation Engine when it applies a Control's evaluation logic (CEL expression or preset) against collected Evidence. Each ControlStatus has its own Evaluation Attestation proving what logic was applied to what evidence.

### Fields

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `id` | uuid | Unique status record identifier | Required. |
| `control_id` | string | Reference to the Control being evaluated | Required. Must reference a valid Control. |
| `timestamp` | timestamp | When this evaluation was performed | Required. UTC. |
| `status` | enum | Evaluated effectiveness | Required. Values: `effective`, `ineffective`, `unknown`, `partial`. |
| `confidence` | enum | Confidence level based on evidence types available | Required. Values: `high`, `medium`, `low`. See confidence rules below. |
| `evidence_ids` | array of uuid | References to all Evidence records used in this evaluation | Required. At least one. |
| `evaluation_details` | object | Detailed breakdown of the evaluation (expression result, per-source results for composite controls) | Required. |
| `evaluation_attestation_ref` | string | Content-addressable reference to the Evaluation Attestation for this verdict | Required. |

### Confidence Rules

| Condition | Confidence | Rationale |
|-----------|------------|-----------|
| Both `passive_observation` and `active_verification` evidence present and agreeing | `high` | Dual-mode verification: configuration exists AND behavior confirmed |
| Only `passive_observation` evidence present | `medium` | Configuration observed but behavior not verified |
| Only `active_verification` evidence present | `medium` | Behavior verified but configuration state not observed |
| Evidence is stale, incomplete, or sources unreachable | `low` | Insufficient data for reliable determination |
| Passive and active evidence disagree | Depends on status | Active test result takes precedence for behavioral assertions; status is `ineffective` if active test fails regardless of passive result |

### Invariants

- A ControlStatus with `status: effective` must have at least one Evidence record with `status_id: 1`.
- When passive evidence shows effective but active test shows ineffective, overall status must be `ineffective` (active takes precedence for behavioral assertions).
- The `evaluation_attestation_ref` must reference an EvaluationAttestation whose `expression_digest` matches the Control's `evaluation_expression_hash` at evaluation time.
- ControlStatus records are immutable. Re-evaluation produces a new ControlStatus, never modifies an existing one.

---

## Schedule

Configuration for automated, recurring evidence collection and active testing. Schedules respect safety classifications and environment scoping for any referenced Tester modules.

### Fields

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `id` | uuid | Unique schedule identifier | Required. |
| `cron_expression` | string | Cron-style schedule expression (e.g., "0 2 * * *" for daily at 02:00 UTC) | Required. Standard 5-field cron syntax. |
| `modules` | array of ModuleRef | Collector and Tester modules to execute on schedule | Required. At least one module. |
| `controls` | array of string | Control IDs whose evidence requirements drive this schedule | Required. At least one control. |
| `last_run` | timestamp | When this schedule last executed | Optional. Null if never run. UTC. |
| `next_run` | timestamp | Computed next execution time | Computed. Derived from cron_expression and last_run. UTC. |
| `enabled` | boolean | Whether this schedule is active | Required. Default: true. |
| `safety_authorization` | SafetyAuth | Pre-authorized safety levels for scheduled active tests | Optional. Required if modules include Testers. |

### SafetyAuth Substructure

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `max_safety_level` | enum | Highest safety classification authorized for unattended execution | Required. Values: `safe`, `observable`, `reversible`. Note: `destructive` cannot be pre-authorized for scheduled runs. |
| `authorized_by` | string | Identity of the person who authorized scheduled testing | Required. |
| `authorized_at` | timestamp | When authorization was granted | Required. UTC. |
| `environment_scope` | enum | Authorized environment for scheduled tests | Required. Values: `production`, `staging`, `isolated`. |

### Invariants

- A Schedule referencing Tester modules must have a valid `safety_authorization`.
- `safety_authorization.max_safety_level` must be equal to or higher than the safety classification of every referenced Tester module, or the schedule is invalid.
- `destructive` tests cannot be scheduled for unattended execution. They always require interactive authorization.
- If the system is offline during a scheduled run, catch-up behavior is configurable: execute immediately on restart or skip and wait for next scheduled time.
- Scheduled Testers must respect their `environment_scope` -- a staging-only tester cannot be scheduled against a production target.

---

## Framework

A compliance standard or benchmark that defines a set of control requirements. Frameworks are reference entities used for cross-mapping controls (e.g., a single OCEAN Control may map to SOC 2 CC6.1, ISO 27001 A.9.4.2, and NIST CSF PR.AC-7 simultaneously).

### Fields

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `id` | string | Unique framework identifier (e.g., "soc2", "iso27001", "nist_csf", "cis_controls") | Required. |
| `name` | string | Full framework name (e.g., "SOC 2 Type II") | Required. |
| `version` | string | Framework version or revision year (e.g., "2017", "v8") | Required. |
| `controls` | array of FrameworkControl | Control references defined by this framework | Required. |

### FrameworkControl Substructure

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `ref` | string | Control identifier within the framework (e.g., "CC6.1") | Required. Unique within the framework. |
| `title` | string | Control title from the framework | Required. |
| `description` | string | Control description from the framework | Optional. |
| `ocean_control_ids` | array of string | OCEAN Control IDs that satisfy this framework control | Optional. Populated as mappings are established. |

### Invariants

- Framework entities are reference data. They do not change based on evidence collection.
- The relationship between Framework controls and OCEAN Controls is many-to-many: one OCEAN Control may satisfy multiple framework controls, and one framework control may be satisfied by multiple OCEAN Controls.

---

## Attestation

A cryptographic provenance record in in-toto DSSE (Dead Simple Signing Envelope) format. Attestations prove the integrity and origin of evidence and evaluations. Every stored Evidence record and every ControlStatus evaluation has a corresponding Attestation.

### Base Fields

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `dsse_envelope` | JSON object | The complete DSSE envelope containing payload, payloadType, and signatures | Required. Conforms to in-toto DSSE specification. |
| `predicate_type` | enum | The type of attestation predicate | Required. Values: `collection`, `evaluation`. |
| `subject_digests` | array of Digest | Content-addressable references to the artifacts this attestation covers | Required. At least one. |
| `signer_identity` | string | Key identifier or OIDC identity of the signer | Required. |
| `timestamp` | timestamp | When the attestation was created | Required. UTC. |

### Digest Substructure

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `algorithm` | string | Hash algorithm used | Required. Default: "sha256". |
| `value` | string | Hex-encoded digest value | Required. |

### Subtype: CollectionAttestation

Created when a Module (Collector or Tester) produces Evidence. Proves what was collected or tested, from where, using what module version, and captures the raw transcript.

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `module_id` | string | The module that performed the collection or test | Required. |
| `module_version` | semver | Version of the module at collection time | Required. |
| `source` | object | Source system details (system, api_version, endpoint) | Required. |
| `evidence_digest` | string | SHA-256 digest of the evidence record | Required. |
| `raw_data_digest` | string | SHA-256 digest of the raw API response or test output | Required. |
| `transcript_digest` | string | SHA-256 digest of the collection transcript (API calls, parameters, responses) or test transcript | Optional. Required for active tests. |

### Subtype: EvaluationAttestation

Created when the Evaluation Engine produces a ControlStatus. Proves what evidence was evaluated, what logic was applied, and what verdict was reached.

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `evidence_digests` | array of string | SHA-256 digests of all evidence records used as input | Required. At least one. |
| `expression_digest` | string | SHA-256 content-address of the CEL expression (or expanded preset) used | Required. Enables reproducing the exact evaluation logic for any historical verdict. |
| `expression_text` | string | The actual CEL expression evaluated (for auditability) | Required. |
| `verdict` | string | The evaluation result (maps to ControlStatus.status) | Required. |
| `control_id` | string | The control that was evaluated | Required. |

### Invariants

- Every stored Evidence record must have exactly one CollectionAttestation.
- Every ControlStatus record must have exactly one EvaluationAttestation.
- Attestation digests must match the actual content. Any mismatch indicates tampering and must be reported by the verification system.
- Signing is mandatory. Evidence or evaluations without signed attestations must be rejected.
- Old attestations remain verifiable after key rotation. Key metadata in the attestation identifies which key version was used.
- The provenance chain is independently verifiable: a third party with the public key and attestation chain can validate any verdict without trusting the OCEAN operator.

---

## TestTranscript

A structured record of an active test's complete execution lifecycle. Embedded within Evidence records produced by Tester modules. The transcript captures three phases: what actions were attempted, what was observed as a result, and what cleanup was performed afterward.

### Fields

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `actions_attempted` | array of TranscriptAction | Actions the tester attempted during execution | Required. At least one action. |
| `observations` | array of TranscriptObservation | What happened as a result of the attempted actions | Required. At least one observation. |
| `cleanup_actions` | array of TranscriptCleanup | Steps taken to reverse any state changes | Required. May be empty only for `safe` classification tests. |

### TranscriptAction Substructure

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `action` | string | Description of the action attempted (e.g., "Attempted authentication without MFA token") | Required. |
| `timestamp` | timestamp | When the action was attempted | Required. UTC. |
| `parameters` | JSON object | Parameters used for the action (credentials redacted) | Required. Must not contain raw credentials. |

### TranscriptObservation Substructure

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `observation` | string | What was observed (e.g., "Authentication request rejected with 403 Forbidden") | Required. |
| `timestamp` | timestamp | When the observation was recorded | Required. UTC. |
| `expected` | boolean | Whether this observation matches the expected outcome for an effective control | Required. true = control behaved as expected. |

### TranscriptCleanup Substructure

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `action` | string | Description of the cleanup action (e.g., "Deleted test user account") | Required. |
| `timestamp` | timestamp | When the cleanup action was performed | Required. UTC. |
| `success` | boolean | Whether the cleanup action succeeded | Required. Cleanup failure triggers operator alert but does not invalidate the test result. |

### Invariants

- Cleanup failures are recorded honestly in the transcript. A failed cleanup does not retroactively invalidate the test result -- it is a separate operational concern.
- The transcript must not contain raw credentials, API tokens, or secrets. Parameters are captured but sensitive values must be redacted.
- For `safe` classification tests, cleanup_actions may be empty (no state changes to reverse). For `reversible` and `destructive` classifications, cleanup_actions are expected.

---

## Entity Relationships

This section describes how entities connect to form the OCEAN data model. Relationships are described using cardinality notation: `1` (exactly one), `0..1` (zero or one), `*` (zero or many), `1..*` (one or many).

### Primary Relationships

```
Control 1 ---- * Evidence
  A Control has many Evidence records.
  Each Evidence record belongs to exactly one Control (via control_id).

Control 1 ---- * ControlStatus
  A Control has many ControlStatus evaluations over time (time-series).
  Each ControlStatus belongs to exactly one Control.

ControlStatus 1 ---- 1..* Evidence
  Each ControlStatus references one or more Evidence records (via evidence_ids).
  An Evidence record may be referenced by multiple ControlStatus evaluations.

Control * ---- * Framework
  A Control maps to many Frameworks (via framework_mappings).
  A Framework contains many Controls (via controls array).
  This is a many-to-many relationship mediated by FrameworkMapping.

Control * ---- * Module
  A Control references many Modules via its collectors and testers arrays.
  A Module may be referenced by many Controls.

Module -- Collector
  A Collector is a subtype of Module (passive evidence gathering).

Module -- Tester
  A Tester is a subtype of Module (active control verification).

Module -- Dual
  A Dual-mode module implements both Collector and Tester subtypes.
```

### Provenance Relationships

```
Evidence 1 ---- 1 CollectionAttestation
  Every Evidence record has exactly one CollectionAttestation.
  CollectionAttestation references the Evidence by digest (content-addressable).

ControlStatus 1 ---- 1 EvaluationAttestation
  Every ControlStatus has exactly one EvaluationAttestation.
  EvaluationAttestation references its input Evidence records by digest.

EvaluationAttestation * ---- 1..* Evidence
  An EvaluationAttestation references one or more Evidence digests as input.
  This creates the provenance chain: Evidence -> CollectionAttestation,
  Evidence -> EvaluationAttestation -> ControlStatus.

CollectionAttestation * ---- 1 Module
  Each CollectionAttestation references the Module that produced the evidence.
```

### Embedded Relationships

```
Evidence 1 ---- 0..1 TestTranscript
  Evidence from active tests embeds a TestTranscript.
  TestTranscript is only present when confidence_level = active_verification.

Evidence 1 ---- * Observable
  Each Evidence record contains zero or more extracted Observables.

Evidence 1 ---- * Finding
  Each Evidence record contains zero or more Findings.

Evidence 1 ---- * Enrichment
  Each Evidence record may have post-collection Enrichments.
```

### Scheduling Relationships

```
Schedule * ---- * Module
  A Schedule references many Modules (collectors and testers).
  A Module may be referenced by many Schedules.

Schedule * ---- * Control
  A Schedule is driven by Control evidence requirements.
  A Control may be covered by many Schedules.
```

### Full Provenance Chain (End-to-End)

```
Source System API
      |
      | (Module executes collection or test)
      v
  Evidence Record
      |
      +--> CollectionAttestation (DSSE envelope, signed)
      |      - subject: Evidence digest
      |      - predicate: module, source, raw_data_digest, transcript_digest
      |
      | (Evaluation Engine applies CEL expression)
      v
  ControlStatus Record
      |
      +--> EvaluationAttestation (DSSE envelope, signed)
             - subjects: Evidence digests (input)
             - predicate: expression_digest, verdict, control_id
```

A third party with the public signing key can independently verify:
1. The Evidence content matches its CollectionAttestation digest (data integrity).
2. The CollectionAttestation was signed by a trusted key (authenticity).
3. The EvaluationAttestation references the correct Evidence digests (chain integrity).
4. The evaluation used a specific, content-addressed CEL expression (reproducibility).
5. The verdict follows from the expression applied to the evidence (logical correctness).

---

## Enumerations Reference

### confidence_level

| Value | Description | Produced By |
|-------|-------------|-------------|
| `passive_observation` | Evidence gathered by reading configuration state without modifying the target system | Collector modules |
| `active_verification` | Evidence gathered by attempting an action that the control should prevent | Tester modules |

### status_id

| Value | Label | Description |
|-------|-------|-------------|
| 0 | Unknown | Effectiveness could not be determined |
| 1 | Effective | Control is operating as intended |
| 2 | Ineffective | Control is NOT operating as intended |
| 99 | Other | Status does not fit standard categories |

### ControlStatus.status

| Value | Description |
|-------|-------------|
| `effective` | All required evidence indicates the control is operating correctly |
| `ineffective` | One or more evidence sources indicate the control is not operating correctly |
| `unknown` | Insufficient evidence or unreachable sources; cannot determine effectiveness |
| `partial` | Some components of a composite control are effective, others are not |

### ControlStatus.confidence

| Value | Description |
|-------|-------------|
| `high` | Both passive and active evidence present and agreeing |
| `medium` | Only one evidence type present (passive-only or active-only) |
| `low` | Evidence is stale, incomplete, or sources were unreachable |

### safety_classification

| Value | Description | Authorization Required | Cleanup Required |
|-------|-------------|----------------------|-----------------|
| `safe` | Read-only probes; no state changes, no audit trail entries | Minimal (default allow) | None |
| `observable` | Creates audit trail entries but no state changes (e.g., failed login attempts) | Explicit authorization citing audit trail impact | None |
| `reversible` | Causes state changes that are automatically reversed | Explicit authorization with rollback confirmation | Automatic, documented in transcript |
| `destructive` | May cause permanent changes requiring manual cleanup | Explicit confirmation with warning about permanent changes | Manual, documented in transcript |

### environment_scope

| Value | Description |
|-------|-------------|
| `production` | Test is safe to run against production systems (must be `safe` classification) |
| `staging` | Test should only run against staging/pre-production environments |
| `isolated` | Test requires an isolated, dedicated test environment |

### module.type

| Value | Description |
|-------|-------------|
| `collector` | Passive evidence gathering only |
| `tester` | Active control verification only |
| `dual` | Implements both collector and tester capabilities |

### attestation.predicate_type

| Value | Description |
|-------|-------------|
| `collection` | Attests to evidence collection or test execution provenance |
| `evaluation` | Attests to control evaluation logic and verdict provenance |
