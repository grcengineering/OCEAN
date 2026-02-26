# OCEAN Constitution
<!-- Open Control Evidence Acquisition Normalizer -->

<!--
Sync Impact Report:
- Version change: 2.0.0 → 3.0.0
- MAJOR: Cryptographic provenance removed as native OCEAN feature
  - Principle X (Cryptographic Provenance Chain) removed
  - Provenance is now handled by Corsair (https://grcorsair.com), used in tandem
- Modified principles:
  - I. Evidence-First Architecture → removed mandatory attestation requirement
  - VII. Radical Transparency → removed "cryptographic provenance" wording
  - VIII. Security & Privacy by Design → removed mandatory signing, updated to Corsair reference
  - Vision Statement → updated to describe 3-pillar OCEAN + Corsair integration
- Removed principles:
  - X. Cryptographic Provenance Chain (removed — now Corsair's domain)
- Technology Stack changes:
  - Removed: Attestation Format (in-toto DSSE)
  - Added: Corsair Integration note
- Templates requiring updates:
  - ⚠ .specify/specs/ocean-core/spec.md — updated to remove provenance pillar and FR-040-FR-047
  - ⚠ .specify/specs/ocean-core/plan.md — updated to remove attestation phases/decisions
  - ⚠ .specify/specs/ocean-core/data-model.md — updated to remove Attestation entity
  - ⚠ .specify/specs/ocean-core/quickstart.md — updated to remove keys/verify-provenance
  - ⚠ .specify/specs/ocean-core/research.md — updated with Corsair Integration section
  - ⚠ .specify/specs/ocean-core/tasks.md — Phase 11 and attestation tasks deprecated
  - ⚠ CLAUDE.md — needs updated principle list and scope description
- Follow-up TODOs: Code changes to remove internal/attestation/, ocean keys, ocean verify-provenance
-->

## Vision Statement

OCEAN is the **"Metasploit for GRC"** — an open-source, portable evidence acquisition, active control testing, and normalization engine powering continuous compliance monitoring. Its ultimate purpose is to serve as the backend for a **"StatusPage for Compliance"** — a radically transparent, shareable dashboard showing historical control operating effectiveness metrics.

Like Metasploit enables security professionals to both *scan for* and *actively test* vulnerabilities, OCEAN enables both **passive monitoring** (querying system APIs to observe configuration state) and **active verification** (attempting what controls should prevent to prove they work). All evidence — whether passively collected or actively generated — is structured, normalized, and queryable.

Like StatusPage shows "Is the service up?", OCEAN enables showing "Is the control operating effectively?" with historical evidence trails, uptime metrics (e.g., "99.94% effective over 180 days"), and honest representation of failures alongside successes.

OCEAN is designed to work in tandem with **[Corsair](https://grcorsair.com)** — the open-source cryptographic provenance layer. OCEAN produces structured evidence; Corsair signs it into independently-verifiable Certificates of Proof of Operational Effectiveness (CPOEs). Together they form a complete, auditor-grade GRC evidence stack.

OCEAN is **NOT** a full GRC platform, and it is **NOT** a cryptographic provenance tool. It is the specialized evidence acquisition and verification layer that GRC platforms consume. Provenance is Corsair's job.

## Core Principles

### I. Evidence-First Architecture

All data in OCEAN is **evidence** — structured records proving whether controls are implemented and operating effectively.

- All evidence MUST have provenance metadata: source system, collection timestamp, module version, chain of custody
- Evidence is **immutable** once collected; enrichment creates new derived records with explicit linkage to originals
- Support both point-in-time snapshots AND continuous/historical time-series data for control uptime calculations
- Evidence MUST be **reproducible** — same query parameters over the same time window MUST produce identical results
- Raw API responses and test transcripts are preserved alongside normalized evidence for auditability
- Evidence carries a **confidence indicator**: passive observation (configuration-based) vs active verification (behavioral) — active verification evidence carries higher confidence for behavioral assertions

### II. OCSF-Inspired Schema Design

The evidence schema draws inspiration from [OCSF](https://schema.ocsf.io/) (Open Cybersecurity Schema Framework) for consistent, extensible data modeling.

- **Hierarchical taxonomy**: Control Domains (categories) → Evidence Classes → Attributes
- **Shared attribute dictionary** ensures consistent semantics across all integrations (e.g., `timestamp`, `resource_id`, `status` mean the same thing everywhere)
- **Profile system** for cross-cutting concerns: audit trail profile, temporal profile, enrichment profile
- **Extension mechanism** for regulation-specific evidence without modifying core schema (e.g., HIPAA extensions, PCI extensions)
- **Single-parentage**: each evidence record belongs to exactly one Evidence Class — no ambiguity
- **Observable extraction**: key indicators (accounts, IPs, resources, domains) are surfaced regardless of nesting depth for unified search
- Enum-first approach: standardized integers for classification; string siblings for unmapped values

### III. Metasploit-Style Extensibility

Like Metasploit's module system enables security researchers to contribute both auxiliary scanners and active exploits, OCEAN's module architecture enables the GRC community to contribute integrations and control tests.

- **Dual-mode module architecture**: Collectors (passive evidence gathering) and Testers (active control verification) as first-class module types
- Each module is a **self-contained unit** with: metadata, operational logic, schema mapping, credential requirements, rate limiting, and (for Testers) safety classification and cleanup procedures
- Collectors and Testers share a common Module base but define **separate interface contracts** — a single module MAY implement both
- **Community contribution model** — clear interface contracts, comprehensive documentation, PRs welcome
- **Runtime module discovery** and loading without recompilation
- Modules declare their **capabilities** and evidence types they produce
- Module versioning independent of core — modules can evolve at their own pace
- Dependency injection for testability — modules receive interfaces, not concrete implementations

### IV. Cross-Platform Portability

OCEAN runs anywhere — from a developer's laptop to enterprise Kubernetes clusters.

- **Single-binary CLI** for Windows, macOS, Linux with zero runtime dependencies
- **Container image** for microservice/sidecar deployment patterns
- **Embeddable as a library** for GRC platforms to consume directly
- **No cloud dependencies** — fully offline-capable with local storage
- Storage backends: SQLite (local/edge), PostgreSQL (enterprise), ClickHouse (analytics at scale)
- Configuration via files, environment variables, or flags — twelve-factor app compliant

### V. Control-Centric Organization

Evidence exists to prove control effectiveness. OCEAN organizes around controls, not APIs.

- Evidence **maps to Controls**, not just raw API responses
- Support **control decomposition**: a WAF control = Cloudflare WAF config + DNS records + Security Group rules + certificate validity
- Control assertions can be validated through **passive observation** (configuration evidence) AND **active verification** (behavioral test results)
- Active test evidence carries **higher confidence** than passive observation for behavioral assertions
- **Control evaluation logic** MUST be user-definable using a non-Turing-complete expression language (CEL) alongside structured YAML presets for common patterns
- Evaluation expressions are **content-addressed and versioned**; the exact logic used for any historical evaluation MUST be reproducible
- **Framework-agnostic control library** with bidirectional mappings (SOC 2 ↔ ISO 27001 ↔ NIST CSF ↔ CIS Controls)
- Controls defined by **threats they mitigate** and **specific technical requirements**, not vague criteria
- Control assertions are testable statements: "MFA is enforced for all admin accounts" can be proven true or false — through both observation and active bypass attempts

### VI. Continuous Monitoring Native

OCEAN is built for ongoing assurance, not point-in-time audits.

- **Scheduled, recurring evidence collection and active testing** — not just on-demand queries
- **Time-series storage** of control status enabling "uptime" calculations (e.g., 99.94% over 180 days)
- **Change detection**: configurable alerts when control status transitions (effective → ineffective or vice versa)
- **Historical queries**: "Was this control effective on DATE?", "Show 180-day trend", "When did this control last fail?"
- **Configurable collection intervals**: per-control scheduling (hourly, daily, weekly) based on risk and cost
- **Safety-aware scheduling**: active tests respect environment scoping and safety classifications when scheduled
- **Backfill support**: retroactively collect evidence for gaps when modules come online

### VII. Radical Transparency

No "trust center theater." OCEAN shows reality.

- **Show failures alongside successes** — hiding failures is antithetical to the mission
- **Complete audit trail** of all collection and testing activities: who triggered, what was collected/tested, when, what was the result
- **Human-readable output** formats alongside machine-readable (JSON, YAML, Markdown reports)
- **Clear error handling** with actionable remediation guidance (not just "collection failed")
- **Public-facing dashboards** show real historical data, not curated point-in-time snapshots
- Evidence includes confidence levels and caveats where applicable
- **Corsair integration** enables third-party independent verification of any compliance claim when cryptographic provenance is desired

### VIII. Security & Privacy by Design

The tool that proves security must itself be secure.

- **Credentials NEVER stored in evidence**; use secret references (environment variables, HashiCorp Vault, AWS Secrets Manager, Azure Key Vault)
- **Minimal permissions principle** — modules request only the permissions they need, document required permissions
- **Evidence redaction** capabilities for sharing: PII masking, resource ID hashing, configurable field removal
- **Role-based access** to different evidence sensitivity levels
- **Secure defaults**: TLS required for remote storage, secrets encrypted at rest
- Regular security audits of module permission scopes
- **Active test modules** undergo additional security review for blast radius and safety classification
- **Test authorization** is required before executing active tests in any environment
- Evidence produced by OCEAN can be cryptographically signed using **Corsair** (https://grcorsair.com) when independent provenance verification is required

### IX. Active Control Verification

OCEAN supports both passive evidence collection AND active control testing. Passive collection observes configuration; active testing proves behavior by attempting what controls should prevent.

- Modules are classified by operational mode: **Collectors** (read-only observation) and **Testers** (active behavioral verification)
- All active test modules MUST declare a **Safety Classification**:
  - **Safe**: read-only probes (attempt unauthenticated access to verify rejection)
  - **Observable**: creates audit trail entries but no state changes (failed login attempts)
  - **Reversible**: state changes that are automatically reversed (create then delete a test resource)
  - **Destructive**: may cause permanent changes requiring manual cleanup
- Active tests MUST implement **pre-flight validation** (target scope, authorization, rollback readiness) and **post-execution cleanup**
- Active tests MUST be **explicitly authorized**; the system MUST NOT execute active tests without confirmation appropriate to the safety level
- Test evidence carries **higher confidence** than collection evidence for behavioral assertions — a blocked unauthorized attempt proves more than a policy configuration read
- **Environment scoping** is mandatory: tests declare whether they are safe for production, staging-only, or require isolated targets
- Active test results include the **full test transcript**: what was attempted, what was observed, what was cleaned up
- **Safety-first principle**: when in doubt, classify tests at a HIGHER risk level; production-safe is a claim that must be proven

## Technology Stack

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Language | **Go** | Cross-platform single binaries, excellent concurrency model, strong cloud ecosystem, proven for CLI tools |
| Schema Format | **JSON** with JSON Schema validation; YAML for human authoring | Industry standard, tooling ubiquity, schema validation built-in |
| Default Storage | **SQLite** | Zero-dependency local storage, portable, sufficient for most use cases |
| Enterprise Storage | **PostgreSQL** | Battle-tested, JSONB support, excellent for structured queries |
| Analytics Storage | **ClickHouse** (optional) | Columnar storage for time-series analytics at scale |
| Expression Engine | **CEL** (Common Expression Language) | Non-Turing-complete, Go-native evaluation engine for user-defined compliance conditions; reference implementation: `github.com/google/cel-go` |
| Provenance Layer | **Corsair** (optional, external) | Open-source cryptographic provenance protocol; OCEAN evidence pipes to Corsair for CPOE (Certificate of Proof of Operational Effectiveness) signing. See https://grcorsair.com |
| API | **REST** (external), gRPC (internal, optional) | REST for broad compatibility, gRPC for performance-critical internal paths |
| License | **Apache 2.0** | Permissive, enterprise-friendly, includes patent protection |

## Quality Gates

### Code Quality
- All PRs MUST pass automated tests (unit, integration where applicable)
- Schema changes MUST include JSON Schema updates and validation tests
- New modules MUST include documentation: required permissions, produced evidence types, example output
- New Tester modules MUST additionally include: safety classification justification, pre-flight/cleanup documentation, environment scoping declaration
- Code coverage targets: 80% for core, 70% for modules

### Schema Governance
- **Breaking schema changes** require major version bump
- Breaking changes MUST include migration tooling and documentation
- Evidence types MUST be documented with examples before merge
- Schema additions SHOULD be additive (new optional fields preferred over required fields)

### Security
- Modules MUST NOT log or persist credentials
- Security-sensitive changes require explicit security review
- Dependencies scanned for known vulnerabilities
- Signed releases for distribution integrity
- **Active test modules** MUST include safety classification and be reviewed for blast radius before merge
- Active tests targeting production environments MUST be classified "safe" with documented evidence of safety

## Governance

### Amendment Process
1. Propose amendment via GitHub Issue with rationale
2. Discussion period (minimum 7 days for non-trivial changes)
3. Approval by maintainers
4. Update constitution with version bump:
   - **MAJOR**: Principle removal or fundamental redefinition
   - **MINOR**: New principle or significant expansion
   - **PATCH**: Clarification, wording improvements

### Compliance Verification
- All PRs MUST verify alignment with these principles
- Reviewers SHOULD cite relevant principles when requesting changes
- Complexity MUST be justified — default to simplicity (YAGNI)

### Precedence
This constitution supersedes all other documentation in cases of conflict. If guidance documents contradict principles here, file an issue to resolve the discrepancy.

**Version**: 3.0.0 | **Ratified**: 2026-01-17 | **Last Amended**: 2026-02-26
