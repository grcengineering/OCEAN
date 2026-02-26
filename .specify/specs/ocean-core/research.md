# Research Notes: OCEAN Core v2.0.0

**Date**: 2026-02-12 (updated 2026-02-26 for v3.0.0)
**Purpose**: Capture all research findings to inform OCEAN design

## Table of Contents
1. [Problem Domain](#problem-domain)
2. [OCSF Schema Analysis](#ocsf-schema-analysis)
3. [Metasploit Architecture](#metasploit-architecture)
4. [Existing GRC Tools](#existing-grc-tools)
5. [NIST OSCAL](#nist-oscal)
6. [Cloud Provider APIs](#cloud-provider-apis)
7. [CEL Expression Engine](#cel-expression-engine) *(new for v2.0.0)*
8. [Corsair Integration](#corsair-integration) *(updated for v3.0.0 — replaces in-toto DSSE)*
9. [Active Control Testing Patterns](#active-control-testing-patterns) *(new for v2.0.0)*
10. [Design Implications](#design-implications)

---

## Problem Domain

### Source: User's Blog Post
**URL**: https://blog.grc.engineering/p/soc-2-is-dead-long-live-soc-2

#### Three Fundamental Flaws of SOC 2

1. **Vague Control Requirements** — Trust Services Criteria lack explicit connections to specific threats
2. **Inadequate Audit Methodologies** — Technical controls assessed only for current state, not historical
3. **Static Reporting Artifacts** — SOC 2 Type II reports become outdated within weeks

#### The ALCOVE Vision

Proposed framework: **ALCOVE** (Assurance Levels for Control Operating Viability & Effectiveness) — multi-level assurance model with threat-informed control requirements and dynamic dashboards.

**OCEAN must avoid "trust center theater" through Radical Transparency (Principle VII).**

### User's Vision: StatusPage for Compliance

Historical control monitoring metrics dashboard showing per-control uptime (e.g., "Phishing-resistant MFA enforced: 99.94% uptime, 180 days"). **This is the ultimate UI that OCEAN should power.**

---

## OCSF Schema Analysis

### Source: https://schema.ocsf.io/

### Taxonomy Structure

Five constructs: Data Types & Attributes, Event Classes, Categories, Profiles, Extensions.

### Design Lessons for OCEAN

1. **Single-parentage hierarchy** — Each evidence belongs to exactly one category
2. **Dictionary-driven reusability** — Shared attributes ensure consistent semantics
3. **Metadata separation** — Provenance in distinct `metadata` object
4. **Enum-first approach** — Integers for classification, strings for unmapped
5. **Observable projection** — Surface indicators for unified search
6. **Constraint-based validation** — Express "at least one of X, Y, Z"

---

## Metasploit Architecture

### Source: https://github.com/rapid7/metasploit-framework

### Design Lessons for OCEAN

1. **Clear module interface** — Well-documented API for contributors
2. **Module metadata** — Self-describing modules with capabilities
3. **Runtime discovery** — Modules loaded without recompilation
4. **Categorization** — Modules organized by function
5. **Community-friendly** — Easy contribution process
6. **Dual-mode analogy** — Auxiliary scanners (→ OCEAN Collectors) + Exploits (→ OCEAN Testers)

---

## Existing GRC Tools

### Summary: OCEAN's Niche

OCEAN is NOT a full GRC platform. It's the specialized **evidence acquisition, testing, and normalization layer** that platforms like GigaChad GRC consume.

- **GigaChad GRC** = The car
- **OCEAN** = The engine

---

## NIST OSCAL

### Implications for OCEAN

- **Don't adopt OSCAL directly** — overfit to federal compliance
- **Borrow design patterns** — layered models, linkage, metadata standards
- **Use OCSF principles** for evidence schema instead
- **Create something new** purpose-built for continuous monitoring with cryptographic provenance

---

## Cloud Provider APIs

*(Unchanged from v1 — Okta, AWS, Cloudflare API patterns documented for collector development)*

---

## CEL Expression Engine

### Source: https://github.com/google/cel-go

**Decision**: CEL (Common Expression Language) for user-defined evaluation logic
**Rationale**: Non-Turing-complete, Go-native, simple expression syntax, no external runtime
**Alternatives Considered**: OPA/Rego (more powerful but heavier, Turing-complete), raw Go (not user-definable), Lua (requires runtime)

### Core Concepts

- **cel.Env**: Environment encapsulates context for parsing, type-checking, and generating evaluable programs
- **cel.Program**: Stateless, thread-safe, cacheable compiled expression
- **Workflow**: Parse → Check (type validation) → Evaluate. Parse/check at config time, evaluate at runtime

### Integration Pattern for OCEAN

```go
env, _ := cel.NewEnv(
    cel.Variable("evidence", cel.MapType(cel.StringType, cel.AnyType)),
    cel.Variable("control", cel.StringType),
)
ast, _ := env.Compile(`evidence.mfa_policy.enforcement == "required" && evidence.mfa_policy.user_exceptions.size() == 0`)
prg, _ := env.Program(ast)
result, _, _ := prg.Eval(map[string]interface{}{
    "evidence": normalizedEvidenceMap,
    "control":  "mfa_enforcement",
})
```

### Best Practices

- **Disable macros** with `cel.ClearMacros()` to ensure linear evaluation paths
- **Type-check at compile time** — static analysis rejects invalid expressions
- **Cache compiled programs** — cel.Program is thread-safe and reusable
- **Use custom functions** over comprehensions for common compliance patterns
- **Subset the environment** with `NewCustomEnv()` to limit available functions

### Content-Addressing Strategy

CEL maintains canonical Protocol Buffer representations for ASTs:

1. Parse/check expression → serialize to protobuf
2. Compute `SHA-256(protobuf_bytes)` → expression content address
3. Store mapping: `expression_hash → cel.Program`
4. Link each evaluation result to the expression hash used
5. For audit: "This control evaluated under expression `sha256:abc123...`"

### Performance

- Evaluation: nanoseconds to microseconds per expression (thread-safe)
- Linear complexity when macros disabled
- Compile once, evaluate thousands of times

### References

- [cel-go Repository](https://github.com/google/cel-go)
- [CEL-Go Codelab](https://codelabs.developers.google.com/codelabs/cel-go)
- [CEL Specification](https://github.com/google/cel-spec)
- [CEL Policy Package](https://github.com/google/cel-go/blob/master/policy/README.md)

---

## Corsair Integration

### Source: https://grcorsair.com | https://github.com/grcorsair/corsair

**Decision**: Cryptographic provenance is NOT a native OCEAN feature. OCEAN evidence pipes to **Corsair** for signing when independent provenance verification is required.
**Rationale**: Corsair is a purpose-built open-source cryptographic provenance protocol for GRC. OCEAN specializes in evidence acquisition and active testing; Corsair specializes in signing and certifying that evidence. The separation keeps OCEAN's scope narrow and the combined stack more powerful than either alone.

### What Corsair Is

Corsair is a TypeScript/Bun open-source tool that creates **CPOEs** (Certificates of Proof of Operational Effectiveness) — machine-verifiable, cryptographically-signed certificates proving that a control worked at a specific time.

**Format**: W3C JWT-VC (Verifiable Credentials) with Ed25519 signatures
**Standards**: IETF SCITT, OpenID SSF/CAEP, DID:web

### Corsair's Six Primitives

| Primitive | Description |
|-----------|-------------|
| `SIGN` | Create a CPOE from input evidence |
| `VERIFY` | Verify an existing CPOE |
| `DIFF` | Compare two CPOEs to detect state changes |
| `LOG` | Append CPOE to an immutable audit log |
| `PUBLISH` | Publish CPOEs to external systems |
| `SIGNAL` | Emit compliance signals to downstream consumers |

### CPOE Input Format

Corsair accepts either a **generic JSON format** or a **mapping pack** targeting specific tool output:

**Generic format:**
```json
{
  "metadata": {
    "source": "ocean",
    "version": "3.0.0",
    "timestamp": "2026-02-26T10:00:00Z"
  },
  "controls": [
    {
      "id": "mfa.enforcement",
      "status": "effective",
      "confidence": "high",
      "evidence": { ... }
    }
  ],
  "assessmentContext": {
    "collector": "ocean",
    "collectionMethod": "passive_observation"
  }
}
```

**Mapping pack**: A Corsair mapping pack targets OCEAN's output format specifically, translating `ControlStatus` records directly into CPOE predicates without manual JSON construction.

### OCEAN → Corsair Integration Patterns

**Pattern 1 — CLI Pipe:**
```bash
ocean collect okta.mfa_policy | corsair sign --output cpoe.jwt
```

**Pattern 2 — REST API:**
```bash
ocean serve &
# Corsair polls OCEAN's API and signs new evidence on schedule
corsair sign --source http://localhost:8080/api/v1/evidence
```

**Pattern 3 — OCEAN Mapping Pack:**
```bash
corsair sign --mapping-pack ocean --input ocean-evidence.json
```

### What OCEAN Outputs for Corsair

OCEAN's `ControlStatus` JSON becomes the body of the Corsair CPOE. Key fields Corsair uses:
- `control_id` → CPOE subject identifier
- `status` (effective|ineffective|unknown|partial) → CPOE assertion
- `confidence` (high|medium|low) → CPOE confidence claim
- `evidence_ids` → CPOE evidence references
- `timestamp` → CPOE issuance time

### Architecture: OCEAN + Corsair Together

```
Source System APIs
      |
      | (OCEAN Collectors + Testers)
      v
  Evidence Records
      |
      | (OCEAN CEL Evaluation)
      v
  ControlStatus JSON
      |
      | (Corsair Mapping Pack or CLI pipe)
      v
  CPOE (Certificate of Proof of Operational Effectiveness)
      |
      | (Corsair PUBLISH + SIGNAL)
      v
  GRC Platforms / Auditors / StatusPage-style UIs
```

### When to Use Corsair

Corsair is **optional** but recommended when:
- Audit-grade evidence is required (auditors need independent verification)
- Evidence will be shared with parties who don't trust the OCEAN operator
- Compliance frameworks require cryptographic non-repudiation
- Building a "StatusPage for Compliance" with verifiable uptime metrics

### References

- [Corsair Website](https://grcorsair.com)
- [Corsair GitHub](https://github.com/grcorsair/corsair)
- [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model/)
- [IETF SCITT Architecture](https://www.ietf.org/archive/id/draft-ietf-scitt-architecture-07.txt)

---

## Active Control Testing Patterns

### Source: https://github.com/redcanaryco/atomic-red-team

**Decision**: OCEAN Testers follow Atomic Red Team's philosophy but adapted for compliance
**Rationale**: ART's 1,770+ tests prove the model for self-contained, mapped-to-framework tests
**Key Difference**: ART tests attack techniques to validate detection; OCEAN tests attempt control bypasses to validate prevention

### Compliance Testing vs. Offensive Security

| Aspect | OCEAN (Compliance) | Offensive Security |
|--------|-------------------|-------------------|
| **Goal** | Prove controls work | Find vulnerabilities |
| **Scope** | Pre-defined, narrow | Broad, exploratory |
| **Frequency** | Continuous/scheduled | Periodic engagements |
| **Authorization** | Mandatory pre-flight | Engagement-scoped |
| **Cleanup** | Mandatory, automated | Best-effort |
| **Output** | Compliance evidence | Vulnerability report |

### Safety Classification System

Based on ISO 27002 Control 8.31 and automated testing best practices:

| Level | Definition | Authorization | Environment |
|-------|-----------|---------------|-------------|
| **Safe** | Read-only probes | Auto-approved | Any including production |
| **Observable** | Creates audit entries, no state changes | Explicit confirmation | Production with caution |
| **Reversible** | State changes automatically reversed | Explicit + cleanup readiness | Staging preferred |
| **Destructive** | May cause permanent changes | Explicit + warning + manual review | Isolated only |

### Pre-Flight Validation Pattern

1. Authorization verification → 2. Scope validation → 3. Environment classification → 4. Rollback readiness → 5. Monitoring active

### Test Transcript Pattern

```yaml
test_transcript:
  initiator: "ocean-scheduler"
  test_id: "okta.mfa_bypass"
  safety_classification: "safe"
  environment: "production"
  actions_attempted:
    - action: "POST /api/v1/authn (no MFA token)"
      timestamp: "2026-02-13T10:30:01Z"
  observations:
    - observation: "401 Unauthorized - MFA required"
      expected: true
  cleanup_actions: []
  verdict: "control_effective"
```

### References

- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [ISO 27002 Control 8.31](https://www.isms.online/iso-27002/control-8-31-separation-of-development-test-and-production-environments/)

---

## Design Implications

### Schema Design (updated for v2.0.0)

**Adopt from OCSF**: Hierarchical taxonomy, shared dictionary, profiles, extensions, observables, temporal conventions.

**New for v2.0.0**:
- `confidence_level` on all evidence (passive_observation | active_verification)
- `test_transcript` structure for active test results
- `attestation` reference linking to DSSE envelope
- Content-addressable artifact references (SHA-256 digests)

### Module Architecture (updated for v2.0.0)

**Dual-mode**: Collectors (passive) + Testers (active) with shared Module base.

### Evaluation Engine (new for v2.0.0)

**CEL-based**: Compile-once evaluate-many with content-addressed expressions for audit trail.

### Architecture Stack (updated for v3.0.0)

```
┌──────────────────────────────────────────────────────┐
│   GRC Platforms (GigaChad, CISO Assist) + Auditors   │
├──────────────────────────────────────────────────────┤
│              StatusPage-style UIs                    │
├────────────────────────┬─────────────────────────────┤
│   Corsair (optional)   │                             │
│   Cryptographic        │   OCEAN                     │
│   Provenance / CPOEs   │   Evidence + Active Testing │
│                        │   + CEL Evaluation          │
├────────────────────────┴─────────────────────────────┤
│        Source APIs (Okta, AWS, GitHub, etc.)         │
└──────────────────────────────────────────────────────┘
```

OCEAN and Corsair are complementary, not competing. OCEAN focuses on evidence quality; Corsair focuses on evidence trustworthiness. Use OCEAN alone for internal continuous monitoring; add Corsair when audit-grade independent verification is required.
