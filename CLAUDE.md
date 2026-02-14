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

## Session Notes

See `docs/SESSION-2026-01-17.md` for detailed session log including issues encountered.
