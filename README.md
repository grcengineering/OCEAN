# OCEAN — Open Control Evidence Assessment Normalizer

[![CI](https://github.com/grcengineering/OCEAN/actions/workflows/ci.yml/badge.svg)](https://github.com/grcengineering/OCEAN/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/grcengineering/OCEAN/branch/main/graph/badge.svg)](https://codecov.io/gh/grcengineering/OCEAN)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

**The "Metasploit for GRC"** — an open-source CLI tool and Rust library for evidence acquisition, active control testing, and normalization powering continuous compliance monitoring.

Imagine a standardized API model and data model for retrieving control evidence. Something that security/GRC practitioners, control owners, and auditors could consistently validate the completeness and accuracy of and thus trust as a gold standard source of truth for compliance audits of all kinds.

That is what OCEAN builds.

The conversation that started it all: [LinkedIn post](https://www.linkedin.com/posts/ayoubfandi_grcengineering-complianceautomation-helpmyfriendjson-activity-7308816365061062656-HJXT)

## What OCEAN Does

1. **Observe** evidence from diverse systems (Okta, AWS, GitHub, etc.) via pluggable observer modules
2. **Test** control effectiveness through active verification with safety-classified tester modules
3. **Normalize** evidence to a consistent OCSF-inspired schema with full provenance
4. **Evaluate** control effectiveness using flexible CEL expressions or built-in presets
5. **Store** evidence in a local SQLite database with structured querying
6. **Monitor** continuously with cron-based scheduling and uptime percentage tracking
7. **Expose** a REST API for integration with external GRC platforms

## Quick Start

```bash
# Build from source (requires Rust stable)
git clone https://github.com/grcengineering/ocean.git
cd ocean
make build

# List available modules
./target/debug/ocean modules list

# Observe evidence using the mock observer
./target/debug/ocean observe mock.test

# Run an active control test
./target/debug/ocean test mock.safety_test --target staging

# Evaluate a control against observed evidence
./target/debug/ocean evaluate mock.mfa_enforcement

# Query control history and uptime
./target/debug/ocean history --control mock.mfa_enforcement --days 30

# Start the REST API server
./target/debug/ocean serve --port 8080
```

See [docs/quickstart.md](docs/quickstart.md) for a detailed walkthrough.

## Modules

OCEAN ships with 11 modules across 4 source systems:

| Module | Type | Source | Safety Class | Description |
|--------|------|--------|-------------|-------------|
| `aws.iam` | observer | AWS | — | IAM user enumeration, MFA status, access key age |
| `aws.s3_public_access` | tester | AWS | safe | Probes S3 buckets for public access |
| `github.branch_protection` | observer | GitHub | — | Branch protection rule collection |
| `github.secret_push` | tester | GitHub | observable | Tests secret push protection |
| `mock.test` | observer | mock | — | Simulated MFA policy collection |
| `mock.network` | observer | mock | — | Simulated network/WAF evidence |
| `mock.safety_test` | tester | mock | safe | Simulated MFA bypass attempt |
| `okta.mfa_policy` | observer | Okta | — | MFA enrollment policy + phishing-resistance attributes |
| `okta.mfa_enrollment_population` | observer | Okta | — | Per-user WebAuthn enrollment coverage analysis |
| `okta.mfa_bypass` | tester | Okta | safe | Attempts authentication without MFA |
| `okta.pr_mfa_downgrade` | tester | Okta | safe | Tests whether phishable factor downgrade is possible |

## CLI Commands

```
ocean version                         Print version information
ocean observe <module>                Observe evidence via a observer module
ocean test <module>                   Run an active tester module
ocean modules list [--type observer|tester]
ocean modules validate <id>           Validate module metadata
ocean evaluate <control>              Evaluate a control against evidence
ocean history --control <id>          Query control evaluation history
ocean report --period YYYY-MM-DD:YYYY-MM-DD
ocean schedule add --cron "0 * * * *" --modules mock.test
ocean schedule list
ocean schedule remove <id>
ocean schedule status <id>
ocean serve [--port 8080] [--auth-token TOKEN]
```

## Architecture

```
ocean/
├── src/
│   ├── main.rs             CLI entry point
│   ├── lib.rs              Public SDK re-exports
│   ├── cli/                CLI commands (clap 4 derive)
│   ├── evidence/           Evidence types (OCSF-inspired schema)
│   ├── module/             Module traits, registry, executor, safety
│   ├── storage/            Store trait + SQLite implementation
│   ├── eval/               CEL engine (native presets + the `cel` crate)
│   ├── control/            Control definitions, CEL evaluator, uptime
│   ├── scheduler/          Cron scheduler + module runner
│   ├── secrets/            Credential providers (env, Vault, AWS Secrets Manager)
│   ├── api/                axum REST API (9 endpoints)
│   ├── config/             Config loading (YAML + env vars)
│   └── modules/            Built-in modules
│       ├── observers/     aws, github, okta, mock
│       └── testers/        aws, github, okta, mock
├── controls/               YAML control definitions
├── schemas/                JSON Schema definitions
└── docs/                   Documentation
```

## Key Concepts

### Evidence-First Design

Every piece of data in OCEAN is an **evidence record** with structured provenance. Evidence is normalized to an OCSF-inspired schema and stored with metadata, observables, and findings.

### Confidence Levels

| Level | Source | Meaning |
|---|---|---|
| `passive_observation` | Observers | Read-only API observation |
| `active_verification` | Testers | Proved via active test |

When both types agree, confidence is **high**. Active evidence always takes precedence over passive in case of disagreement.

### Safety Classifications

Testers declare their impact level, which controls where they can run:

| Classification | Impact | Allowed Environments |
|---|---|---|
| `safe` | Read-only | All |
| `observable` | Visible in audit logs | Production, Staging |
| `reversible` | Auto-reversible changes | Staging, Isolated |
| `destructive` | Irreversible changes | Isolated only |

### CEL Evaluation

Control effectiveness is determined by user-defined [CEL expressions](https://github.com/google/cel-spec):

```yaml
evaluation:
  cel: "effective_count > 0 && ineffective_count == 0 && has_active"
```

Built-in presets available: `all_effective`, `any_effective`, `active_verified`.

### Framework Mappings

Controls map to multiple compliance frameworks simultaneously:

```yaml
framework_mappings:
  - framework: soc2
    control: CC6.1
  - framework: iso27001
    control: A.9.4.2
  - framework: nist_csf
    control: PR.AC-7
```

Supported frameworks: SOC 2, ISO 27001, NIST CSF, CIS Controls.

## REST API

When `ocean serve` is running:

| Endpoint | Description |
|---|---|
| `GET /api/v1/health` | Health check |
| `GET /api/v1/evidence` | List evidence (query: control_id, source, limit) |
| `GET /api/v1/evidence/:id` | Get single evidence record |
| `GET /api/v1/controls/:id/status` | Latest control status |
| `GET /api/v1/controls/:id/history` | Control status history (from/to params) |
| `GET /api/v1/modules` | List registered modules |
| `GET /api/v1/schedules` | List schedules |
| `POST /api/v1/schedules` | Create a schedule |
| `DELETE /api/v1/schedules/:id` | Delete a schedule |

Optionally protect with a bearer token: `--auth-token <token>` or `OCEAN_AUTH_TOKEN=<token>`.

## Building

```bash
# Development build
make build

# Run tests (509 tests)
make test

# Release binary (stripped + LTO)
make release

# Lint (clippy + fmt)
make clippy
make fmt-check

# Code coverage (requires cargo-llvm-cov)
make coverage
```

## Configuration

OCEAN uses a YAML config file at `~/.ocean/config.yaml` with sensible defaults:

```yaml
storage_path: ~/.ocean/ocean.db
controls_dir: controls
output_format: json
server:
  port: 8080
  auth_token: ""
```

Environment variables override config file values:

| Variable | Purpose |
|---|---|
| `OCEAN_DB` | SQLite database path |
| `OCEAN_CONTROLS_DIR` | Control YAML directory |
| `OCEAN_PORT` | API server port |
| `OCEAN_AUTH_TOKEN` | Bearer token for API |

## Technology Stack

- **Language**: Rust (single binary, zero runtime dependencies)
- **Storage**: SQLite (via rusqlite, bundled)
- **Evaluation**: CEL (via the `cel` crate + native presets)
- **Schema**: OCSF-inspired hierarchical taxonomy
- **CLI**: clap 4 (derive API)
- **API**: axum 0.7 + tokio
- **HTTP (modules)**: ureq (sync)

## Contributing

OCEAN is open source under the Apache 2.0 license.

1. Fork the repository
2. Create a feature branch
3. Write tests first (TDD required)
4. Implement your changes
5. Run `make test` and `make build`
6. Submit a pull request

When creating new modules, follow the [Module Development Guide](docs/modules.md).

## Author

Created by [Justin Pagano](https://github.com/p4gs).

## License

Apache 2.0 — see [LICENSE](LICENSE) for details.
