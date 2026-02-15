# OCEAN -- Open Control Evidence Acquisition Normalizer

**The "Metasploit for GRC"** -- an open-source CLI tool and Go library for evidence acquisition, active control testing, and normalization powering continuous compliance monitoring.

Imagine a standardized API model and data model for retrieving control evidence. Something that security/GRC practitioners, control owners, and auditors could consistently validate the completeness and accuracy of and thus trust as a gold standard source of truth for compliance audits of all kinds.

That is what OCEAN builds.

The conversation that started it all: [LinkedIn post](https://www.linkedin.com/posts/ayoubfandi_grcengineering-complianceautomation-helpmyfriendjson-activity-7308816365061062656-HJXT)

## What OCEAN Does

1. **Collect** evidence from diverse systems (Okta, AWS, GitHub, etc.) via pluggable collector modules
2. **Test** control effectiveness through active verification with safety-classified tester modules
3. **Normalize** evidence to a consistent OCSF-inspired schema with full provenance
4. **Evaluate** control effectiveness using flexible CEL expressions or built-in presets
5. **Store** evidence with cryptographic attestation (in-toto DSSE) for tamper-evident audit trails
6. **Monitor** continuously with cron-based scheduling and uptime percentage tracking
7. **Expose** a REST API for integration with external GRC platforms

## Quick Start

```bash
# Build from source
git clone https://github.com/grcengineering/ocean.git
cd ocean
make build

# Generate signing keys for cryptographic attestation
./ocean keys generate

# List available modules
./ocean modules list

# Collect evidence using the mock collector
./ocean collect mock.test

# Run an active control test
./ocean test mock.safety_test --target staging

# Dual-mode verification (collect + test + evaluate)
./ocean verify mock.mfa_enforcement

# Verify cryptographic provenance
./ocean verify-provenance run --evidence <evidence-id>

# Start the API server
./ocean serve --port 8080 --auth-token "your-token"
```

See [docs/quickstart.md](docs/quickstart.md) for a detailed walkthrough.

## Modules

OCEAN ships with 9 modules across 4 source systems:

| Module | Type | Source | Safety Class | Description |
|--------|------|--------|-------------|-------------|
| `aws.iam` | collector | AWS | - | IAM user enumeration, MFA status, access key age |
| `aws.s3_public_access` | tester | AWS | safe | Probes S3 buckets for public access |
| `github.branch_protection` | collector | GitHub | - | Branch protection rule collection |
| `github.secret_push` | tester | GitHub | observable | Tests secret push protection |
| `mock.test` | collector | mock | - | Simulated MFA policy collection |
| `mock.network` | collector | mock | - | Simulated network/WAF evidence |
| `mock.safety_test` | tester | mock | safe | Simulated MFA bypass attempt |
| `okta.mfa_policy` | collector | Okta | - | MFA enrollment policy collection |
| `okta.mfa_bypass` | tester | Okta | safe | Attempts authentication without MFA |

## Architecture

```
ocean
  cmd/ocean/           CLI entrypoint
  internal/
    api/               REST API server (11 endpoints)
    attestation/       Cryptographic provenance (in-toto DSSE, Ed25519)
    cli/               Cobra command definitions
    config/            Configuration management (YAML + env vars)
    control/           Control definitions, CEL evaluation, framework mappings
    eval/              CEL expression engine with presets and versioning
    evidence/          Core evidence schema (OCSF-inspired)
    module/            Module interfaces, registry, executor, safety classification
    scheduler/         Cron-based continuous monitoring
    secrets/           Credential providers (env, Vault, AWS Secrets Manager)
    storage/           Persistence interface + SQLite implementation
  modules/
    collectors/
      aws/             AWS IAM collector (SigV4 signing, stdlib only)
      github/          GitHub branch protection collector (REST v3)
      mock/            Reference collector implementation
      okta/            Okta MFA policy collector (rate-limited)
    testers/
      aws/             S3 public access tester
      github/          Secret push protection tester
      mock/            Reference tester implementation
      okta/            MFA bypass tester
  controls/
    iam/               IAM control definitions (MFA enforcement)
    network/           Network control definitions (WAF protection)
    frameworks/        Framework mappings (SOC 2, ISO 27001, NIST CSF, CIS)
  pkg/
    ocean/             Public Go library API for embedding
    schema/            Stable public types for library consumers
  schemas/             JSON Schema definitions
  docs/                Documentation
```

## Key Concepts

### Evidence-First Design

Every piece of data in OCEAN is an **evidence record** with cryptographic provenance. Evidence is immutable, content-addressed, and signed using in-toto DSSE envelopes with Ed25519 keys.

### Confidence Levels

| Level | Source | Meaning |
|---|---|---|
| `passive_observation` | Collectors | Read-only API observation |
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
  cel: "status_counts.effective > 0 && status_counts.ineffective == 0 && has_active"
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

## Building

```bash
# Standard build
make build

# Run tests
make test

# Stripped release binary
make release

# Run linter
make lint

# Docker build
docker build -t ocean .
```

## Configuration

OCEAN uses a YAML config file at `~/.ocean/config.yaml` with sensible defaults:

```yaml
storage_path: ~/.ocean/ocean.db
log_level: info
key_path: ~/.ocean/keys
controls_dir: controls
output_format: json
server:
  port: 8080
  auth_token: ""  # Set via --auth-token or OCEAN_AUTH_TOKEN env var
```

Environment variables override config file values:
- `OCEAN_STORAGE_PATH` -- SQLite database path
- `OCEAN_LOG_LEVEL` -- Logging verbosity
- `OCEAN_KEY_PATH` -- Directory for signing keys
- `OCEAN_AUTH_TOKEN` -- Bearer token for API authentication

## Documentation

- [Quick Start Guide](docs/quickstart.md) -- Get running in minutes
- [Module Development Guide](docs/modules.md) -- Create custom collectors and testers
- [API Documentation](docs/api.md) -- REST API reference

## Technology Stack

- **Language**: Go (single binary, zero runtime dependencies)
- **Storage**: SQLite (via modernc.org/sqlite, pure Go)
- **Evaluation**: CEL (Common Expression Language)
- **Attestation**: in-toto DSSE (Dead Simple Signing Envelope) with Ed25519
- **Schema**: OCSF-inspired hierarchical taxonomy
- **CLI**: Cobra + zerolog

## Contributing

OCEAN is open source under the Apache 2.0 license.

1. Fork the repository
2. Create a feature branch
3. Write tests first (TDD required)
4. Implement your changes
5. Run `make test` and `make build`
6. Submit a pull request

When creating new modules, follow the [Module Development Guide](docs/modules.md).

## License

Apache 2.0 -- see [LICENSE](LICENSE) for details.
