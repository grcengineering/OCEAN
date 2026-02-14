# OCEAN -- Open Control Evidence Acquisition Normalizer

**The "Metasploit for GRC"** -- an open-source CLI tool and Go library for evidence acquisition, active control testing, and normalization powering continuous compliance monitoring.

Imagine a standardized API model and data model for retrieving control evidence. Something that security/GRC practitioners, control owners, and auditors could consistently validate the completeness and accuracy of and thus trust as a gold standard source of truth for compliance audits of all kinds.

That is what OCEAN builds.

The conversation that started it all: [LinkedIn post](https://www.linkedin.com/posts/ayoubfandi_grcengineering-complianceautomation-helpmyfriendjson-activity-7308816365061062656-HJXT)

## What OCEAN Does

1. **Collect** evidence from diverse systems (Okta, AWS, GitHub, Cloudflare, etc.) via pluggable collector modules
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

# List available modules
./ocean modules list

# Collect evidence using the mock module
./ocean collect --module mock.test --control mock.mfa_enforcement

# Run an active control test
./ocean test --module mock.safety_test --control mock.mfa_enforcement

# Evaluate control effectiveness
./ocean evaluate --control mock.mfa_enforcement

# Start the API server
./ocean serve --port 8080 --auth-token "your-token"
```

See [docs/quickstart.md](docs/quickstart.md) for a detailed walkthrough.

## Architecture

```
ocean
  cmd/ocean/           CLI entrypoint
  internal/
    api/               REST API server (10 endpoints)
    attestation/       Cryptographic provenance (in-toto DSSE)
    cli/               Cobra command definitions
    config/            Configuration management
    control/           Control definitions, evaluation, framework mappings
    eval/              CEL expression engine with presets and versioning
    evidence/          Core evidence schema (OCSF-inspired)
    module/            Module interfaces, registry, safety classification
    scheduler/         Cron-based continuous monitoring
    secrets/           Credential resolution (env-based)
    storage/           Persistence interface + SQLite implementation
  modules/
    collectors/mock/   Reference collector implementation
    testers/mock/      Reference tester implementation
  controls/
    iam/               IAM control definitions (MFA enforcement)
    network/           Network control definitions (WAF protection)
    frameworks/        Framework mappings (SOC 2, ISO 27001, etc.)
  pkg/
    ocean/             Public Go library API for embedding
    schema/            Stable public types for library consumers
  docs/                Documentation
```

## Key Concepts

### Evidence-First Design

Every piece of data in OCEAN is an **evidence record** with cryptographic provenance. Evidence is immutable, content-addressed, and signed using in-toto DSSE envelopes.

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

## Building

```bash
# Standard build
make build

# Run tests
make test

# Cross-compile for all platforms
make cross-compile

# Docker build
docker build -t ocean .
```

## Documentation

- [Quick Start Guide](docs/quickstart.md) -- Get running in minutes
- [Module Development Guide](docs/modules.md) -- Create custom collectors and testers
- [API Documentation](docs/api.md) -- REST API reference

## Technology Stack

- **Language**: Go (single binary, zero dependencies)
- **Storage**: SQLite (default), PostgreSQL (enterprise)
- **Evaluation**: CEL (Common Expression Language)
- **Attestation**: in-toto DSSE (Dead Simple Signing Envelope)
- **Schema**: OCSF-inspired hierarchical taxonomy

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
