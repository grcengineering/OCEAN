# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

Only the latest release receives security patches. We recommend always running the most recent version.

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, report vulnerabilities through [GitHub Security Advisories](https://github.com/grcengineering/ocean/security/advisories/new).

### What to Include

- Description of the vulnerability
- Steps to reproduce (proof of concept if possible)
- Impact assessment (what an attacker could achieve)
- Affected version(s)
- Any suggested fix or mitigation

### Response Timeline

| Action | SLA |
| ------ | --- |
| Acknowledgment of report | **72 hours** |
| Initial triage and severity assessment | **5 business days** |
| Patch for critical severity (CVSS >= 9.0) | **7 days** |
| Patch for high severity (CVSS 7.0-8.9) | **14 days** |
| Patch for medium severity (CVSS 4.0-6.9) | **30 days** |
| Patch for low severity (CVSS < 4.0) | **90 days** |

### Process

1. **Report** — Submit via GitHub Security Advisory (preferred) or email security@grc.engineering.
2. **Acknowledge** — We confirm receipt within 72 hours and assign a tracking ID.
3. **Triage** — We assess severity using CVSS v3.1/v4.0 and determine affected versions.
4. **Fix** — We develop and test a patch within the SLA above.
5. **Disclose** — We publish a GitHub Security Advisory with the fix. We follow coordinated disclosure — we will not disclose before a fix is available unless 90 days have elapsed since the initial report.
6. **Credit** — We credit reporters in the advisory unless they prefer to remain anonymous.

## Security Practices

OCEAN follows these security practices:

- **Dependency auditing**: `cargo-audit` runs in CI on every push and PR, failing builds on known vulnerabilities.
- **Static analysis**: Clippy with `-D warnings` enforced in CI.
- **No unsafe code**: We minimize use of `unsafe` blocks. Any `unsafe` usage requires justification and review.
- **Input validation**: All CLI inputs and external data (API responses, file contents) are validated at system boundaries.
- **Credential handling**: OCEAN processes API credentials for evidence collection. Credentials are never logged, stored in plaintext, or included in evidence output.
- **Supply chain**: We use `Cargo.lock` for reproducible builds and audit dependencies for known vulnerabilities.

## Scope

This security policy covers:

- The `ocean` CLI binary and library
- All GRC check modules in the `checks/` directory
- The OCEAN container image published to GHCR

Out of scope:

- Third-party infrastructure that OCEAN connects to (cloud provider APIs, SaaS platforms)
- Vulnerabilities in upstream dependencies (report those to the respective maintainers, but do let us know so we can assess impact)
