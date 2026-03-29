# Changelog

All notable changes to OCEAN are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] — 2026-03-27

### Overview

OCEAN v0.1.0 is the first release of the Open Control Evidence
Assessment Normalizer — the "Metasploit for GRC". This release ships 52
modules across GitHub, Okta, AWS, and Azure, a full attestation chain,
CEL-based evaluation, REST API, scheduling, and multi-platform binaries.

### Added

#### Core Infrastructure
- **DSSE attestation** (`ocean::attest`) — Ed25519 signing/verification of
  Evidence records using the in-toto Dead Simple Signing Envelope spec
- **CEL evaluation engine** (`ocean::eval`) — `CelEngine` dispatches to native
  presets (`all_effective`, `any_effective`, `active_verified`) or arbitrary
  CEL expressions with variables: `evidence_count`, `effective_count`,
  `ineffective_count`, `unknown_count`, `active_count`, `has_active`
- **Composite control evaluation** (`ocean::control::composite`) — evaluate
  multi-component controls spanning multiple source systems
- **REST API** (`ocean serve`) — axum-based server with token auth, evidence
  listing/retrieval, control status/history, module listing, schedule CRUD
- **SQLite storage** — evidence, control status, schedules, schedule runs with
  full query support and cascade deletes
- **Scheduler** — cron-based schedule execution with partial failure handling,
  safety level enforcement, and run history
- **Test infrastructure** — `MockHTTPServer` in `src/testutil.rs`, integration
  test harness (`tests/integration/`), e2e CLI test harness (`tests/e2e/`)

#### GitHub Observers (24 total)
| Module ID | Control |
|-----------|---------|
| `github.branch_protection` | Branch protection rules (existing) |
| `github.repo_security` | Repository security settings |
| `github.actions_permissions` | Actions permissions |
| `github.dependabot_alerts` | Dependabot vulnerability alerts |
| `github.secret_scanning_alerts` | Secret scanning alerts |
| `github.code_scanning_alerts` | Code scanning alerts |
| `github.workflow_permissions` | Workflow permissions |
| `github.org_mfa_enforcement` | Org-wide MFA enforcement (GH-1.1) |
| `github.org_base_permissions` | Org member base permissions (GH-1.2) |
| `github.org_admin_audit` | Admin audit log enabled (GH-1.3) |
| `github.saml_sso` | SAML SSO enforcement (GHEC) |
| `github.pat_policy` | Personal access token policy |
| `github.org_rulesets` | Org branch rulesets (GH-2.3) |
| `github.commit_signing` | Required commit signing (GH-2.4) |
| `github.actions_allowed` | Actions allowed policy (GH-3.1) |
| `github.runner_config` | Self-hosted runner detection (GH-3.2) |
| `github.environment_protection` | Environment protection rules (GH-3.3) |
| `github.oidc_config` | Actions OIDC sub-claim config (GH-5.2) |
| `github.oauth_apps` | OAuth app authorizations |
| `github.installed_apps` | Installed GitHub Apps |
| `github.dependency_review` | Dependency review enforcement |
| `github.audit_log_streaming` | Audit log streaming (GHEC) |
| `github.security_config` | Org security configuration (GHEC) |
| `github.copilot_governance` | Copilot usage policies |

#### GitHub Testers (5 total)
| Module ID | What it tests |
|-----------|---------------|
| `github.branch_bypass` | Branch protection bypass (existing) |
| `github.secret_push` | Secret push protection (existing) |
| `github.actions_restriction` | Actions restriction enforcement |
| `github.unsigned_commit` | Unsigned commit detection |
| `github.workflow_injection` | Workflow expression injection |
| `github.action_pin_audit` | Unpinned Actions detection |

#### Okta Observers (11 total)
| Module ID | Control |
|-----------|---------|
| `okta.mfa_policy` | MFA policy enforcement (existing) |
| `okta.mfa_enrollment_population` | MFA enrollment population |
| `okta.password_policy` | Password policy strength |
| `okta.session_policy` | Session lifetime policy |
| `okta.recovery_policy` | Account recovery policy |
| `okta.threat_insight` | ThreatInsight configuration |
| `okta.system_log_streaming` | System log streaming |
| `okta.behavior_detection` | Behavior detection rules |
| `okta.authenticators` | Authenticator configuration |
| `okta.admin_roles` | Admin role assignments |
| `okta.network_zones` | Network zone configuration |
| `okta.oauth_app_policy` | OAuth app sign-on policy |

#### Okta Testers (3 total)
| Module ID | What it tests |
|-----------|---------------|
| `okta.mfa_bypass` | MFA policy bypass (existing) |
| `okta.admin_ip_restriction` | Admin IP restriction enforcement |
| `okta.default_policy_bypass` | Default policy bypass |
| `okta.pr_mfa_downgrade` | PR-triggered MFA downgrade |

#### AWS
| Module ID | Type | Control |
|-----------|------|---------|
| `aws.iam` | Observer | IAM policy configuration (existing) |
| `aws.s3_public_access` | Tester | S3 public access block (existing) |

#### Azure
| Module ID | Type | Control |
|-----------|------|---------|
| `azure.conditional_access` | Observer | Conditional Access policies (existing) |
| `azure.mfa_bypass` | Tester | MFA bypass attempt |

#### Mock (testing only)
| Module ID | Type |
|-----------|------|
| `mock.test` | Observer |
| `mock.network` | Observer |
| `mock.safety_test` | Tester |

### CI/CD
- GitHub Actions CI: unit, integration, e2e test tiers + nightly Rust matrix
- `cargo audit` security vulnerability scanning in CI
- Release workflow: 5-platform binary matrix (Linux amd64/arm64, macOS
  Intel/Apple Silicon, Windows amd64) with checksums and GitHub Release
- Docker image: multi-stage build with distroless base (`gcr.io/distroless/cc-debian12`)
  published to GHCR

### Makefile targets
- `make test-unit` — unit tests only
- `make test-integration` — integration tests
- `make test-e2e` — end-to-end CLI tests
- `make test-all` — complete test suite
- `make coverage-check` — coverage with 80% minimum threshold

---

## [0.1.0] — 2025-12-01

### Added
- Initial project skeleton: CLI, storage (SQLite), scheduler, module registry
- Core evidence schema (OCSF-inspired)
- First 9 modules: `mock.test`, `mock.network`, `mock.safety_test`,
  `aws.iam`, `aws.s3_public_access`, `github.branch_protection`,
  `github.secret_push`, `okta.mfa_policy`, `okta.mfa_bypass`

---

[0.1.0]: https://github.com/grcengineering/ocean/releases/tag/v0.1.0
