# OCEAN Module Catalog

OCEAN ships 52 modules across 4 source systems. Each module is either an
**Observer** (passive evidence collection) or a **Tester** (active control
verification).

---

## GitHub (29 modules)

### Observers

| Module ID | Control | API Endpoint | Config Keys |
|-----------|---------|-------------|-------------|
| `github.branch_protection` | Branch protection rules | `GET /repos/{owner}/{repo}/branches/{branch}/protection` | `GITHUB_TOKEN`, `GITHUB_OWNER`, `GITHUB_REPO` |
| `github.repo_security` | Repository security settings | `GET /repos/{owner}/{repo}` | `GITHUB_TOKEN`, `GITHUB_OWNER`, `GITHUB_REPO` |
| `github.actions_permissions` | Actions permissions | `GET /repos/{owner}/{repo}/actions/permissions` | `GITHUB_TOKEN`, `GITHUB_OWNER`, `GITHUB_REPO` |
| `github.dependabot_alerts` | Dependabot vulnerability alerts | `GET /repos/{owner}/{repo}/dependabot/alerts` | `GITHUB_TOKEN`, `GITHUB_OWNER`, `GITHUB_REPO` |
| `github.secret_scanning_alerts` | Secret scanning alerts | `GET /repos/{owner}/{repo}/secret-scanning/alerts` | `GITHUB_TOKEN`, `GITHUB_OWNER`, `GITHUB_REPO` |
| `github.code_scanning_alerts` | Code scanning alerts | `GET /repos/{owner}/{repo}/code-scanning/alerts` | `GITHUB_TOKEN`, `GITHUB_OWNER`, `GITHUB_REPO` |
| `github.workflow_permissions` | Default workflow permissions | `GET /repos/{owner}/{repo}/actions/permissions/workflow` | `GITHUB_TOKEN`, `GITHUB_OWNER`, `GITHUB_REPO` |
| `github.org_mfa_enforcement` | 2FA required for all members (GH-1.1) | `GET /orgs/{org}` | `GITHUB_TOKEN`, `GITHUB_ORG` |
| `github.org_base_permissions` | Member base permissions (GH-1.2) | `GET /orgs/{org}` | `GITHUB_TOKEN`, `GITHUB_ORG` |
| `github.org_admin_audit` | Admin audit log enabled (GH-1.3) | `GET /orgs/{org}` | `GITHUB_TOKEN`, `GITHUB_ORG` |
| `github.saml_sso` | SAML SSO enforcement (GHEC only) | `GET /orgs/{org}/credential-authorizations` | `GITHUB_TOKEN`, `GITHUB_ORG` |
| `github.pat_policy` | PAT expiration policy | `GET /orgs/{org}` | `GITHUB_TOKEN`, `GITHUB_ORG` |
| `github.org_rulesets` | Org branch rulesets (GH-2.3) | `GET /orgs/{org}/rulesets` | `GITHUB_TOKEN`, `GITHUB_ORG` |
| `github.commit_signing` | Required commit signing (GH-2.4) | `GET /repos/{owner}/{repo}/branches/{branch}/protection/required_signatures` | `GITHUB_TOKEN`, `GITHUB_OWNER`, `GITHUB_REPO` |
| `github.actions_allowed` | Actions allowed policy (GH-3.1) | `GET /orgs/{org}/actions/permissions` | `GITHUB_TOKEN`, `GITHUB_ORG` |
| `github.runner_config` | Self-hosted runner detection (GH-3.2) | `GET /orgs/{org}/actions/runners` | `GITHUB_TOKEN`, `GITHUB_ORG` |
| `github.environment_protection` | Environment protection rules (GH-3.3) | `GET /repos/{owner}/{repo}/environments` | `GITHUB_TOKEN`, `GITHUB_OWNER`, `GITHUB_REPO` |
| `github.oidc_config` | Actions OIDC sub-claim config (GH-5.2) | `GET /orgs/{org}/actions/oidc/customization/sub` | `GITHUB_TOKEN`, `GITHUB_ORG` |
| `github.oauth_apps` | OAuth app authorizations | `GET /orgs/{org}/oauth_authorizations` | `GITHUB_TOKEN`, `GITHUB_ORG` |
| `github.installed_apps` | Installed GitHub Apps | `GET /orgs/{org}/installations` | `GITHUB_TOKEN`, `GITHUB_ORG` |
| `github.dependency_review` | Dependency review enforcement | `GET /repos/{owner}/{repo}/dependency-graph` | `GITHUB_TOKEN`, `GITHUB_OWNER`, `GITHUB_REPO` |
| `github.audit_log_streaming` | Audit log streaming (GHEC only) | `GET /orgs/{org}/audit-log/streams` | `GITHUB_TOKEN`, `GITHUB_ORG` |
| `github.security_config` | Org security configuration (GHEC only) | `GET /orgs/{org}/security-configuration` | `GITHUB_TOKEN`, `GITHUB_ORG` |
| `github.copilot_governance` | Copilot usage policies | `GET /orgs/{org}/copilot/billing` | `GITHUB_TOKEN`, `GITHUB_ORG` |

### Testers

| Module ID | What it tests | Safety | Config Keys |
|-----------|---------------|--------|-------------|
| `github.branch_bypass` | Branch protection bypass | Observable | `GITHUB_TOKEN`, `GITHUB_OWNER`, `GITHUB_REPO` |
| `github.secret_push` | Secret push protection | Observable | `GITHUB_TOKEN`, `GITHUB_OWNER`, `GITHUB_REPO` |
| `github.actions_restriction` | Actions restriction enforcement | Safe | `GITHUB_TOKEN`, `GITHUB_ORG` |
| `github.unsigned_commit` | Unsigned commit detection | Observable | `GITHUB_TOKEN`, `GITHUB_OWNER`, `GITHUB_REPO` |
| `github.workflow_injection` | Workflow expression injection | Observable | `GITHUB_TOKEN`, `GITHUB_OWNER`, `GITHUB_REPO` |
| `github.action_pin_audit` | Unpinned Actions detection | Safe | `GITHUB_TOKEN`, `GITHUB_OWNER`, `GITHUB_REPO` |

---

## Okta (15 modules)

### Observers

| Module ID | Control | API Endpoint | Config Keys |
|-----------|---------|-------------|-------------|
| `okta.mfa_policy` | MFA policy enforcement | `GET /api/v1/policies?type=MFA_ENROLL` | `OKTA_DOMAIN`, `OKTA_API_TOKEN` |
| `okta.mfa_enrollment_population` | MFA enrollment population | `GET /api/v1/groups/{id}/users` | `OKTA_DOMAIN`, `OKTA_API_TOKEN` |
| `okta.password_policy` | Password policy strength | `GET /api/v1/policies?type=PASSWORD` | `OKTA_DOMAIN`, `OKTA_API_TOKEN` |
| `okta.session_policy` | Session lifetime policy | `GET /api/v1/policies?type=OKTA_SIGN_ON` | `OKTA_DOMAIN`, `OKTA_API_TOKEN` |
| `okta.recovery_policy` | Account recovery policy | `GET /api/v1/policies?type=OKTA_SIGN_ON` | `OKTA_DOMAIN`, `OKTA_API_TOKEN` |
| `okta.threat_insight` | ThreatInsight configuration | `GET /api/v1/threats/configuration` | `OKTA_DOMAIN`, `OKTA_API_TOKEN` |
| `okta.system_log_streaming` | System log streaming | `GET /api/v1/logStreams` | `OKTA_DOMAIN`, `OKTA_API_TOKEN` |
| `okta.behavior_detection` | Behavior detection rules | `GET /api/v1/behaviors` | `OKTA_DOMAIN`, `OKTA_API_TOKEN` |
| `okta.authenticators` | Authenticator configuration | `GET /api/v1/authenticators` | `OKTA_DOMAIN`, `OKTA_API_TOKEN` |
| `okta.admin_roles` | Admin role assignments | `GET /api/v1/iam/roles` | `OKTA_DOMAIN`, `OKTA_API_TOKEN` |
| `okta.network_zones` | Network zone configuration | `GET /api/v1/zones` | `OKTA_DOMAIN`, `OKTA_API_TOKEN` |
| `okta.oauth_app_policy` | OAuth app sign-on policy | `GET /api/v1/policies?type=ACCESS_POLICY` | `OKTA_DOMAIN`, `OKTA_API_TOKEN` |

### Testers

| Module ID | What it tests | Safety | Config Keys |
|-----------|---------------|--------|-------------|
| `okta.mfa_bypass` | MFA policy bypass | Observable | `OKTA_DOMAIN`, `OKTA_API_TOKEN` |
| `okta.admin_ip_restriction` | Admin IP restriction enforcement | Observable | `OKTA_DOMAIN`, `OKTA_API_TOKEN` |
| `okta.default_policy_bypass` | Default policy bypass | Observable | `OKTA_DOMAIN`, `OKTA_API_TOKEN` |
| `okta.pr_mfa_downgrade` | PR-triggered MFA downgrade | Observable | `OKTA_DOMAIN`, `OKTA_API_TOKEN` |

---

## AWS (2 modules)

| Module ID | Type | Control | Config Keys |
|-----------|------|---------|-------------|
| `aws.iam` | Observer | IAM policy configuration | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION` |
| `aws.s3_public_access` | Tester | S3 public access block | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`, `S3_BUCKET` |

---

## Azure (2 modules)

| Module ID | Type | Control | Config Keys |
|-----------|------|---------|-------------|
| `azure.conditional_access` | Observer | Conditional Access policies | `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` |
| `azure.mfa_bypass` | Tester | MFA bypass attempt | `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` |

---

## Mock (testing only)

These modules are excluded from production use. They serve as reference
implementations and for integration testing.

| Module ID | Type | Purpose |
|-----------|------|---------|
| `mock.test` | Observer | Returns a single synthetic Evidence record |
| `mock.network` | Observer | Simulates a network-dependent observation |
| `mock.safety_test` | Tester | Demonstrates the safety classification system |

---

## Writing a Custom Module

All modules implement the `Module` trait plus either `Observer` or `Tester`:

```rust
use ocean::module::{Module, Observer, CredentialReq};
use ocean::evidence::Evidence;
use std::collections::HashMap;
use anyhow::Result;

pub struct MyObserver;

impl Module for MyObserver {
    fn id(&self) -> &str { "myco.my_control" }
    fn name(&self) -> &str { "My Control Observer" }
    fn version(&self) -> &str { "0.1.0" }
    fn source_system(&self) -> &str { "myco" }
    fn evidence_types(&self) -> &[i32] { &[1001] }
    fn credential_requirements(&self) -> Vec<CredentialReq> {
        vec![CredentialReq {
            name: "MY_API_TOKEN".to_string(),
            cred_type: "api_token".to_string(),
            description: "API token for MyService".to_string(),
            required: true,
        }]
    }
}

impl Observer for MyObserver {
    fn observe(&self, config: &HashMap<String, String>) -> Result<Vec<Evidence>> {
        // Call your API and return Evidence records
        todo!()
    }
}
```

Register in `src/modules/observers/mod.rs`:

```rust
pub mod my_observer;
// in register_all():
registry.register_observer(Arc::new(my_observer::MyObserver));
```

See `src/modules/observers/github_org_mfa.rs` for a complete worked example.

---

## Safety Classifications (Testers only)

| Level | Description | Permitted scopes |
|-------|-------------|-----------------|
| `Safe` | Read-only verification, no side effects | Production, Staging, Isolated |
| `Observable` | Leaves an observable log trace | Staging, Isolated |
| `Reversible` | Makes a change then rolls it back | Isolated only |
| `Destructive` | Irreversible side effects | Isolated only |

A schedule's `max_safety_level` controls which testers run. Setting
`max_safety_level: safe` skips all `Observable`, `Reversible`, and
`Destructive` testers automatically.
