# OCEAN Evidence Schema v1.0.0

**Purpose**: Normalized controls evidence taxonomy — the "OCSF for GRC"
**Created**: 2026-02-27
**Status**: Draft — design artifact, not yet implemented
**Builds on**: `grc-schema-research.md`, `data-model.md`

---

## Overview

This document defines the **OCEAN evidence schema** from first principles: what controls OCEAN
assesses, what systems evidence is drawn from, and how assessments are conducted. From this
intersection we derive the irreducible set of common primitives and per-class extensions that
make up a normalized, extensible controls evidence schema.

OCEAN's position in the GRC ecosystem is unique: we produce **structured, API-collected,
machine-interpretable evidence with provenance**, not narrative text or document pointers.
No existing standard (OSCAL, OpenControl, CSA CCM) normalizes evidence at this level.
This schema is the taxonomic artifact that makes OCEAN interoperable and extensible.

---

## Part 1 — Control Domains (What OCEAN Assesses)

Working backwards from real compliance frameworks (SOC 2, ISO 27001, NIST CSF 2.0,
CIS Controls v8, PCI DSS 4.0, FedRAMP), these are the security control domains that
produce assessable, machine-readable evidence.

### Domain 1: Identity & Access Management (IAM)

The single highest-signal domain. Almost every compliance framework's first chapter.

| Control Class | Key Question Answered |
|---|---|
| Authentication Policy | Is strong authentication (MFA, phishing-resistant) required and enforced? |
| Authorization Policy | Are access rights scoped to least privilege? Is RBAC in place? |
| Identity Lifecycle | Are accounts provisioned/deprovisioned promptly? Are joiners/movers/leavers managed? |
| Privileged Access | Are admin/root/break-glass accounts governed, monitored, reviewed? |
| Session Management | Do sessions expire? Are concurrent sessions limited? Is re-auth required for sensitive ops? |
| Service Accounts | Are non-human identities (service accounts, API keys, tokens) inventoried and rotated? |

**What makes IAM evidence distinctive**:
- Population semantics: controls apply to ALL users (or ALL admins), so evidence must
  express coverage rates, not just binary on/off
- Policy vs. enforcement: a policy may exist but not apply to all users
- Identity provider hierarchy: IdP policy → application-level enforcement → actual user behavior

---

### Domain 2: Data Protection

| Control Class | Key Question Answered |
|---|---|
| Encryption at Rest | Are data stores (databases, S3, backups, disks) encrypted? With what key strength? |
| Encryption in Transit | Is TLS 1.2+ enforced everywhere? Are plaintext channels blocked? Are certs valid? |
| Public Exposure | Are any storage resources publicly accessible (no auth required)? |
| Data Retention | Are retention policies configured and enforced? Are logs and backups within lifecycle bounds? |
| Key Management | Are encryption keys rotated? Are KMS policies restrictive? Are old keys disabled? |

**What makes data protection evidence distinctive**:
- Resource enumeration: must check ALL instances (every bucket, every DB, every disk)
- Both config-level AND network-observable (TLS can be probed actively)
- Time-bounded for certs and keys (expiry is a continuous risk)

---

### Domain 3: Network Security

| Control Class | Key Question Answered |
|---|---|
| Firewall & Segmentation | Are security groups / ACLs properly scoped? Are management ports unexposed? |
| WAF Protection | Is a WAF deployed? Is it blocking OWASP Top 10 attack classes? |
| Certificate Health | Are TLS certificates valid, not self-signed, not expired, using strong ciphers? |
| DDoS Protection | Is DDoS mitigation enabled on public-facing services? |
| Exposed Services | Are any unexpected services reachable from the public internet? |

**What makes network evidence distinctive**:
- Both passive (config API) AND active (probe the endpoint) are natural
- WAF bypass attempts are a canonical active test: send attack payloads, verify blocking
- Network state is ephemeral — evidence window matters

---

### Domain 4: Code & SDLC Security

| Control Class | Key Question Answered |
|---|---|
| Repository Policy | Are branch protection rules enforced? Required reviewers, status checks, signed commits? |
| Secret Exposure | Are credentials/secrets committed to source code or exposed in history? |
| Dependency Vulnerability | Are known-vulnerable dependencies in use? Are CVEs unpatched beyond SLA? |
| Pipeline Security | Is SAST/DAST run in CI? Are artifacts signed? Is the pipeline tamper-resistant? |
| Release Authorization | Are production releases authorized? Is deployment gated on security checks? |

**What makes code evidence distinctive**:
- Git-centric: branches, commits, authors are first-class concepts
- Alert semantics: vulnerability scanners produce counts of open/closed/dismissed alerts
- Active test: attempt to push a secret; verify it is blocked

---

### Domain 5: Vulnerability Management

| Control Class | Key Question Answered |
|---|---|
| CVE Finding | What known vulnerabilities are present? At what severity? How old? |
| Patch Compliance | Is the mean time to remediate (MTTR) within SLA by severity? |
| Container Security | Are container images from approved registries? Do they pass image scans? |
| Scan Coverage | Are all assets in scope being scanned? How recently? |

**What makes vuln evidence distinctive**:
- Severity-graded: CVSS scores, EPSS probability, exploitability
- Population + time: patch SLA requires knowing when a CVE was first seen AND when remediated
- Asset-scoped: evidence is tied to a specific host, image, or package version

---

### Domain 6: Endpoint Security

| Control Class | Key Question Answered |
|---|---|
| Endpoint Enrollment | Are all managed devices enrolled in MDM/EDR? |
| Disk Encryption | Is full-disk encryption enabled on all endpoints? |
| OS Patch Status | Are OS versions within the supported window? Are critical patches applied? |
| Screen Lock Policy | Are auto-lock and password policies enforced? |
| EDR Agent Health | Is EDR agent present, up-to-date, and reporting? |

**What makes endpoint evidence distinctive**:
- Fleet-level: must cover ALL devices, express % compliant
- Agent-mediated: evidence comes from MDM/EDR agents, not direct API
- Device identity: MAC, serial, UDID, hostname are key subject identifiers

---

### Domain 7: Logging & Monitoring

| Control Class | Key Question Answered |
|---|---|
| Audit Log Coverage | Are audit logs enabled for all in-scope services? |
| Log Retention | Are logs retained for the required period (90 days, 1 year, etc.)? |
| Alert Configuration | Are critical security event classes (failed logins, privilege escalation) alerting? |
| SIEM Integration | Are log sources feeding a centralized SIEM? |
| Incident Detection | Are alert thresholds set and tested? Is mean time to detect (MTTD) measured? |

---

### Domain 8: Third-Party & Vendor

| Control Class | Key Question Answered |
|---|---|
| Vendor Assessment | Do vendors have current SOC 2 / ISO 27001 reports? When do they expire? |
| Supply Chain | Are software dependencies from trusted registries? Are SBOMs generated? |
| Contract Review | Are vendor contracts current? Do they include security requirements? |

---

## Part 2 — Source System Taxonomy (Where Evidence Comes From)

Every piece of evidence originates from a specific source system. OCEAN normalizes across all
of these into a unified evidence record.

### Source System Categories

```
source.category                source.system examples
─────────────────────────────────────────────────────────────────────
cloud.iam                      aws.iam, gcp.iam, azure.entra_id
identity.idp                   okta, jumpcloud, google_workspace, onelogin, azure_ad
code.scm                       github, gitlab, bitbucket, azure_devops
cloud.storage                  aws.s3, gcp.gcs, azure.blob
cloud.compute                  aws.ec2, gcp.gce, azure.vm, aws.ecs, aws.eks
endpoint.mdm                   jamf, intune, kandji, mosyle
endpoint.edr                   crowdstrike, sentinelone, ms_defender, carbon_black
network.waf                    cloudflare, aws.waf, fastly, akamai, imperva
network.cdn                    cloudflare, fastly, cloudfront
network.probe                  direct tcp/tls (no vendor — protocol-level)
vuln.sca                       snyk, dependabot, mend, socket
vuln.scanner                   trivy, grype, qualys, tenable, wiz, orca
siem.aggregator                splunk, datadog, elastic, sumo_logic, microsoft_sentinel
secrets.vault                  hashicorp_vault, aws.secrets_manager, azure.key_vault, gcp.secret_manager
container.registry             ecr, gcr, dockerhub, artifactory, ghcr
compliance.platform            drata, vanta, vanta, secureframe, tugboat_logic
```

### Source System Attributes (common fields on every evidence record)

```
source.category        — top-level category (cloud.iam, identity.idp, etc.)
source.system          — specific system identifier (okta, aws.iam, github)
source.system_version  — API version used (v3.0, 2022-08-08, etc.)
source.endpoint        — specific API path or endpoint queried
source.account_id      — cloud account / tenant / org scope identifier
source.account_name    — human-readable account/org name
source.region          — geographic region (us-east-1, EU, etc.) — omit if not applicable
```

---

## Part 3 — Assessment Method Taxonomy (How Evidence is Gathered)

The `activity_id` field encodes which assessment method produced the evidence. This is a
first-class concept: the same control can have passive-observed evidence AND actively-verified
evidence with different confidence levels.

### Activity Registry

| activity_id | Name | Method | Confidence | Description |
|---|---|---|---|---|
| 1 | `config_inspection` | Passive | `passive_observation` | Read-only API query of configuration state at a point in time. Most common method. |
| 2 | `resource_enumeration` | Passive | `passive_observation` | List all instances of a resource type; check each against a policy. Produces population-level findings. |
| 3 | `log_query` | Passive | `passive_observation` | Query historical event/audit logs. Returns events within a time window. Evidence is time-bounded. |
| 4 | `behavioral_test` | Active | `active_verification` | Attempt what the control should prevent. If blocked → effective. If not blocked → ineffective. |
| 5 | `bypass_attempt` | Active | `active_verification` | Send a known attack payload or bypass technique; verify the control intercepts it. |
| 6 | `probe` | Hybrid | `active_verification` | Initiate a connection to a service and inspect the response (TLS handshake, HTTP headers, etc.). Active but non-destructive. |
| 7 | `population_analysis` | Passive | `passive_observation` | Aggregate compliance across a population (e.g., % of users with MFA). Requires minimum coverage thresholds. |

### Safety Classification (for active activities 4 and 5)

Active tests (activity_id 4 and 5) MUST carry a `safety_classification`:

| safety_classification | Meaning | Example |
|---|---|---|
| `safe` | Test generates no real traffic, uses synthetic/mock targets | WAF rule unit test |
| `observable` | Test creates real traffic/logs but causes no lasting change | Attempt a blocked login |
| `reversible` | Test creates a change that is automatically cleaned up | Create then delete a resource |
| `destructive` | Test causes lasting change; requires explicit authorization | Disable an account to test deprovisioning |

---

## Part 4 — Evidence Class Registry

From the intersection of (Domain × Source × Method), we define a finite set of **Evidence
Classes**. Each class specifies: which domain it belongs to, which activity_ids apply, and
what class-specific extension attributes it carries beyond the base schema.

### Numbering Convention

```
class_uid = (category_uid × 1000) + class_index
```

Example: class_uid 1003 = Domain 1 (IAM) × 1000 + 3 = Identity Lifecycle class.

### Domain 1: Identity & Access (category_uid: 1)

#### Class 1001: Authentication Policy

**Description**: Evidence of MFA and authentication strength policy configuration.

**Typical sources**: Okta policy API, AWS IAM password policy, Azure AD Authentication Methods

**Applicable activities**: `config_inspection` (1), `population_analysis` (7)

**Class-specific attributes**:
```
iam_auth.policy_type        — mfa | passwordless | password | sso | phishing_resistant
iam_auth.provider           — okta | azure_ad | google_workspace | aws_iam | jumpcloud
iam_auth.total_users        — integer: total users in scope
iam_auth.compliant_users    — integer: users meeting the auth policy
iam_auth.coverage_pct       — float: compliant_users / total_users × 100
iam_auth.non_compliant      — array: list of non-compliant user IDs/names (redacted if PII)
iam_auth.policy_name        — string: name of the policy evaluated
iam_auth.policy_scope       — all | privileged | subset: who the policy applies to
iam_auth.factors            — array of factor types enforced (totp, push, webauthn, sms, etc.)
```

**Effective condition**: All users in scope (or all privileged users) are enrolled and required to use MFA.

---

#### Class 1002: Authorization Policy

**Description**: Evidence of least-privilege RBAC/ABAC configuration and access scoping.

**Typical sources**: AWS IAM (policy analysis), Okta groups, GitHub team permissions, GCP IAM bindings

**Applicable activities**: `config_inspection` (1), `resource_enumeration` (2)

**Class-specific attributes**:
```
iam_authz.model             — rbac | abac | dac | mac
iam_authz.resource_type     — s3 | iam_role | github_repo | okta_group | etc.
iam_authz.overprivileged    — integer: count of identities with more access than used
iam_authz.wildcards         — integer: count of overly broad policy statements (e.g., Action: *)
iam_authz.admin_count       — integer: total identities with admin/root/superuser
iam_authz.last_review_date  — timestamp: when access was last reviewed
```

---

#### Class 1003: Identity Lifecycle

**Description**: Evidence of account provisioning/deprovisioning hygiene and orphan account detection.

**Typical sources**: Okta users API, Azure AD users, SCIM logs

**Applicable activities**: `resource_enumeration` (2), `log_query` (3)

**Class-specific attributes**:
```
iam_lifecycle.active_accounts   — integer: total enabled accounts
iam_lifecycle.stale_accounts    — integer: accounts inactive beyond threshold
iam_lifecycle.orphan_accounts   — integer: accounts with no owner or HR record
iam_lifecycle.deprovo_lag_days  — integer: mean days from offboarding trigger to account disable
iam_lifecycle.stale_threshold   — integer: inactivity days used to define "stale"
```

---

#### Class 1004: Privileged Access

**Description**: Evidence governing admin/root/break-glass account usage and controls.

**Typical sources**: AWS IAM root usage, Okta admin roles, GitHub org owners, GCP Project Owner bindings

**Applicable activities**: `config_inspection` (1), `resource_enumeration` (2), `log_query` (3)

**Class-specific attributes**:
```
iam_priv.admin_count           — integer: number of privileged identities
iam_priv.root_access_keys      — integer: AWS root access keys active (0 is ideal)
iam_priv.mfa_on_privileged     — boolean: is MFA required for all privileged access?
iam_priv.shared_accounts       — integer: shared privileged accounts detected
iam_priv.just_in_time          — boolean: is JIT privileged access in place?
iam_priv.last_used_days        — integer: most recent privileged access in days
```

---

#### Class 1005: Service Account Management

**Description**: Evidence of non-human identity (service accounts, API keys, tokens) hygiene.

**Typical sources**: AWS IAM access keys, GitHub tokens, GCP service accounts, Vault leases

**Applicable activities**: `resource_enumeration` (2)

**Class-specific attributes**:
```
iam_svc.total                  — integer: total service accounts in scope
iam_svc.unrotated              — integer: service accounts with credentials older than max_age
iam_svc.max_age_days           — integer: credential rotation policy threshold
iam_svc.unused                 — integer: service accounts with no activity in stale_days
iam_svc.stale_days             — integer: inactivity threshold for "unused"
iam_svc.over_permissioned      — integer: service accounts with admin-equivalent permissions
```

---

### Domain 2: Data Protection (category_uid: 2)

#### Class 2001: Encryption at Rest

**Description**: Evidence that data stores use encryption with adequate key strength.

**Typical sources**: AWS S3 bucket properties, RDS encryption settings, Okta log encryption, GCP Cloud SQL

**Applicable activities**: `resource_enumeration` (2)

**Class-specific attributes**:
```
data_enc_rest.resource_type       — s3 | rds | dynamodb | ebs | gcs_bucket | azure_blob | etc.
data_enc_rest.total_resources     — integer
data_enc_rest.encrypted           — integer
data_enc_rest.unencrypted         — integer
data_enc_rest.encryption_method   — sse_s3 | sse_kms | cmk | aes_256 | etc.
data_enc_rest.key_rotation        — boolean: is automatic key rotation enabled?
data_enc_rest.unencrypted_ids     — array: IDs/names of non-compliant resources
```

---

#### Class 2002: Encryption in Transit

**Description**: Evidence that network connections enforce TLS with current versions and strong ciphers.

**Typical sources**: Network probe (TLS handshake inspection), AWS ALB SSL policies, Cloudflare TLS settings

**Applicable activities**: `config_inspection` (1), `probe` (6)

**Class-specific attributes**:
```
data_enc_transit.endpoint          — string: URL or hostname inspected
data_enc_transit.tls_version       — tls_1_0 | tls_1_1 | tls_1_2 | tls_1_3
data_enc_transit.min_tls_enforced  — boolean: is TLS 1.2+ the minimum?
data_enc_transit.cipher_suites     — array: cipher suite IDs negotiated
data_enc_transit.forward_secrecy   — boolean
data_enc_transit.hsts_enabled      — boolean: HTTP Strict Transport Security header present
data_enc_transit.http_redirect     — boolean: does HTTP redirect to HTTPS?
```

---

#### Class 2003: Public Storage Exposure

**Description**: Evidence that no storage resources are publicly accessible without authentication.

**Typical sources**: AWS S3 Block Public Access settings, GCS IAM, Azure RBAC

**Applicable activities**: `resource_enumeration` (2)

**Class-specific attributes**:
```
data_public.resource_type         — s3 | gcs | azure_blob | ecr | etc.
data_public.total_resources       — integer
data_public.public_resources      — integer
data_public.public_read_resource_ids  — array: publicly readable resource IDs
data_public.public_write_resource_ids — array: publicly writable resource IDs
data_public.block_public_access       — boolean: platform-level block enabled?
```

---

### Domain 3: Network Security (category_uid: 3)

#### Class 3001: Firewall & Network Segmentation

**Description**: Evidence of network security group, firewall rule, and VPC configuration.

**Typical sources**: AWS Security Groups, GCP VPC firewall rules, Azure NSG

**Applicable activities**: `resource_enumeration` (2)

**Class-specific attributes**:
```
net_firewall.exposed_ports          — array: [{port, protocol, cidr}] for each public rule
net_firewall.risky_ports_exposed    — array: management ports open to internet (22, 3389, etc.)
net_firewall.overly_permissive      — integer: security groups with 0.0.0.0/0 ingress
net_firewall.total_security_groups  — integer
net_firewall.private_subnet_ratio   — float: % of subnets that are private
```

---

#### Class 3002: WAF Protection

**Description**: Evidence that a Web Application Firewall is deployed and blocking attack payloads.

**Typical sources**: Cloudflare WAF API, AWS WAF, Fastly WAF, active bypass attempts

**Applicable activities**: `config_inspection` (1), `bypass_attempt` (5)

**Class-specific attributes**:
```
net_waf.vendor                 — cloudflare | aws | fastly | akamai | imperva
net_waf.mode                   — block | log | challenge | off
net_waf.rule_sets              — array: enabled rule groups (owasp_core, sqli, xss, etc.)
net_waf.bypass_test_payload    — string: attack payload used in test (if activity = bypass_attempt)
net_waf.bypass_test_response   — blocked | passed | error
net_waf.bypass_test_http_code  — integer: HTTP status returned for attack payload
net_waf.protected_endpoints    — array: hostnames/paths behind WAF
```

---

#### Class 3003: Certificate Health

**Description**: Evidence that TLS certificates are valid, trusted, and not near expiry.

**Typical sources**: Network probe (TLS handshake), Certificate Transparency logs, cert APIs

**Applicable activities**: `probe` (6)

**Class-specific attributes**:
```
net_cert.hostname              — string
net_cert.issuer                — string: CA that issued the cert
net_cert.subject               — string: cert subject CN/SAN
net_cert.expiry_date           — timestamp
net_cert.days_until_expiry     — integer
net_cert.is_expired            — boolean
net_cert.is_self_signed        — boolean
net_cert.tls_version           — string
net_cert.key_type              — rsa_2048 | rsa_4096 | ecdsa_256 | ecdsa_384 | etc.
net_cert.chain_valid           — boolean: full chain validates to trusted root
```

---

### Domain 4: Code & SDLC Security (category_uid: 4)

#### Class 4001: Repository Policy

**Description**: Evidence of branch protection and code review controls on source repositories.

**Typical sources**: GitHub branch protection API, GitLab protected branches, Bitbucket branch permissions

**Applicable activities**: `config_inspection` (1), `resource_enumeration` (2)

**Class-specific attributes**:
```
code_repo.platform                    — github | gitlab | bitbucket | azure_devops
code_repo.repository                  — string: org/repo full name
code_repo.default_branch              — string
code_repo.protection_enabled          — boolean
code_repo.required_reviewers          — integer
code_repo.require_status_checks       — boolean
code_repo.require_signed_commits      — boolean
code_repo.allow_force_push            — boolean (false = good)
code_repo.allow_deletions             — boolean (false = good)
code_repo.require_code_owner_reviews  — boolean
code_repo.dismiss_stale_reviews       — boolean
```

---

#### Class 4002: Secret Exposure

**Description**: Evidence that no secrets, credentials, or private keys are exposed in source code.

**Typical sources**: GitHub secret scanning alerts, GitLab secret detection, Gitleaks, TruffleHog

**Applicable activities**: `resource_enumeration` (2), `behavioral_test` (4)

**Class-specific attributes**:
```
code_secret.repository              — string: org/repo
code_secret.open_alerts             — integer: active unresolved secret alerts
code_secret.resolved_alerts         — integer
code_secret.dismissed_alerts        — integer
code_secret.secret_types            — array: categories of secrets found (api_key, password, token, etc.)
code_secret.oldest_open_days        — integer: age of oldest unresolved alert
code_secret.push_protection_enabled — boolean: is push protection (pre-commit blocking) on?
code_secret.test_push_blocked       — boolean: if activity=behavioral_test, was test secret push blocked?
```

---

#### Class 4003: Dependency Vulnerability

**Description**: Evidence of known-vulnerable packages in source dependencies.

**Typical sources**: Snyk, GitHub Dependabot, npm audit, Trivy, OWASP dependency-check

**Applicable activities**: `resource_enumeration` (2)

**Class-specific attributes**:
```
code_dep.repository                 — string: org/repo or image name
code_dep.scanner                    — snyk | dependabot | trivy | grype | mend | socket
code_dep.total_direct_deps          — integer
code_dep.total_transitive_deps      — integer
code_dep.open_critical              — integer: critical severity CVEs open
code_dep.open_high                  — integer: high severity CVEs open
code_dep.open_medium                — integer: medium severity CVEs open
code_dep.mean_age_days_critical     — float: mean age of unpatched critical CVEs
code_dep.sla_breach_critical        — integer: critical CVEs open beyond SLA
code_dep.sla_days_critical          — integer: SLA policy for critical CVEs
```

---

### Domain 5: Vulnerability Management (category_uid: 5)

#### Class 5001: CVE Finding

**Description**: Evidence of specific CVE findings on infrastructure, images, or packages.

**Typical sources**: Wiz, Orca, Qualys, Tenable, Trivy, AWS Inspector

**Applicable activities**: `resource_enumeration` (2)

**Class-specific attributes**:
```
vuln_cve.cve_id              — string: e.g., CVE-2021-44228
vuln_cve.cvss_score          — float: 0.0–10.0
vuln_cve.cvss_vector         — string: CVSS vector string
vuln_cve.epss_score          — float: 0.0–1.0 exploit probability
vuln_cve.severity            — critical | high | medium | low | informational
vuln_cve.asset_type          — host | container_image | package | application
vuln_cve.asset_id            — string: affected asset identifier
vuln_cve.first_seen          — timestamp
vuln_cve.days_open           — integer
vuln_cve.patch_available     — boolean
vuln_cve.patch_version       — string: version that fixes this CVE
vuln_cve.exploited_itw       — boolean: known exploited in the wild (CISA KEV)
```

---

#### Class 5002: Container Security

**Description**: Evidence that container images pass security scanning and provenance requirements.

**Typical sources**: Trivy, ECR scan, GCR vulnerability analysis, Snyk container, Grype

**Applicable activities**: `resource_enumeration` (2)

**Class-specific attributes**:
```
vuln_container.registry             — string: registry host
vuln_container.image                — string: image name:tag or digest
vuln_container.base_image           — string: FROM layer identifier
vuln_container.total_layers         — integer
vuln_container.critical_vulns       — integer
vuln_container.high_vulns           — integer
vuln_container.run_as_root          — boolean (true = bad)
vuln_container.read_only_rootfs     — boolean
vuln_container.secret_in_env       — boolean: sensitive env vars detected
vuln_container.approved_base        — boolean: base image from approved registry/list
```

---

### Domain 6: Endpoint Security (category_uid: 6)

#### Class 6001: Endpoint Enrollment & Compliance

**Description**: Evidence of device MDM/EDR enrollment and policy compliance.

**Typical sources**: Jamf Pro, Microsoft Intune, Kandji, CrowdStrike Falcon Device API

**Applicable activities**: `resource_enumeration` (2), `population_analysis` (7)

**Class-specific attributes**:
```
endpoint.total_devices          — integer
endpoint.enrolled_devices       — integer
endpoint.compliance_rate        — float: % of devices meeting all policy requirements
endpoint.non_compliant_count    — integer
endpoint.non_compliant_reasons  — array: [{reason, count}] breakdown of failures
endpoint.platform               — macos | windows | linux | ios | android | chromeos
endpoint.mdm_vendor             — jamf | intune | kandji | mosyle | google_endpoint
endpoint.edr_vendor             — crowdstrike | sentinelone | ms_defender | carbon_black
```

---

#### Class 6002: Disk Encryption

**Description**: Evidence that full-disk encryption is enabled on managed endpoints.

**Typical sources**: Jamf FileVault status, Intune device compliance (BitLocker), CrowdStrike

**Applicable activities**: `resource_enumeration` (2), `population_analysis` (7)

**Class-specific attributes**:
```
endpoint_enc.total_devices           — integer
endpoint_enc.encrypted_count         — integer
endpoint_enc.unencrypted_count       — integer
endpoint_enc.encryption_method       — filevault | bitlocker | luks | other
endpoint_enc.key_escrow              — boolean: are recovery keys escrowed?
endpoint_enc.unencrypted_device_ids  — array: non-compliant device identifiers
```

---

### Domain 7: Logging & Monitoring (category_uid: 7)

#### Class 7001: Audit Log Coverage

**Description**: Evidence that audit logging is enabled for in-scope systems.

**Typical sources**: AWS CloudTrail, GCP Cloud Audit Logs, Okta System Log, GitHub audit log API

**Applicable activities**: `config_inspection` (1), `resource_enumeration` (2)

**Class-specific attributes**:
```
audit_log.service                   — string: service being audited (cloudtrail, okta, github, etc.)
audit_log.enabled                   — boolean
audit_log.log_types                 — array: management, data, and/or read events logged
audit_log.regions_covered           — array: AWS regions with logging enabled
audit_log.multi_region              — boolean: single trail covering all regions?
audit_log.log_validation            — boolean: log file integrity validation enabled?
audit_log.destination               — s3 | siem | cloudwatch | sentinel | etc.
```

---

#### Class 7002: Log Retention

**Description**: Evidence that logs are retained for the required minimum period.

**Typical sources**: AWS CloudTrail S3 lifecycle policy, Splunk index retention, Datadog retention

**Applicable activities**: `config_inspection` (1)

**Class-specific attributes**:
```
audit_ret.log_type                  — string: type of log (cloudtrail, access_log, etc.)
audit_ret.retention_days            — integer: configured retention period
audit_ret.required_days             — integer: policy minimum (e.g., 90, 365)
audit_ret.meets_requirement         — boolean
audit_ret.storage_backend           — string: where logs are stored long-term
```

---

### Domain 8: Third-Party & Vendor (category_uid: 8)

#### Class 8001: Vendor Security Assessment

**Description**: Evidence of external vendor security posture verification — whether vendors have current, valid third-party attestations (SOC 2, ISO 27001, etc.) and whether security reviews are performed.

**Typical sources**: Vendor-provided SOC 2 report (PDF), Whistic, OneTrust, Vanta Third-Party, manual registries

**Applicable activities**: `config_inspection` (1), `resource_enumeration` (2)

**Class-specific attributes**:
```
tpr_vendor.vendor_name              — string: vendor name
tpr_vendor.vendor_id                — string: internal vendor identifier
tpr_vendor.assessment_type         — soc2_type2 | soc2_type1 | iso27001 | soc3 | questionnaire | pentest
tpr_vendor.report_period_start     — timestamp: attestation period start
tpr_vendor.report_period_end       — timestamp: attestation period end
tpr_vendor.days_until_expiry       — integer: days until report considered stale (typically 365)
tpr_vendor.opinion                 — unqualified | qualified | adverse | disclaimer
tpr_vendor.qualifications          — array: specific control failures noted by auditor
tpr_vendor.handles_pii             — boolean: does this vendor process personal data?
tpr_vendor.handles_phi             — boolean: does this vendor process health data?
tpr_vendor.critical_vendor         — boolean: classified as critical/high-risk vendor?
```

**Effective condition**: Vendor has a current (within 12 months), unqualified attestation appropriate to their risk classification.

---

#### Class 8002: Software Supply Chain Integrity

**Description**: Evidence that software artifacts (packages, containers, releases) have verifiable provenance and have not been tampered with.

**Typical sources**: SLSA provenance attestations, Sigstore/cosign signatures, SBOM registries, GitHub attestation API

**Applicable activities**: `config_inspection` (1), `resource_enumeration` (2)

**Class-specific attributes**:
```
tpr_supply.artifact_type            — container_image | package | release_binary | github_actions
tpr_supply.artifact_id              — string: artifact identifier (image digest, package@version)
tpr_supply.slsa_level               — integer: 0–4 (SLSA provenance level achieved)
tpr_supply.signed                   — boolean: artifact has a cryptographic signature
tpr_supply.signature_valid          — boolean: signature verification passed
tpr_supply.sbom_present             — boolean: SBOM available for this artifact
tpr_supply.sbom_format              — spdx | cyclonedx | syft | none
tpr_supply.known_compromised_deps   — integer: dependencies matching known compromised packages
tpr_supply.pinned_deps              — boolean: all dependencies pinned to exact versions
```

**Effective condition**: Artifact is signed with valid signature at SLSA L2+, SBOM present, no known-compromised dependencies.

---

#### Class 8003: Vendor SLA Monitoring

**Description**: Evidence of vendor uptime, performance, and security incident response against contractual SLAs.

**Typical sources**: Vendor status pages, uptime monitoring services, incident log queries

**Applicable activities**: `config_inspection` (1), `log_query` (3)

**Class-specific attributes**:
```
tpr_sla.vendor_name                 — string
tpr_sla.sla_type                    — uptime | rto | rpo | incident_response | mttr
tpr_sla.period_days                 — integer: measurement window
tpr_sla.sla_target_pct             — float: contracted SLA (e.g., 99.9)
tpr_sla.actual_pct                 — float: actual measured value
tpr_sla.sla_breached               — boolean
tpr_sla.incidents_count            — integer: security incidents in period
tpr_sla.mean_resolution_hours      — float: mean time to resolve incidents
tpr_sla.contractual_penalties_due  — boolean: breach triggers penalty clause
```

---

## Part 5 — Base Evidence Schema (Common Attributes)

Every evidence record, regardless of class, carries all of these fields. The class-specific
attributes in Part 4 are additive extensions stored in `raw_data` and surfaced as typed
`findings`.

### Schema (Canonical Field List)

```
# Core Identity
id                             uuid       — globally unique record ID
class_uid                      integer    — evidence class (e.g., 1001 = Authentication Policy)
category_uid                   integer    — domain (e.g., 1 = IAM)
activity_id                    integer    — assessment method (1–7, see Part 3)

# Temporal
time                           timestamp  — normalized collection/test time (UTC)
window_start                   timestamp  — start of observation window (optional; for log_query)
window_end                     timestamp  — end of observation window (optional; for log_query)

# Subject (what was assessed)
subject.type                   enum       — account | user | resource | repository | device | endpoint | network | service | population
subject.id                     string     — unique identifier of the subject within its source system
subject.name                   string     — human-readable name
subject.url                    string     — link to the subject in source system UI (optional)

# Source (where evidence came from)
source.category                string     — top-level source category (e.g., cloud.iam, identity.idp)
source.system                  string     — specific system (e.g., okta, aws.iam, github)
source.system_version          string     — API version used
source.endpoint                string     — API path or probe target
source.account_id              string     — account/tenant/org scoping ID
source.account_name            string     — human-readable account/org name
source.region                  string     — geographic region (omit if N/A)

# OCEAN Provenance
metadata.module.name           string     — OCEAN module that produced this (e.g., okta.mfa_policy)
metadata.module.version        semver     — module version
metadata.module.type           enum       — collector | tester
metadata.processed_time        timestamp  — when OCEAN normalized this record
metadata.original_time         timestamp  — source system's own timestamp (optional)
metadata.safety_classification enum       — safe | observable | reversible | destructive (active tests only)

# Effectiveness Determination
confidence_level               enum       — passive_observation | active_verification
status_id                      integer    — 0=Unknown 1=Effective 2=Ineffective 99=Other
status                         string     — human-readable status

# Payload
raw_data                       json       — verbatim source API response or test output
findings                       array      — structured observations (title, description, severity_id)
observables                    array      — key extracted values (type, value) for search indexing

# Control Reference
control_id                     string     — control this evidence supports (e.g., iam.mfa_enforcement)
```

---

## Part 6 — Subject Type Reference

The `subject.type` field describes the entity being assessed. This determines what
`subject.id` represents and what class-specific attributes are relevant.

| subject.type | Description | subject.id example | Typical classes |
|---|---|---|---|
| `account` | Cloud account, tenant, or top-level org | AWS 123456789012, Okta org ID | 1001, 1002, 7001 |
| `user` | Individual human identity | user@example.com, okta-uid | 1001, 1003, 1004 |
| `service_account` | Non-human identity | github-app/my-app, arn:aws:iam::123:user/svc | 1005 |
| `resource` | Cloud storage/compute resource | arn:aws:s3:::my-bucket, projects/myproject/... | 2001, 2003 |
| `repository` | Source code repository | org/repo | 4001, 4002, 4003 |
| `device` | Managed endpoint | device serial, UDID | 6001, 6002 |
| `endpoint` | Network-accessible service | https://example.com, 10.0.1.5:443 | 3002, 3003, 2002 |
| `network` | Firewall, VPC, or security group | sg-abc123, projects/myproject/networks/default | 3001 |
| `service` | Abstract service (e.g., CloudTrail) | aws.cloudtrail.us-east-1 | 7001, 7002 |
| `population` | Fleet or user set with coverage semantics | all_managed_devices, all_okta_users | 1001, 6001, 6002 |

---

## Part 7 — Finding Severity Reference

The `findings[].severity_id` field uses a standard 5-tier scale:

| severity_id | severity | Meaning |
|---|---|---|
| 0 | `informational` | Observation with no control implication |
| 1 | `low` | Minor deviation, low risk |
| 2 | `medium` | Moderate deviation, meaningful risk |
| 3 | `high` | Significant control failure, high risk |
| 4 | `critical` | Critical control failure, immediate risk |

---

## Part 8 — ID Scheme Summary

### Evidence Classes

```
class_uid = (category_uid × 1000) + class_index

Domain 1: IAM           1001–1099
Domain 2: Data Prot.    2001–2099
Domain 3: Network       3001–3099
Domain 4: Code/SDLC     4001–4099
Domain 5: Vuln Mgmt     5001–5099
Domain 6: Endpoint      6001–6099
Domain 7: Logging       7001–7099
Domain 8: Third-Party   8001–8099
```

### Activity IDs

```
1 = config_inspection
2 = resource_enumeration
3 = log_query
4 = behavioral_test
5 = bypass_attempt
6 = probe
7 = population_analysis
```

### Status IDs

```
0 = Unknown
1 = Effective
2 = Ineffective
99 = Other / Error
```

### Severity IDs

```
0 = informational
1 = low
2 = medium
3 = high
4 = critical
```

---

## Part 9 — Design Principles & Interoperability

### Design Principles (borrowed from prior art)

1. **Hierarchy like ATT&CK**: `category_uid` → `class_uid` → `activity_id` mirrors
   Tactic → Technique → Sub-technique. Self-documenting numerics, stable parents, evolving children.

2. **Attribute dictionary like OCSF**: Every class has documented, typed fields. Class-specific
   attributes are ADDITIVE to the base schema — never replace base fields.

3. **Population semantics are first-class**: Many GRC controls are fleet-level (ALL users,
   ALL devices, ALL buckets). The schema uses `_count` and `_pct` fields + `subject.type=population`
   to express coverage, not just binary on/off.

4. **Assessment method is explicit**: `activity_id` is not optional metadata. It determines
   the confidence level, safety classification requirements, and interpretation of findings.

5. **Source system is structured, not free-text**: `source.category` and `source.system` are
   from a controlled vocabulary, enabling cross-source aggregation.

### OSCAL Interoperability

OCEAN evidence maps to OSCAL Assessment Results as follows:

```
OCEAN Evidence          OSCAL Assessment Results
────────────────        ──────────────────────────────────────────────────────
control_id           →  finding.related-controls[].control-id
status_id            →  finding.target.status (satisfied | not-satisfied)
findings[]           →  observation.relevant-evidence (described, not href pointer)
raw_data             →  observation.relevant-evidence.description (JSON-serialized)
confidence_level     →  observation.methods (EXAMINE | INTERVIEW | TEST)
time                 →  result.end (assessment end timestamp)
```

OSCAL export is a downstream transform, not a native storage format. OCEAN stores structured
evidence natively; OSCAL is an output layer for audit package generation.

### Framework Mapping (CCM-style)

Controls defined in `controls/*.yaml` carry `framework_mappings[]` linking each control to
specific clauses across SOC 2, ISO 27001, NIST CSF, CIS Controls, PCI DSS. This is flat
reference data — the evidence schema itself is framework-agnostic.

---

## Part 10 — Gap Analysis vs. Current Implementation

The current OCEAN Rust implementation (`src/evidence/mod.rs`) uses a simplified schema
relative to this design. Here is what exists and what this document proposes to add:

### Currently Implemented

- `id`, `control_id`, `status_id`, `confidence_level`, `raw_data`, `time`
- `metadata.module.*`, `metadata.source.*`
- `findings[]` (title, description, severity_id)
- `observables[]` (type, value)
- `class_uid`, `category_uid`, `activity_id` — fields EXIST but values are not yet
  governed by this taxonomy (no class registry was published)

### Proposed Additions (Phase 4 / v0.2.0)

1. **Publish class registry** — assign `class_uid` values to all built-in modules
2. **subject struct** — add `subject.type`, `subject.id`, `subject.name`, `subject.url`
3. **window_start / window_end** — for log_query evidence that covers a time range
4. **source.category** — coarser-grained source taxonomy field
5. **safety_classification** on base Evidence — currently lives only on TestTranscript
6. **Class-specific attribute validation** — schema-validate `raw_data` keys per class_uid

### Priority Order

| Priority | Change | Reason |
|---|---|---|
| 1 | Assign class_uid values to 9 built-in modules | Makes existing data queryable by class |
| 2 | Add subject struct | Enables cross-control subject-centric queries ("show me all evidence about user X") |
| 3 | Publish taxonomy doc as JSON Schema | Enables tool integration, type-safe module development |
| 4 | Expand activity_id to 7 values | Currently only 1 (collect) and 2 (test); population_analysis missing |
| 5 | window_start / window_end | Required for log-query evidence (Domain 7) |

These additions are non-breaking: the core Evidence struct fields already exist; the changes
populate previously undefined values and add optional struct fields.

---

## Part 11 — Existing Module → Class Mapping

How OCEAN's 9 current modules map to this taxonomy. This table is the bridge between
implementation and schema, and is the first artifact to be kept in sync as modules are added.

| Module ID | Source System | Module Type | class_uid | Class Name | activity_id |
|-----------|--------------|-------------|-----------|------------|-------------|
| `mock.test` | mock | collector | 1001 | Authentication Policy | 7 (population_analysis) |
| `mock.network` | mock | collector | 3002 | WAF Protection | 1 (config_inspection) |
| `mock.safety_test` | mock | tester | 3002 | WAF Protection | 5 (bypass_attempt) |
| `okta.mfa_policy` | okta | collector | 1001 | Authentication Policy | 7 (population_analysis) |
| `okta.mfa_bypass` | okta | tester | 1001 | Authentication Policy | 4 (behavioral_test) |
| `aws.iam` | aws | collector | 1004 | Privileged Access | 2 (resource_enumeration) |
| `aws.s3_public_access` | aws | tester | 2003 | Public Storage Exposure | 5 (bypass_attempt) |
| `github.branch_protection` | github | collector | 4001 | Repository Policy | 1 (config_inspection) |
| `github.secret_push` | github | tester | 4002 | Secret Exposure | 4 (behavioral_test) |

### Notes on Current Mapping

- `mock.safety_test` and `mock.network` both map to class `3002` (WAF Protection) — one passive,
  one active. This is the intended dual-mode pattern: the same class accommodates both
  `config_inspection` (is the WAF configured?) and `bypass_attempt` (does it actually block?).

- `okta.mfa_bypass` maps to class `1001` (Authentication Policy) rather than a separate bypass
  class because MFA bypass testing is evidence about the authentication policy's effectiveness.
  The `activity_id=4` differentiates it from the passive `okta.mfa_policy` collector.

- As modules are added, update this table. The module ID, class_uid, and activity_id triple is
  the canonical identity of each evidence producer.

---

## Part 12 — Class Registry Quick Reference

Full class registry for at-a-glance lookup. All 26 classes across 8 domains.

```
class_uid   class_name                  domain      activity_ids
─────────────────────────────────────────────────────────────────────
1001        Authentication Policy        IAM         1, 7
1002        Authorization Policy         IAM         1, 2
1003        Identity Lifecycle           IAM         2, 3
1004        Privileged Access            IAM         1, 2, 3
1005        Service Account Mgmt        IAM         2

2001        Encryption at Rest          Data Prot.  2
2002        Encryption in Transit       Data Prot.  1, 6
2003        Public Storage Exposure     Data Prot.  2

3001        Firewall & Segmentation     Network     2
3002        WAF Protection              Network     1, 5
3003        Certificate Health          Network     6

4001        Repository Policy           Code/SDLC   1, 2
4002        Secret Exposure             Code/SDLC   2, 4
4003        Dependency Vulnerability    Code/SDLC   2

5001        CVE Finding                 Vuln Mgmt   2
5002        Container Security          Vuln Mgmt   2

6001        Endpoint Enrollment         Endpoint    2, 7
6002        Disk Encryption             Endpoint    2, 7

7001        Audit Log Coverage          Logging     1, 2
7002        Log Retention               Logging     1

8001        Vendor Assessment           Third-Party 1, 2
8002        Supply Chain Integrity      Third-Party 1, 2
8003        Vendor SLA Monitoring       Third-Party 1, 3
```
