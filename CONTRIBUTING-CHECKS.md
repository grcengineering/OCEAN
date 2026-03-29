# Contributing Checks to OCEAN

This guide explains how to create new `.check.yaml` files for OCEAN's check library.

## Quick Start

1. Copy an existing check from `checks/` as a template
2. Edit the fields for your new check
3. Validate against the schema: `ocean check validate checks/your-check.check.yaml`
4. Run the check locally: `ocean observe --check YOUR-CHECK-ID`

## File Structure

Checks live in `checks/<source>/` directories, organized by source system:

```
checks/
├── aws/          # AWS checks (IAM, CloudTrail, S3, KMS)
├── azure/        # Azure checks (AAD, NSG, Key Vault)
├── github/       # GitHub checks (org, repo, actions)
├── okta/         # Okta checks (auth, admin, policies)
└── test.check.yaml
```

## Naming Convention

Files follow the pattern: `<ID>-<slug>.check.yaml`

- **ID format**: `SOURCE-CATEGORY-N.NN` (e.g., `GH-1.01`, `AWS-IAM-3.01`, `OKTA-5.02`)
- **Slug**: lowercase kebab-case summary (e.g., `org-mfa`, `key-rotation`)

## Check Schema

Every check is validated against `schemas/check.schema.json`. Required fields:

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique identifier matching `^[A-Z][A-Z0-9-]*-[0-9]+(\.[0-9]+)*$` |
| `name` | string | Human-readable check name |
| `source` | string | Source system (`github`, `aws`, `okta`, `azure`, `gcp`) |

## Recommended Fields

```yaml
id: SOURCE-CAT-N.NN
name: Human-Readable Check Name
description: |
  Multi-line description of what this check verifies and why it matters.
author: grc-engineering
version: "1.0"
source: github
profile: L1          # L1 = baseline, L2 = hardened, L3 = maximum
tags: [category, subcategory]
```

## References (Compliance Mappings)

Map checks to compliance frameworks. At minimum, include `nist` and `soc2`:

```yaml
references:
  cis: "1.1"                    # CIS Benchmark section
  nist: ["IA-2(1)", "IA-2(2)"] # NIST 800-53 controls (string or array)
  soc2: CC6.1                   # SOC 2 criteria
  iso27001: A.9.4.2             # ISO 27001 controls
  pci_dss: "8.3"                # PCI DSS requirements
```

## Credentials

Declare required credentials keyed by environment variable name:

```yaml
credentials:
  GITHUB_TOKEN:
    type: api_token          # api_token, oauth2, or basic_auth
    scopes: [admin:org]      # required API scopes
    required: true
```

## Inputs

Declare runtime inputs:

```yaml
inputs:
  org:
    description: GitHub organization name
    env: GITHUB_ORG           # environment variable to read from
    default: "my-org"         # optional default value
    required: true
```

## Steps

Steps are sequential HTTP API calls. Each step **must** have `id` and `request`:

```yaml
steps:
  - id: get_org_settings
    action: api_call           # default, can be omitted
    request:
      method: GET              # GET, POST, PUT, PATCH, DELETE
      url: "https://api.github.com/orgs/{{org}}"
      headers:
        Authorization: "Bearer {{GITHUB_TOKEN}}"
        Accept: "application/vnd.github+json"
      body: {}                 # optional request body
      paginate: true           # optional, follows Link headers
    extract:
      mfa_enforced: "$.two_factor_requirement_enabled"
      org_name: "$.login"
    on_error:
      "404": "skip"            # optional per-status error handling
```

### Step Rules

- `request.method` and `request.url` are **required**
- Use `{{variable}}` templates for dynamic values (inputs, credentials, extracted values)
- `extract` maps variable names to JSONPath expressions for use in later steps and assertions
- For AWS/Azure checks, auth signing is handled by the runtime — provide URL and method only
- Steps execute in order; extracted variables are available to subsequent steps

## Assertions

CEL expressions evaluated against extracted variables:

```yaml
assertions:
  - id: mfa_enforcement
    expr: "mfa_enforced == true"     # CEL expression returning bool
    severity: critical               # critical, high, medium, low, info
    title: Organization MFA Enforcement
    pass_message: "MFA is enforced for all organization members"
    fail_message: "MFA is NOT enforced for the organization"
    finding:
      description: |
        Detailed description of the finding, its security impact,
        and what the operator should investigate.
```

### Assertion Rules

- `id` and `expr` are **required**
- `expr` must be a valid CEL expression that returns a boolean
- Use `{{variable}}` templates in messages
- `severity` defaults to `medium`
- Always include a `finding.description` explaining the security impact

## Remediation

Provide actionable fix instructions:

```yaml
remediation:
  description: |
    High-level description of what needs to change and why.
  steps:
    - "Navigate to Settings > Security"          # UI steps (strings only)
    - "Enable the security feature"
    - "Click Save"
  api:
    method: PATCH                                  # required
    url: "https://api.example.com/settings"        # required
    headers:
      Content-Type: "application/json"
    body:
      setting_enabled: true
  cli:
    command: "tool api settings -X PATCH -f setting=true"
```

### Remediation Rules

- `remediation.steps` items **must be strings** — quote any step containing a colon (`:`)
- `remediation.api` requires both `method` and `url` (not `endpoint`)
- `remediation.api` only allows: `method`, `url`, `headers`, `body`

## Profile Tiers

| Profile | Description | Example |
|---------|-------------|---------|
| L1 | Baseline security — essential controls everyone should enable | Enforce MFA, block public S3 |
| L2 | Hardened — defense-in-depth controls for security-conscious orgs | Key rotation, credential hygiene |
| L3 | Maximum — advanced controls, may impact usability | Hardware MFA, strict network isolation |

## Validation Checklist

Before submitting a new check:

- [ ] File is in the correct `checks/<source>/` directory
- [ ] ID matches the naming pattern (`SOURCE-CAT-N.NN`)
- [ ] Passes schema validation (`schemas/check.schema.json`)
- [ ] Has `references` with at least `nist` and `soc2` mappings
- [ ] Has `remediation` with `steps` (strings) and `api` (with `method` + `url`)
- [ ] All steps have `id` and `request` with `method` + `url`
- [ ] All assertions have `id` and `expr`
- [ ] Shows up in `ocean observe --list`
- [ ] Runs successfully against a test environment

## Common Mistakes

| Mistake | Fix |
|---------|-----|
| Using `endpoint` in remediation.api | Use `url` instead |
| Unquoted colon in remediation.steps | Wrap the string in quotes |
| Missing `request` in steps | Every step needs `request: { method, url }` |
| Missing `id` in steps or assertions | Both require an `id` field |
| Using `implementation: native` without Rust module | Use YAML steps instead |
