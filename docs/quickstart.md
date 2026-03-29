# OCEAN Quickstart Guide

Get up and running with OCEAN in minutes using the built-in mock modules.

## Prerequisites

- Go 1.22+ installed
- Git

## Installation

### From Source

```bash
git clone https://github.com/grcengineering/ocean.git
cd ocean
make build
```

This produces the `ocean` binary in the current directory.

### Verify Installation

```bash
./ocean version
# ocean <commit> (built <timestamp>)
```

## Step 1: List Available Modules

```bash
./ocean modules list
```

Output:

```
ID                        VERSION  TYPE       SOURCE SYSTEM  SAFETY CLASS
--                        -------  ----       -------------  ------------
aws.iam                   0.1.0    observer  aws            -
aws.s3_public_access      0.1.0    tester     aws            safe
github.branch_protection  0.1.0    observer  github         -
github.secret_push        0.1.0    tester     github         observable
mock.network              0.1.0    observer  mock           -
mock.safety_test          0.1.0    tester     mock           safe
mock.test                 0.1.0    observer  mock           -
okta.mfa_bypass           0.1.0    tester     okta           safe
okta.mfa_policy           0.1.0    observer  okta           -
```

Filter by type:

```bash
./ocean modules list --type tester
./ocean modules list --type observer
```

## Step 3: Collect Evidence (Passive)

Passive collection queries system APIs to observe configuration state without modifying anything. The mock observer works without any credentials:

```bash
./ocean collect mock.test
```

Output (JSON):

```json
{
  "id": "<uuid>",
  "control_id": "mfa.enforcement",
  "class_uid": 1001,
  "activity_id": 1,
  "time": "<timestamp>",
  "confidence_level": "passive_observation",
  "metadata": {
    "module": { "name": "mock.test", "version": "0.1.0", "type": "observer" },
    "source": { "system": "mock", "api_version": "v1", "endpoint": "/api/v1/policies" }
  },
  "status_id": 1,
  "status": "MFA enforcement is required for all users",
  "findings": [
    {
      "title": "MFA Policy Active",
      "description": "MFA enforcement is set to 'required' with zero user exceptions",
      "severity_id": 0
    }
  ],
}
```

Evidence is automatically stored in SQLite at `~/.ocean/ocean.db`.

Use `--format yaml` for YAML output:

```bash
./ocean collect mock.test --format yaml
```

## Step 4: Run an Active Test

Active testing attempts what controls should prevent and records whether the control blocked it. Every tester declares a safety classification:

```bash
./ocean test mock.safety_test --target staging
```

This produces `active_verification` evidence with a full **test transcript** documenting:
- **Actions attempted** -- what the test tried to do (e.g., submit credentials without MFA)
- **Observations** -- what happened (e.g., MFA challenge presented, login blocked)
- **Cleanup actions** -- what was cleaned up after the test

The `--target` flag controls environment scope. Safety classification enforcement prevents dangerous tests from running in inappropriate environments:

| Classification | Allowed Environments |
|---|---|
| `safe` | production, staging, isolated |
| `observable` | production, staging |
| `reversible` | staging, isolated |
| `destructive` | isolated only |

## Step 5: Validate a Module

Check that a module's metadata and configuration are correct:

```bash
./ocean modules validate mock.safety_test
# PASS: module "mock.safety_test" passed all validation checks.
```

## Step 6: Dual-Mode Verification

Run both observer + tester and evaluate control effectiveness in a single command:

```bash
./ocean verify mock.mfa_enforcement
```

This runs the control's configured observers and testers, then evaluates using CEL expressions to produce a unified status:

```json
{
  "control": {
    "id": "mock.mfa_enforcement",
    "name": "MFA Enforcement",
    "framework_mappings": [
      { "framework_id": "SOC2", "control_ref": "CC6.1" }
    ]
  },
  "status": {
    "status": "effective",
    "confidence": "high",
    "evaluation_details": "composite evaluation: ... verdict=effective"
  },
  "evidences": [ ... ]
}
```

When passive observation and active verification agree, confidence is `high`.

## Step 7: Start the API Server

Run the REST API for integration with external GRC platforms:

```bash
./ocean serve --port 8080 --auth-token "your-secret-token"
```

Query evidence via the API:

```bash
# Health check (no auth required)
curl http://localhost:8080/api/v1/health

# List evidence
curl -H "Authorization: Bearer your-secret-token" \
  http://localhost:8080/api/v1/evidence

# List modules
curl -H "Authorization: Bearer your-secret-token" \
  http://localhost:8080/api/v1/modules
```

See [api.md](api.md) for full API documentation.

## Using Real Modules

Real modules require credentials for their target systems. Set credentials via environment variables:

### Okta

```bash
export OKTA_DOMAIN="your-org.okta.com"
export OKTA_API_TOKEN="your-api-token"

./ocean collect okta.mfa_policy
./ocean test okta.mfa_bypass --target production
```

### AWS

```bash
export AWS_ACCESS_KEY_ID="your-key"
export AWS_SECRET_ACCESS_KEY="your-secret"
export AWS_REGION="us-east-1"

./ocean collect aws.iam
./ocean test aws.s3_public_access --target production
```

### GitHub

```bash
export GITHUB_TOKEN="your-personal-access-token"
export GITHUB_OWNER="your-org"
export GITHUB_REPO="your-repo"

./ocean collect github.branch_protection
./ocean test github.secret_push --target production
```

## Key Concepts

### Evidence Types

| Confidence Level | Description | Produced By |
|---|---|---|
| `passive_observation` | Read-only system state observation | Observers |
| `active_verification` | Active test proving control works | Testers |

### Control Status

| Status | Meaning |
|---|---|
| `effective` | Control is operating correctly |
| `ineffective` | Control has failed or is misconfigured |
| `unknown` | Insufficient evidence to determine |

### Confidence Levels

| Level | Criteria |
|---|---|
| `high` | Both passive and active evidence agree |
| `medium` | Only one evidence type present |
| `low` | Stale, insufficient, or disagreeing evidence |

## Next Steps

- Read the [Module Development Guide](modules.md) to create custom observers and testers
- Review the [API Documentation](api.md) for integration options
- Define custom controls in `controls/` directory
- Write CEL expressions for organization-specific compliance conditions
