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
# ocean dev (built unknown)
```

## Your First Evidence Collection

OCEAN ships with mock modules that simulate real-world evidence collection without requiring any external credentials.

### Step 1: List Available Modules

```bash
./ocean modules list
```

Expected output:

```
Available modules:

Collectors:
  mock.network         Mock Network Collector             v0.1.0   [mock]
  mock.test            Mock Test Collector                v0.1.0   [mock]

Testers:
  mock.safety_test     Mock Safety Test                   v0.1.0   [mock]     safe/production
```

### Step 2: Collect Evidence (Passive)

Run the mock collector to gather simulated MFA policy evidence:

```bash
./ocean collect --module mock.test --control mock.mfa_enforcement
```

Expected output (JSON):

```json
{
  "id": "<uuid>",
  "control_id": "mfa.enforcement",
  "class_uid": 1001,
  "status_id": 1,
  "status": "MFA enforcement is required for all users",
  "confidence_level": "passive_observation",
  "metadata": {
    "module": { "name": "mock.test", "version": "0.1.0", "type": "collector" },
    "source": { "system": "mock", "api_version": "v1" }
  }
}
```

### Step 3: Run an Active Test

Run the mock tester to simulate an MFA bypass attempt:

```bash
./ocean test --module mock.safety_test --control mock.mfa_enforcement
```

This produces `active_verification` evidence with a full test transcript showing:
- Actions attempted (MFA bypass simulation)
- Observations recorded (bypass correctly blocked)
- Cleanup performed

### Step 4: Evaluate Control Effectiveness

Evaluate the control using the CEL expression engine:

```bash
./ocean evaluate --control mock.mfa_enforcement
```

The evaluator combines passive and active evidence to determine:
- **Status**: effective, ineffective, unknown, or partial
- **Confidence**: high (both types agree), medium (single type), low (stale/missing)

### Step 5: View History

Query the historical effectiveness of a control:

```bash
./ocean history --control mock.mfa_enforcement
```

### Step 6: Verify Provenance

Verify the cryptographic provenance chain for collected evidence:

```bash
./ocean verify --evidence-id <uuid>
```

## Running the API Server

Start the REST API for integration with external GRC platforms:

```bash
./ocean serve --port 8080 --auth-token "your-secret-token"
```

Query evidence via the API:

```bash
curl -H "Authorization: Bearer your-secret-token" \
  http://localhost:8080/api/v1/evidence

curl http://localhost:8080/api/v1/health
```

See [docs/api.md](api.md) for full API documentation.

## Key Concepts

### Evidence Types

| Confidence Level | Description | Produced By |
|---|---|---|
| `passive_observation` | Read-only system state observation | Collectors |
| `active_verification` | Active test proving control works | Testers |

### Control Status

| Status | Meaning |
|---|---|
| `effective` | Control is operating correctly |
| `ineffective` | Control has failed or is misconfigured |
| `unknown` | Insufficient evidence to determine |
| `partial` | Mixed results across evidence |

### Confidence Levels

| Level | Criteria |
|---|---|
| `high` | Both passive and active evidence agree |
| `medium` | Only one evidence type present |
| `low` | Stale, insufficient, or disagreeing evidence |

## Next Steps

- Read the [Module Development Guide](modules.md) to create custom collectors
- Review the [API Documentation](api.md) for integration options
- Explore control definitions in `controls/` directory
