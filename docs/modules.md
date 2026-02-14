# Module Development Guide

This guide explains how to create custom collectors and testers for OCEAN. Modules are the pluggable integration points that gather evidence from external systems (collectors) and actively verify control effectiveness (testers).

## Architecture Overview

OCEAN uses a Metasploit-style module system. Each module:

1. Implements a Go interface (`Collector` or `Tester`)
2. Registers itself with the module registry at startup
3. Produces structured `evidence.Evidence` records
4. Declares its credential requirements and source system

```
modules/
  collectors/
    mock/          # Reference implementation
    okta/          # Real-world example (future)
  testers/
    mock/          # Reference implementation
```

## Collector Interface

Collectors perform **passive observation** -- they read system state without modifying it. They produce evidence at the `passive_observation` confidence level.

```go
// From internal/module/collector.go
type Collector interface {
    Module
    Collect(ctx context.Context, config map[string]string) ([]evidence.Evidence, error)
}
```

The base `Module` interface that all modules must implement:

```go
// From internal/module/module.go
type Module interface {
    ID() string                              // Unique identifier (e.g., "okta.mfa_policy")
    Name() string                            // Human-readable name
    Version() string                         // Semantic version
    SourceSystem() string                    // External system name (e.g., "okta")
    EvidenceTypes() []int                    // OCSF class UIDs produced
    CredentialRequirements() []CredentialReq // Required credentials
}
```

### Creating a Collector

Here is a walkthrough using the mock collector as reference:

**Step 1: Define the struct and implement the Module interface.**

```go
package okta

import "github.com/grcengineering/ocean/internal/module"

type MFAPolicyCollector struct{}

// Compile-time interface check.
var _ module.Collector = (*MFAPolicyCollector)(nil)

func (c *MFAPolicyCollector) ID() string            { return "okta.mfa_policy" }
func (c *MFAPolicyCollector) Name() string          { return "Okta MFA Policy Collector" }
func (c *MFAPolicyCollector) Version() string       { return "0.1.0" }
func (c *MFAPolicyCollector) SourceSystem() string  { return "okta" }
func (c *MFAPolicyCollector) EvidenceTypes() []int  { return []int{1001} }

func (c *MFAPolicyCollector) CredentialRequirements() []module.CredentialReq {
    return []module.CredentialReq{
        {
            Name:        "OKTA_API_TOKEN",
            Type:        "api_key",
            Description: "Okta API token with read-only admin access",
            Required:    true,
        },
        {
            Name:        "OKTA_DOMAIN",
            Type:        "string",
            Description: "Okta organization domain (e.g., dev-123456.okta.com)",
            Required:    true,
        },
    }
}
```

**Step 2: Implement the `Collect` method.**

The `config` map contains resolved credentials and configuration. Return one or more `evidence.Evidence` records.

```go
func (c *MFAPolicyCollector) Collect(ctx context.Context, config map[string]string) ([]evidence.Evidence, error) {
    domain := config["OKTA_DOMAIN"]
    token := config["OKTA_API_TOKEN"]

    // Call the Okta API to retrieve MFA policies.
    // ... (your API logic here)

    now := time.Now().UTC()
    ev := evidence.Evidence{
        ID:              uuid.New(),
        ControlID:       "iam.mfa_enforcement",
        ClassUID:        1001,
        CategoryUID:     1,
        ActivityID:      1, // Config Check
        Time:            now,
        ConfidenceLevel: evidence.PassiveObservation,
        Metadata: evidence.Metadata{
            Module: evidence.ModuleInfo{
                Name:    "okta.mfa_policy",
                Version: "0.1.0",
                Type:    "collector",
            },
            Source: evidence.SourceInfo{
                System:     "okta",
                APIVersion: "v1",
                Endpoint:   fmt.Sprintf("https://%s/api/v1/policies", domain),
            },
            ProcessedTime: now,
        },
        StatusID: evidence.StatusEffective,
        Status:   "MFA enforcement is required for all users",
        RawData:  rawJSON,
        // ... populate remaining fields
    }

    return []evidence.Evidence{ev}, nil
}
```

**Step 3: Register the module.**

Create a `register.go` file that registers the collector with the module registry:

```go
package okta

import "github.com/grcengineering/ocean/internal/module"

func RegisterAll(reg *module.Registry) {
    reg.RegisterCollector(&MFAPolicyCollector{})
}
```

**Step 4: Wire it into the application.**

Add the registration call in `cmd/ocean/main.go` where modules are loaded.

## Tester Interface

Testers perform **active verification** -- they interact with target systems to prove controls are working. They produce evidence at the `active_verification` confidence level.

```go
// From internal/module/tester.go
type Tester interface {
    Module
    SafetyClass() SafetyClassification
    EnvironmentScope() EnvironmentScope
    PreFlightChecks() []string
    CleanupProcedures() []string
    Test(ctx context.Context, config map[string]string) ([]evidence.Evidence, error)
}
```

### Safety Classifications

Every tester MUST declare a safety classification that determines when and where it can run:

| Classification | Description | Environments | Authorization |
|---|---|---|---|
| `safe` | Read-only, no system impact | All | Automatic |
| `observable` | API calls visible in audit logs | Production, Staging | Prompt required |
| `reversible` | Makes changes that can be rolled back | Staging, Isolated | Explicit approval |
| `destructive` | Irreversible changes | Isolated only | Warning + approval |

```go
func (t *MyTester) SafetyClass() module.SafetyClassification {
    return module.SafetyClassObservable
}
```

### Environment Scopes

Testers declare their intended operating environment:

- `production` -- Live production systems
- `staging` -- Pre-production environments
- `isolated` -- Fully isolated test environments

### Pre-Flight Checks and Cleanup

Testers must declare what they need before running and how they clean up after:

```go
func (t *MyTester) PreFlightChecks() []string {
    return []string{
        "verify target system is reachable",
        "confirm test user account exists",
    }
}

func (t *MyTester) CleanupProcedures() []string {
    return []string{
        "reset test user password",
        "remove temporary MFA enrollment",
    }
}
```

### Test Transcripts

Active tests should record their actions using the transcript recorder:

```go
func (t *MyTester) Test(ctx context.Context, config map[string]string) ([]evidence.Evidence, error) {
    recorder := evidence.NewTranscriptRecorder()

    // Record actions taken.
    recorder.RecordAction("submit login without MFA", map[string]string{
        "target": "auth.example.com",
        "user":   "test-user@example.com",
    })

    // Record observations.
    recorder.RecordObservation("MFA challenge presented", true)
    recorder.RecordObservation("login blocked without MFA", true)

    // Record cleanup.
    recorder.RecordCleanup("remove test artifacts", true)

    transcript := recorder.Finalize()

    ev := evidence.Evidence{
        // ... standard fields ...
        ConfidenceLevel: evidence.ActiveVerification,
        TestTranscript:  transcript,
    }

    return []evidence.Evidence{ev}, nil
}
```

## Evidence Schema

Every evidence record must populate these core fields:

| Field | Type | Description |
|---|---|---|
| `ID` | `uuid.UUID` | Unique identifier (generate with `uuid.New()`) |
| `ControlID` | `string` | ID of the control this evidence supports |
| `ClassUID` | `int` | OCSF class UID for the evidence type |
| `CategoryUID` | `int` | OCSF category UID |
| `ActivityID` | `int` | Activity type (1=config check, 2=active test) |
| `Time` | `time.Time` | When the evidence was collected (UTC) |
| `ConfidenceLevel` | `ConfidenceLevel` | `passive_observation` or `active_verification` |
| `StatusID` | `StatusID` | 0=unknown, 1=effective, 2=ineffective, 99=other |
| `Status` | `string` | Human-readable status description |
| `RawData` | `json.RawMessage` | Original API response or test output |

## Testing Modules

Write tests that verify:

1. The module implements the correct interface (compile-time check)
2. `Collect` or `Test` returns valid evidence records
3. Evidence has all required fields populated
4. Status mapping is correct for different scenarios
5. Error handling works for API failures

Example test structure:

```go
func TestMyCollector_ImplementsInterface(t *testing.T) {
    var _ module.Collector = (*MyCollector)(nil)
}

func TestMyCollector_Collect(t *testing.T) {
    c := &MyCollector{}
    evs, err := c.Collect(context.Background(), map[string]string{
        "API_TOKEN": "test-token",
    })
    require.NoError(t, err)
    require.Len(t, evs, 1)

    ev := evs[0]
    assert.Equal(t, "my.control_id", ev.ControlID)
    assert.Equal(t, evidence.StatusEffective, ev.StatusID)
    assert.Equal(t, evidence.PassiveObservation, ev.ConfidenceLevel)
}
```

## Directory Structure

Follow this convention for new modules:

```
modules/
  collectors/
    <source_system>/
      collector.go         # Main collector implementation
      register.go          # Registry registration function
      collector_test.go    # Tests
  testers/
    <source_system>/
      tester.go            # Main tester implementation
      register.go          # Registry registration function
      tester_test.go       # Tests
```

## Reference Implementations

The mock modules in `modules/collectors/mock/` and `modules/testers/mock/` serve as complete reference implementations. Study these before creating your own modules.
