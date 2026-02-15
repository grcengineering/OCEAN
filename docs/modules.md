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
    aws/             AWS IAM collector
    github/          GitHub branch protection collector
    mock/            Reference collector implementation
    okta/            Okta MFA policy collector
  testers/
    aws/             S3 public access tester
    github/          Secret push protection tester
    mock/            Reference tester implementation
    okta/            MFA bypass tester
```

## Module Interface

All modules implement the base `Module` interface:

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

## Collector Interface

Collectors perform **passive observation** -- they read system state without modifying it. They produce evidence at the `passive_observation` confidence level.

```go
// From internal/module/collector.go
type Collector interface {
    Module
    Collect(ctx context.Context, config map[string]string) ([]evidence.Evidence, error)
}
```

### Creating a Collector

Here is a walkthrough based on the real Okta MFA policy collector:

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
                Name:    c.ID(),
                Version: c.Version(),
                Type:    "collector",
            },
            Source: evidence.SourceInfo{
                System:     c.SourceSystem(),
                APIVersion: "v1",
                Endpoint:   fmt.Sprintf("https://%s/api/v1/policies", domain),
            },
            ProcessedTime: now,
        },
        StatusID: evidence.StatusEffective,
        Status:   "MFA enforcement is required for all users",
        RawData:  rawJSON,
    }

    return []evidence.Evidence{ev}, nil
}
```

**Step 3: Create a registration function.**

Every module package must export a `RegisterAll` function:

```go
package okta

import "github.com/grcengineering/ocean/internal/module"

func RegisterAll(reg *module.Registry) {
    reg.RegisterCollector(&MFAPolicyCollector{})
}
```

**Step 4: Wire it into the CLI.**

Add the import and registration call in the CLI files (`internal/cli/collect.go`, `internal/cli/modules.go`, etc.):

```go
import (
    oktacollector "github.com/grcengineering/ocean/modules/collectors/okta"
)

// In the command's RunE function:
reg := module.NewRegistry()
oktacollector.RegisterAll(reg)
```

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

### Environment Scopes

Testers declare their intended operating environment:

- `production` -- Live production systems
- `staging` -- Pre-production environments
- `isolated` -- Fully isolated test environments

### Creating a Tester

Based on the real Okta MFA bypass tester:

```go
package okta

import "github.com/grcengineering/ocean/internal/module"

type MFABypassTester struct{}

var _ module.Tester = (*MFABypassTester)(nil)

func (t *MFABypassTester) ID() string            { return "okta.mfa_bypass" }
func (t *MFABypassTester) Name() string          { return "Okta MFA Bypass Tester" }
func (t *MFABypassTester) Version() string       { return "0.1.0" }
func (t *MFABypassTester) SourceSystem() string  { return "okta" }
func (t *MFABypassTester) EvidenceTypes() []int  { return []int{1001} }

func (t *MFABypassTester) CredentialRequirements() []module.CredentialReq {
    return []module.CredentialReq{
        {Name: "OKTA_DOMAIN", Type: "string", Required: true},
        {Name: "OKTA_API_TOKEN", Type: "api_key", Required: true},
        {Name: "OKTA_TEST_USER", Type: "string", Required: true},
        {Name: "OKTA_TEST_PASSWORD", Type: "string", Required: true},
    }
}

func (t *MFABypassTester) SafetyClass() module.SafetyClassification {
    return module.SafetyClassSafe
}

func (t *MFABypassTester) EnvironmentScope() module.EnvironmentScope {
    return module.ScopeProduction
}

func (t *MFABypassTester) PreFlightChecks() []string {
    return []string{
        "verify Okta domain is reachable",
        "verify test user credentials are valid",
    }
}

func (t *MFABypassTester) CleanupProcedures() []string {
    return nil // safe test, no cleanup needed
}
```

### Test Transcripts

Active tests record their actions using the transcript recorder for full auditability:

```go
func (t *MFABypassTester) Test(ctx context.Context, config map[string]string) ([]evidence.Evidence, error) {
    recorder := evidence.NewTranscriptRecorder()

    // Record actions taken.
    recorder.RecordAction("submit login without MFA", map[string]string{
        "target": config["OKTA_DOMAIN"],
        "user":   config["OKTA_TEST_USER"],
    })

    // Make the actual API call...
    // ... your test logic here ...

    // Record observations.
    recorder.RecordObservation("MFA challenge presented", true)
    recorder.RecordObservation("login blocked without MFA token", true)

    // Record cleanup (if any).
    recorder.RecordCleanup("remove test artifacts", true)

    transcript := recorder.Finalize()

    ev := evidence.Evidence{
        ID:              uuid.New(),
        ControlID:       "iam.mfa_enforcement",
        ClassUID:        1001,
        CategoryUID:     1,
        ActivityID:      2, // Active Test
        Time:            time.Now().UTC(),
        ConfidenceLevel: evidence.ActiveVerification,
        TestTranscript:  transcript,
        Metadata: evidence.Metadata{
            Module: evidence.ModuleInfo{
                Name:    t.ID(),
                Version: t.Version(),
                Type:    "tester",
            },
            SafetyClassification: string(t.SafetyClass()),
        },
        StatusID: evidence.StatusEffective,
        Status:   "MFA bypass attempt was correctly blocked",
    }

    return []evidence.Evidence{ev}, nil
}
```

### Registering Testers

Same pattern as collectors:

```go
package okta

import "github.com/grcengineering/ocean/internal/module"

func RegisterAll(reg *module.Registry) {
    reg.RegisterTester(&MFABypassTester{})
}
```

Wire into `internal/cli/test.go` and `internal/cli/modules.go`:

```go
import (
    oktatester "github.com/grcengineering/ocean/modules/testers/okta"
)

// In RunE:
oktatester.RegisterAll(reg)
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
| `Findings` | `[]Finding` | Structured findings with title, description, severity |
| `Observables` | `[]Observable` | Entities observed (users, resources, etc.) |

## Module Validation

OCEAN validates modules at runtime. Run validation with:

```bash
./ocean modules validate <module-id>
```

Validation checks:
- ID is non-empty and follows `<source>.<name>` convention
- Name, Version, SourceSystem are populated
- EvidenceTypes list is non-empty
- For testers: SafetyClass and EnvironmentScope are valid values
- For testers: CanRunInEnvironment matrix is respected

## Testing Modules

Write tests that verify:

1. The module implements the correct interface (compile-time check)
2. `Collect` or `Test` returns valid evidence records
3. Evidence has all required fields populated
4. Status mapping is correct for different scenarios
5. Error handling works for API failures

Use `net/http/httptest` to mock external APIs:

```go
func TestMFAPolicyCollector_Collect(t *testing.T) {
    // Create a mock Okta API server.
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode([]map[string]interface{}{
            {"id": "policy1", "status": "ACTIVE", "type": "MFA_ENROLL"},
        })
    }))
    defer srv.Close()

    c := &MFAPolicyCollector{}
    evs, err := c.Collect(context.Background(), map[string]string{
        "OKTA_DOMAIN":    strings.TrimPrefix(srv.URL, "http://"),
        "OKTA_API_TOKEN": "test-token",
    })
    require.NoError(t, err)
    require.Len(t, evs, 1)

    ev := evs[0]
    assert.Equal(t, "okta.mfa_policy", ev.Metadata.Module.Name)
    assert.Equal(t, evidence.PassiveObservation, ev.ConfidenceLevel)
    assert.Equal(t, evidence.StatusEffective, ev.StatusID)
}
```

## Directory Structure

Follow this convention for new modules:

```
modules/
  collectors/
    <source_system>/
      collector.go         # Base HTTP client and RegisterAll function
      <feature>.go         # Feature-specific collector (e.g., mfa.go, iam.go)
      collector_test.go    # Tests for base client
      <feature>_test.go    # Tests for feature collector
  testers/
    <source_system>/
      <feature>.go         # Feature-specific tester (e.g., mfa_bypass.go)
      register.go          # RegisterAll function
      <feature>_test.go    # Tests
```

## Reference Implementations

Study these existing modules before creating your own:

| Module | Files | Good Example Of |
|--------|-------|-----------------|
| `modules/collectors/mock/` | Simple, self-contained | Basic collector pattern |
| `modules/testers/mock/` | Simple, self-contained | Basic tester with transcript |
| `modules/collectors/okta/` | HTTP client + rate limiting | Real API integration |
| `modules/collectors/aws/` | SigV4 signing, pagination | Complex auth, XML parsing |
| `modules/testers/github/` | Observable safety class | Non-safe tester pattern |
