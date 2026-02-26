# Plan: Phase 1 — Shared Test Helper Package (`internal/testutil/`)

## Context

Creating 6 files in `/mnt/c/users/justi/code/ocean/internal/testutil/` that provide shared test infrastructure for the OCEAN project. The existing `testutil.go` already has the package doc comment. I need to either update it or leave it as-is and create the remaining 5 files.

## Key Observations from Code Review

Before writing code, I reviewed every relevant source interface and type. Here are critical differences between the user's spec and the actual codebase that the implementation must respect:

1. **`ConfidenceLevel` is a `string`, not `int`**. Constants are `PassiveObservation = "passive_observation"` and `ActiveVerification = "active_verification"`. The user spec says `int` values 1/2 — I must use the actual `string` type.

2. **`SafetyClassification` is a `string`, not `int`**. Constants are `SafetyClassSafe = "safe"`, etc. The user spec says int 0-3 — I must use the actual `string` type.

3. **`EnvironmentScope` is a `string`, not `int`**. Constants are `ScopeProduction = "production"`, `ScopeStaging = "staging"`, `ScopeIsolated = "isolated"`. User spec says int 0-2 — I must use actual type.

4. **The tester method is `SafetyClass()` not `SafetyClassification()`**. Confirmed from `internal/module/tester.go`.

5. **`Finding` struct has `SeverityID int`, not `Severity int`**. And it has NO `Labels map[string]string` field.

6. **`Observable` struct has only `Type` and `Value` fields — no `Name` field**.

7. **`CredentialRequirements()` returns `[]CredentialReq`**, a struct with Name/Type/Description/Required fields.

8. **`EvidenceQuery.Source` is a `string` field** — filtering by source system name.

9. **The Registry method for assertions is `GetModule(id string) (Module, error)`** — not just `Get`.

10. **`testutil.go` already exists** with the package doc comment. I can leave it as-is or update it slightly.

## Files to Create

### 1. `testutil.go` — Already exists, may need minor update

The existing file already has the package doc and helper list. It matches the spec. Leave as-is.

### 2. `evidence.go` (~120 lines) — EvidenceBuilder

```
Package: testutil
Imports: evidence, uuid, time, encoding/json

EvidenceBuilder struct with all Evidence fields as builder state.

NewEvidence() *EvidenceBuilder — sets defaults:
  - ID: uuid.New()
  - ControlID: "test.control"
  - ClassUID: 9999, CategoryUID: 9, ActivityID: 1
  - Time: time.Now().UTC()
  - ConfidenceLevel: evidence.PassiveObservation (string, not int)
  - StatusID: evidence.StatusEffective
  - Status: "effective"
  - Metadata.Module: {Name: "test.module", Version: "0.1.0", Type: "collector"}
  - Metadata.Source: {System: "test", APIVersion: "v1", Endpoint: "/test"}
  - Metadata.ProcessedTime: time.Now().UTC()
  - RawData: json.RawMessage(`{"test":true}`)
  - Findings: []evidence.Finding{} (empty, not nil)
  - Observables: []evidence.Observable{} (empty, not nil)

Builder methods (all return *EvidenceBuilder for chaining):
  - WithControlID(id string)
  - WithStatus(statusID evidence.StatusID, status string)
  - WithConfidence(level evidence.ConfidenceLevel)
  - WithModule(name, version, typ string)
  - WithSource(system, apiVersion, endpoint string)
  - WithRawData(data json.RawMessage)
  - WithFinding(title, desc string, severity int) — appends Finding
  - WithTranscript(transcript *evidence.TestTranscript)

Build() evidence.Evidence — returns the constructed value
```

### 3. `httpserver.go` (~80 lines) — MockAPIServer

```
Package: testutil
Imports: net/http, net/http/httptest, testing, fmt, sync

MockAPIServer struct:
  - server *httptest.Server
  - mu sync.Mutex
  - routes map[string]http.HandlerFunc  (key: "METHOD /path")

NewMockAPIServer(t *testing.T) *MockAPIServer:
  - Creates routes map
  - Creates httptest.NewServer with handler that:
    - Locks mu, looks up "METHOD /path" key
    - If found, calls handler
    - If not found, writes 404 with JSON body {"error":"not found"}
  - Registers t.Cleanup(server.Close)
  - Returns &MockAPIServer

Handle(method, path string, status int, body string):
  - Registers handler that writes status + body

HandleFunc(method, path string, handler http.HandlerFunc):
  - Registers handler directly

Host() string — returns server.Listener.Addr().String()
URL() string — returns server.URL
```

### 4. `module.go` (~100 lines) — StubCollector and StubTester

```
Package: testutil
Imports: module, evidence, context

StubCollector struct:
  - IDVal string
  - NameVal string
  - VersionVal string
  - SourceSystemVal string
  - EvidenceTypesVal []int
  - CredReqsVal []module.CredentialReq
  - CollectFunc func(ctx context.Context, config map[string]string) ([]evidence.Evidence, error)

Methods implementing module.Collector:
  - ID() string -> IDVal
  - Name() string -> NameVal
  - Version() string -> VersionVal
  - SourceSystem() string -> SourceSystemVal
  - EvidenceTypes() []int -> EvidenceTypesVal
  - CredentialRequirements() []module.CredentialReq -> CredReqsVal
  - Collect(ctx, config) -> calls CollectFunc if non-nil, else returns nil, nil

NewStubCollector(id string) *StubCollector:
  - IDVal: id
  - NameVal: id (same)
  - VersionVal: "0.1.0"
  - SourceSystemVal: "test"
  - EvidenceTypesVal: []int{9999}

StubTester struct:
  - Embeds same base fields as StubCollector (IDVal, NameVal, etc.)
  - SafetyVal module.SafetyClassification
  - ScopeVal module.EnvironmentScope
  - PreFlightVal []string
  - CleanupVal []string
  - TestFunc func(ctx context.Context, config map[string]string) ([]evidence.Evidence, error)

Methods implementing module.Tester:
  - All Module methods (ID, Name, Version, SourceSystem, EvidenceTypes, CredentialRequirements)
  - SafetyClass() -> SafetyVal
  - EnvironmentScope() -> ScopeVal
  - PreFlightChecks() -> PreFlightVal
  - CleanupProcedures() -> CleanupVal
  - Test(ctx, config) -> calls TestFunc if non-nil, else returns nil, nil

NewStubTester(id string) *StubTester:
  - Same base defaults as collector
  - SafetyVal: module.SafetyClassSafe
  - ScopeVal: module.ScopeIsolated
```

### 5. `store.go` (~120 lines) — MemoryStore

```
Package: testutil
Imports: context, sync, time, fmt,
         uuid, evidence, control, scheduler, storage

MemoryStore struct:
  - mu sync.RWMutex
  - evidence map[uuid.UUID]*evidence.Evidence
  - statuses map[string][]control.ControlStatus  (keyed by ControlID)
  - attestations map[string][]byte
  - schedules map[string]*scheduler.Schedule
  - runs map[string][]scheduler.ScheduleRun  (keyed by ScheduleID)
  - closed bool

NewMemoryStore() *MemoryStore — initializes all maps

Implements storage.Store (16 methods + Close):

StoreEvidence: copies ev, stores by ID
GetEvidence: returns pointer to stored copy, or fmt.Errorf not found
QueryEvidence: iterate evidence map, filter by:
  - ControlID (if query.ControlID != "")
  - Source (if query.Source != "", match ev.Metadata.Source.System)
  - Apply query.Limit
StoreControlStatus: appends to statuses[status.ControlID]
GetControlStatus: returns latest (last element) for controlID, or error
QueryHistory: filter statuses[controlID] by from/to time range on Timestamp
StoreAttestation: stores envelope by ref
GetAttestation: returns envelope or error
StoreSchedule: copies, stores by ID
GetSchedule: returns pointer or error
ListSchedules: returns all values
DeleteSchedule: deletes key or error
StoreScheduleRun: appends to runs[run.ScheduleID]
ListScheduleRuns: returns runs for scheduleID, capped by limit
Close: sets closed=true, returns nil
```

### 6. `assertions.go` (~60 lines) — Assertion helpers

```
Package: testutil
Imports: testing, evidence, module, uuid

AssertValidEvidence(t *testing.T, ev evidence.Evidence):
  t.Helper()
  - Check ev.ID != uuid.Nil (uuid.UUID zero value)
  - Check ev.ControlID != ""
  - Check ev.Time.IsZero() == false
  - Check ev.Metadata.Module.Name != ""
  - On failure, use t.Errorf with descriptive messages

AssertEvidenceCount(t *testing.T, evs []evidence.Evidence, expected int):
  t.Helper()
  - Check len(evs) == expected
  - On failure, t.Errorf("got %d evidence records, want %d", len(evs), expected)

AssertModuleRegistered(t *testing.T, reg *module.Registry, moduleID string):
  t.Helper()
  - Call reg.GetModule(moduleID)
  - If err != nil, t.Errorf("module %q not registered: %v", moduleID, err)
```

## Implementation Order

1. `testutil.go` — Verify existing file is sufficient (already done, it's fine)
2. `evidence.go` — No internal dependencies
3. `httpserver.go` — No internal dependencies
4. `module.go` — Depends on module and evidence packages
5. `store.go` — Depends on evidence, control, scheduler, storage packages
6. `assertions.go` — Depends on evidence, module packages

Files 2-4 can be created in parallel. File 5 can follow. File 6 can be created alongside any of them.

## Verification

After creating all files, run:
```bash
cd /mnt/c/users/justi/code/ocean && go build ./internal/testutil/
```

This confirms everything compiles. No test files are being written in this phase (tests for the test helpers would be Phase 2 or a separate concern).
