# OCEAN Test Suite Framework

## Context

OCEAN v2.0.0 is fully implemented (193 tasks, 109 Go files) but the test infrastructure is ad-hoc. 32 test files exist with good patterns (httptest, t.TempDir, testify in some packages), but there are 8 packages at 0% coverage, no test categorization (build tags), no shared helpers, no CI pipeline, and no coverage thresholds. Before adding any new features, we need a robust test framework that runs locally and ports cleanly to GitHub Actions.

**Current coverage snapshot:**
- 0%: config, storage interface, aws/github modules, pkg/ocean, pkg/schema
- 26%: cli | 44%: sqlite | 58%: mock collectors
- 65-92%: core packages (control, eval, attestation, evidence, secrets, scheduler)

## Plan

### Phase 1: Shared Test Helpers (`internal/testutil/`)

Create 6 files providing reusable test infrastructure:

**`internal/testutil/testutil.go`** — Package doc only (~15 lines)

**`internal/testutil/evidence.go`** (~120 lines) — Fluent `EvidenceBuilder`:
```go
ev := testutil.NewEvidence().WithControlID("mfa").WithStatus(evidence.StatusEffective).Build()
```
Defaults: uuid, "test.control", ClassUID 9999, StatusEffective, PassiveObservation, valid metadata.

**`internal/testutil/httpserver.go`** (~80 lines) — `MockAPIServer` wrapping httptest:
```go
srv := testutil.NewMockAPIServer(t)
srv.Handle("GET", "/api/v1/policies", 200, `[{"id":"pol001"}]`)
// srv.Host() returns host:port, srv.URL() returns full URL
// Auto-cleanup via t.Cleanup
```

**`internal/testutil/module.go`** (~100 lines) — `StubCollector` and `StubTester` configurable fakes implementing module.Collector and module.Tester interfaces.

**`internal/testutil/store.go`** (~120 lines) — `MemoryStore` implementing all 16 methods of `storage.Store` interface (generalized from the mockStore in `internal/api/handlers_test.go`). Thread-safe with sync.RWMutex.

**`internal/testutil/assertions.go`** (~60 lines) — `AssertValidEvidence(t, ev)`, `AssertEvidenceCount(t, evs, n)`, `AssertModuleRegistered(t, reg, id)`.

### Phase 2: Makefile Test Targets

Add to existing `Makefile` (keeping `test:` target unchanged):

```makefile
COVERAGE_THRESHOLD ?= 70

test-unit:        go test -race -count=1 -coverprofile=coverage.out ./...
test-integration: go test -race -count=1 -tags=integration ./...
test-e2e:         go test -race -count=1 -tags=e2e ./...
test-all:         go test -race -count=1 -tags="integration e2e" -coverprofile=coverage.out ./...
test-json:        go test -race -count=1 -json ./... 2>&1
coverage-check:   Parses coverage.out, fails if total < COVERAGE_THRESHOLD
coverage-report:  go tool cover -func=coverage.out (per-package breakdown)
```

Convention: Integration test files start with `//go:build integration`. Default `go test ./...` skips them automatically.

### Phase 3: Test Scaffolding for Zero-Coverage Packages

8 new test files, one per untested package:

| File | Key Tests | Notes |
|------|-----------|-------|
| `internal/config/config_test.go` (~70 lines) | DefaultConfig returns proper defaults, SetupLogging parses levels | Uses raw testing.T |
| `internal/config/loader_test.go` (~80 lines) | Load with no file, valid YAML, env overrides | t.TempDir, t.Setenv |
| `modules/collectors/aws/collector_test.go` (~120 lines) | newAWSClient validation, sha256Hex, isThrottleError, IAMCollector metadata | Needs endpoint override (see note below) |
| `modules/collectors/github/collector_test.go` (~100 lines) | Client creation, rate limit handling, BranchProtection collect with httptest | Uses GITHUB_API_URL config override |
| `modules/testers/aws/public_access_test.go` (~90 lines) | 403=effective, 200=ineffective, missing config, transcript present | httptest for bucket URL |
| `modules/testers/github/secret_push_test.go` (~110 lines) | 409/422=blocked, 201=allowed+cleanup, missing config | httptest via GITHUB_API_URL |
| `pkg/schema/evidence_test.go` (~40 lines) | JSON round-trip, constant values, field tags | Pure unit tests |
| `pkg/ocean/client_test.go` (~80 lines) | NewClient, Collect/Test/Evaluate error paths, Close | t.TempDir for SQLite |

**Critical note — AWS endpoint override:** The `iamEndpoint` is a package-level `const`. To test `IAMCollector.Collect` with httptest, we need a small production code change: add `AWS_IAM_ENDPOINT` config key support in `iam.go`, falling back to the constant when not set. Same pattern Okta already uses with `OKTA_INSECURE`/domain override. This is the only production code change in the plan.

### Phase 4: Module Test Template

**`internal/testutil/moduletest.go`** (~80 lines) — `RunCollectorTests(t, collector, config)` and `RunTesterTests(t, tester, config)` that verify the standard module contract: non-empty ID, valid version, evidence types, credential requirements, and that Collect/Test returns valid evidence.

New module tests become:
```go
func TestMyCollector_Contract(t *testing.T) {
    srv := testutil.NewMockAPIServer(t)
    srv.Handle("GET", "/api/data", 200, `{"ok":true}`)
    testutil.RunCollectorTests(t, &MyCollector{}, map[string]string{"URL": srv.URL()})
}
```

**`docs/testing.md`** (~80 lines) — Testing guide: how to run tiers, write module tests, check coverage.

### Phase 5: Integration Tests

**`tests/integration/pipeline_test.go`** (~120 lines, `//go:build integration`):
- `TestCollectStoreEvaluate` — Full pipeline with mock collector + SQLite
- `TestAttestationRoundTrip` — Collect → sign → store → retrieve → verify

**`internal/storage/sqlite/sqlite_integration_test.go`** (~60 lines, `//go:build integration`):
- `TestSQLite_LargeDataset` — 10k evidence records, query correctness
- `TestSQLite_ConcurrentAccess` — Parallel reads/writes

### Phase 6: Test Fixtures

4 fixture files in `tests/fixtures/`:
- `okta_mfa_policy_response.json` — Canned Okta API response
- `aws_list_users_response.xml` — Canned AWS IAM XML
- `github_branch_protection_response.json` — Canned GitHub API response
- `control_mfa.yaml` — Sample control definition for integration tests

**`internal/testutil/fixtures.go`** (~40 lines) — `LoadFixture(t, "okta_mfa_policy_response.json")` helper using `runtime.Caller` to locate project root.

### Phase 7: GitHub Actions CI

**`.github/workflows/ci.yml`** (~100 lines):

```
Jobs:
  lint:           golangci-lint-action
  test-unit:      go test -race -json | gotestfmt, coverage-check, upload artifact
  test-integration: (needs test-unit) go test -tags=integration -json | gotestfmt
  build:          (needs lint, test-unit) matrix: linux/darwin/windows × amd64/arm64
```

Uses `actions/setup-go@v5` with `go-version-file: go.mod` and cache. gotestfmt installed via `go install`.

### Phase 8: Documentation

**`docs/testing.md`** covering:
- Running tests: `make test-unit`, `make test-integration`, `make test-all`
- Coverage: `make coverage-check`, `make coverage-report`
- Writing module tests (reference template pattern)
- Build tag conventions
- CI pipeline overview

## Key Design Decisions

1. **Keep mixed testify/raw testing.T** — Match existing file patterns. New testutil uses raw testing.T.
2. **70% initial coverage threshold** — Realistic given 8 packages at 0%. Raise to 80% after filling gaps.
3. **Colocated integration tests with build tags** — Standard Go pattern. `tests/integration/` only for cross-package tests.
4. **go test -json + gotestfmt** — Native Go output, gotestfmt for CI annotations.
5. **Endpoint override for AWS** — Only production code change. Add `AWS_IAM_ENDPOINT` config support, matching Okta's pattern.

## Files Modified/Created

| Phase | Files | ~Lines |
|-------|-------|--------|
| 1 | 6 new in `internal/testutil/` | 495 |
| 2 | Makefile (modify) | +40 |
| 3 | 8 new test files | 690 |
| 4 | 1 new in testutil + 1 doc | 160 |
| 5 | 2 new integration test files | 180 |
| 6 | 4 fixtures + 1 loader | 170 |
| 7 | 1 CI workflow | 100 |
| 8 | 1 doc | 80 |
| **Total** | **24 new + 1 modified + 1 prod change** | **~1,915** |

**Production code change:** `modules/collectors/aws/iam.go` — Add `AWS_IAM_ENDPOINT` config override (5 lines).

## Execution Order

```
Phase 1 (testutil) → Phase 2 (Makefile)
    ↓
Phase 3 + 4 + 6 (parallel: scaffolding, template, fixtures)
    ↓
Phase 5 (integration tests)
    ↓
Phase 7 (CI) → Phase 8 (docs)
```

## Verification

1. `make test-unit` — All existing + new tests pass
2. `make test-integration` — Integration tests run with build tag
3. `make coverage-check` — Passes 70% threshold
4. `make coverage-report` — Shows per-package breakdown, no packages at 0%
5. `grep "//go:build integration" tests/integration/pipeline_test.go` — Tag present
6. `cat .github/workflows/ci.yml` — Valid workflow with all job dependencies
7. `make test-json | head` — JSON output streams correctly
