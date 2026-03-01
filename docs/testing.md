# OCEAN Testing Guide

This document describes how to run tests, check coverage, and write tests for new modules in the OCEAN project.

## Running Tests Locally

OCEAN uses a tiered testing strategy with build tags to separate fast unit tests from slower integration and end-to-end tests.

### Unit Tests

Unit tests run without any external dependencies and do not require build tags. They are the fastest tier and should always pass before submitting code.

```bash
make test-unit
```

This runs `go test -race -count=1 -coverprofile=coverage.out ./...` across all packages.

### Integration Tests

Integration tests use the `//go:build integration` build tag. They exercise real SQLite storage, multi-module pipelines, and cross-package interactions.

```bash
make test-integration
```

This runs `go test -race -count=1 -tags=integration ./...`.

### All Tests

To run every test tier (unit + integration + e2e) in a single pass:

```bash
make test-all
```

This runs `go test -race -count=1 -tags="integration e2e" -coverprofile=coverage.out ./...`.

## Checking Coverage

### Coverage Threshold

The project enforces a minimum coverage threshold (default 70%). The CI pipeline will fail if coverage drops below this threshold.

```bash
make coverage-check
```

This runs unit tests, generates `coverage.out`, and checks the total coverage percentage against the `COVERAGE_THRESHOLD` variable (configurable via environment).

### Coverage Report

To see a per-package breakdown of coverage:

```bash
make coverage-report
```

To generate an HTML coverage report:

```bash
make coverage
```

This produces `coverage.html` which you can open in a browser for a visual line-by-line coverage view.

## Writing Tests for New Modules

When adding a new observer or tester module, use the standard contract test helpers in `internal/testutil/moduletest.go` to verify your module satisfies all interface contracts.

### Observer Tests

Use `testutil.RunObserverTests` to validate a new observer:

```go
package mymodule_test

import (
    "testing"

    "github.com/grcengineering/ocean/internal/testutil"
    "github.com/grcengineering/ocean/modules/observers/mymodule"
)

func TestMyObserver(t *testing.T) {
    // Set up a mock API server for the external service.
    srv := testutil.NewMockAPIServer(t)
    srv.Handle("GET", "/api/v1/data", 200, `{"result": "ok"}`)

    observer := mymodule.NewObserver()
    config := map[string]string{
        "API_URL": srv.URL,
        "API_KEY": "test-key",
    }

    // RunObserverTests validates:
    // - All metadata fields (ID, Name, Version, SourceSystem, EvidenceTypes) are non-empty
    // - Collect returns valid evidence with passive_observation confidence
    // - Each evidence record passes structural validation
    testutil.RunObserverTests(t, observer, config)
}
```

### Tester Tests

Use `testutil.RunTesterTests` to validate a new tester:

```go
package mymodule_test

import (
    "testing"

    "github.com/grcengineering/ocean/internal/testutil"
    "github.com/grcengineering/ocean/modules/testers/mymodule"
)

func TestMyTester(t *testing.T) {
    srv := testutil.NewMockAPIServer(t)
    srv.Handle("POST", "/api/v1/test", 200, `{"blocked": true}`)

    tester := mymodule.NewTester()
    config := map[string]string{
        "API_URL": srv.URL,
        "API_KEY": "test-key",
    }

    // RunTesterTests validates everything RunObserverTests does, plus:
    // - SafetyClass() returns a valid classification
    // - EnvironmentScope() returns a valid scope
    // - PreFlightChecks() is non-nil
    // - Test returns evidence with active_verification confidence
    // - Each evidence record includes a TestTranscript
    testutil.RunTesterTests(t, tester, config)
}
```

### Using Test Helpers

The `internal/testutil` package provides several helpers:

| Helper | Purpose |
|--------|---------|
| `NewStubObserver(id)` | Configurable fake observer for registry/pipeline tests |
| `NewStubTester(id)` | Configurable fake tester for registry/pipeline tests |
| `NewEvidence()` | Fluent builder for constructing evidence records |
| `NewMockAPIServer(t)` | HTTP test server for mocking external APIs |
| `NewMemoryStore()` | In-memory `storage.Store` implementation |
| `AssertValidEvidence(t, ev)` | Validates evidence structural requirements |
| `AssertEvidenceCount(t, evs, n)` | Checks evidence slice length |
| `AssertModuleRegistered(t, reg, id)` | Verifies a module is in the registry |
| `LoadFixture(t, name)` | Reads canned responses from `tests/fixtures/` |

### Evidence Builder Example

```go
ev := testutil.NewEvidence().
    WithControlID("mfa.enforcement").
    WithStatus(evidence.StatusEffective).
    WithConfidence(evidence.ActiveVerification).
    WithModule("my.module", "1.0.0", "tester").
    WithSource("myservice", "v2", "/api/test").
    WithTranscript().
    Build()
```

## Build Tag Conventions

| Tag | Usage | When to use |
|-----|-------|-------------|
| _(none)_ | Unit tests | Default; no external dependencies |
| `integration` | Integration tests | Real SQLite, cross-package pipelines |
| `e2e` | End-to-end tests | Full CLI workflows, external services |

Always place the build constraint as the first line of the file:

```go
//go:build integration

package integration
```

## CI Pipeline Overview

The GitHub Actions CI pipeline (`.github/workflows/ci.yml`) runs on every push to `main` and every pull request targeting `main`. It consists of four jobs:

1. **lint** -- Runs `golangci-lint` against the entire codebase.
2. **test-unit** -- Runs all unit tests with race detection, generates coverage, and checks the coverage threshold.
3. **test-integration** -- Runs integration tests (requires `test-unit` to pass first).
4. **build** -- Cross-compiles for linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, and windows/amd64 (requires `lint` and `test-unit` to pass first).

### Test Fixture Files

Canned API responses for external services live in `tests/fixtures/`:

| File | Description |
|------|-------------|
| `control_mfa.yaml` | Sample MFA enforcement control definition |
| `github_branch_protection_response.json` | GitHub branch protection API response |
| `aws_list_users_response.xml` | AWS IAM ListUsers API response |
| `okta_mfa_policy_response.json` | Okta MFA policy API response |

Load fixtures in tests with:

```go
data := testutil.LoadFixture(t, "github_branch_protection_response.json")
```
