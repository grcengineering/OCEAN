# Phase 3: Test Scaffolding for 8 Zero-Coverage Packages

## Summary

Create test files for 8 packages that currently have 0% test coverage. All tests use stdlib `testing` (matching the dominant style -- only 5 of 32 test files use testify). All HTTP tests use `httptest.NewServer`. All file/DB operations use `t.TempDir()`. All env var tests use `t.Setenv()`.

## Findings from Source Analysis

1. **Test style**: The neighboring module tests (mock, okta) all use plain `testing` package -- no testify. We match that style.
2. **GitHub observer/tester**: Both `newClient` and `newGHClient` accept `GITHUB_API_URL` in config, so we CAN point them at httptest servers.
3. **AWS observer**: The `iamEndpoint` is a package-level constant. Cannot override for httptest. Test only utility functions and client creation.
4. **AWS tester (PublicAccessTester)**: Uses `config["AWS_TEST_BUCKET"]` as the full URL for HTTP GET. We CAN point it at httptest.
5. **pkg/schema**: Pure data types. Test JSON round-trip and constant values.
6. **pkg/ocean/client**: Uses real SQLite via `sqlitestore.Open`. Use `t.TempDir()` for the DB path.

---

## File 1: `/mnt/c/users/justi/code/ocean/internal/config/config_test.go`

**Target: ~70 lines**

Tests:
- `TestDefaultConfig_StoragePath` -- assert `"~/.ocean/ocean.db"`
- `TestDefaultConfig_LogLevel` -- assert `"info"`
- `TestDefaultConfig_KeyPath` -- assert `"~/.ocean/keys"`
- `TestDefaultConfig_ControlsDir` -- assert `"controls"`
- `TestDefaultConfig_OutputFormat` -- assert `"json"`
- `TestDefaultConfig_ServerPort` -- assert `8080`
- `TestDefaultConfig_AuthTokenEmpty` -- assert `""`
- `TestSetupLogging_ValidLevel` -- set `"debug"`, call SetupLogging, verify `zerolog.GlobalLevel() == zerolog.DebugLevel`
- `TestSetupLogging_InvalidLevel` -- set `"bogus"`, call SetupLogging, verify falls back to `zerolog.InfoLevel`

```go
package config

import (
	"testing"

	"github.com/rs/zerolog"
)

func TestDefaultConfig_StoragePath(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.StoragePath != "~/.ocean/ocean.db" {
		t.Errorf("StoragePath = %q, want %q", cfg.StoragePath, "~/.ocean/ocean.db")
	}
}

func TestDefaultConfig_LogLevel(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, "info")
	}
}

func TestDefaultConfig_KeyPath(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.KeyPath != "~/.ocean/keys" {
		t.Errorf("KeyPath = %q, want %q", cfg.KeyPath, "~/.ocean/keys")
	}
}

func TestDefaultConfig_ControlsDir(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.ControlsDir != "controls" {
		t.Errorf("ControlsDir = %q, want %q", cfg.ControlsDir, "controls")
	}
}

func TestDefaultConfig_OutputFormat(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.OutputFormat != "json" {
		t.Errorf("OutputFormat = %q, want %q", cfg.OutputFormat, "json")
	}
}

func TestDefaultConfig_ServerPort(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Server.Port != 8080 {
		t.Errorf("Server.Port = %d, want %d", cfg.Server.Port, 8080)
	}
}

func TestDefaultConfig_AuthTokenEmpty(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Server.AuthToken != "" {
		t.Errorf("Server.AuthToken = %q, want empty", cfg.Server.AuthToken)
	}
}

func TestSetupLogging_ValidLevel(t *testing.T) {
	cfg := &Config{LogLevel: "debug"}
	SetupLogging(cfg)
	if zerolog.GlobalLevel() != zerolog.DebugLevel {
		t.Errorf("global level = %v, want %v", zerolog.GlobalLevel(), zerolog.DebugLevel)
	}
	// Reset to avoid affecting other tests.
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
}

func TestSetupLogging_InvalidLevel(t *testing.T) {
	cfg := &Config{LogLevel: "bogus"}
	SetupLogging(cfg)
	if zerolog.GlobalLevel() != zerolog.InfoLevel {
		t.Errorf("global level = %v, want %v (fallback)", zerolog.GlobalLevel(), zerolog.InfoLevel)
	}
}
```

---

## File 2: `/mnt/c/users/justi/code/ocean/internal/config/loader_test.go`

**Target: ~80 lines**

Tests:
- `TestLoad_NoFile_ReturnsDefaults` -- pass nonexistent path via TempDir, get defaults
- `TestLoad_ValidYAML` -- write YAML to TempDir, verify override
- `TestLoad_InvalidYAML` -- write garbage to TempDir, expect error
- `TestLoad_EnvVarOverrides` -- use `t.Setenv()` for `OCEAN_STORAGE_PATH`, `OCEAN_LOG_LEVEL`, `OCEAN_KEY_PATH`

```go
package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_NoFile_ReturnsDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent.yaml")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, "info")
	}
	if cfg.StoragePath != "~/.ocean/ocean.db" {
		t.Errorf("StoragePath = %q, want default", cfg.StoragePath)
	}
}

func TestLoad_ValidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	content := []byte("storage_path: /tmp/test.db\nlog_level: debug\n")
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatalf("writing config file: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if cfg.StoragePath != "/tmp/test.db" {
		t.Errorf("StoragePath = %q, want %q", cfg.StoragePath, "/tmp/test.db")
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, "debug")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")

	content := []byte(":::not yaml at all[[[")
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatalf("writing config file: %v", err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() should return error for invalid YAML")
	}
}

func TestLoad_EnvVarOverrides(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent.yaml")

	t.Setenv("OCEAN_STORAGE_PATH", "/env/override.db")
	t.Setenv("OCEAN_LOG_LEVEL", "warn")
	t.Setenv("OCEAN_KEY_PATH", "/env/keys")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if cfg.StoragePath != "/env/override.db" {
		t.Errorf("StoragePath = %q, want %q", cfg.StoragePath, "/env/override.db")
	}
	if cfg.LogLevel != "warn" {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, "warn")
	}
	if cfg.KeyPath != "/env/keys" {
		t.Errorf("KeyPath = %q, want %q", cfg.KeyPath, "/env/keys")
	}
}
```

---

## File 3: `/mnt/c/users/justi/code/ocean/modules/observers/aws/observer_test.go`

**Target: ~120 lines**

Tests (utility functions and client creation only -- iamEndpoint is constant):
- `TestNewAWSClient_MissingAccessKey`
- `TestNewAWSClient_MissingSecretKey`
- `TestNewAWSClient_DefaultRegion`
- `TestNewAWSClient_CustomRegion`
- `TestNewAWSClient_SessionToken`
- `TestSha256Hex_EmptyString` -- known value: `"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"`
- `TestSha256Hex_KnownValue` -- `sha256Hex("hello")` known value
- `TestDeriveSigningKey_NotEmpty` -- verify non-nil result
- `TestIsThrottleError_True` -- pass `*throttleError`, expect true
- `TestIsThrottleError_False` -- pass `fmt.Errorf(...)`, expect false
- `TestIAMObserver_ID`
- `TestIAMObserver_Name`
- `TestIAMObserver_CredentialRequirements`

```go
package aws

import (
	"fmt"
	"testing"

	"github.com/grcengineering/ocean/internal/module"
)

func TestNewAWSClient_MissingAccessKey(t *testing.T) {
	config := map[string]string{
		"AWS_SECRET_ACCESS_KEY": "secret",
	}
	_, err := newAWSClient(config)
	if err == nil {
		t.Fatal("newAWSClient() should return error when AWS_ACCESS_KEY_ID is missing")
	}
}

func TestNewAWSClient_MissingSecretKey(t *testing.T) {
	config := map[string]string{
		"AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
	}
	_, err := newAWSClient(config)
	if err == nil {
		t.Fatal("newAWSClient() should return error when AWS_SECRET_ACCESS_KEY is missing")
	}
}

func TestNewAWSClient_DefaultRegion(t *testing.T) {
	config := map[string]string{
		"AWS_ACCESS_KEY_ID":     "AKIAIOSFODNN7EXAMPLE",
		"AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}
	client, err := newAWSClient(config)
	if err != nil {
		t.Fatalf("newAWSClient() returned error: %v", err)
	}
	if client.region != "us-east-1" {
		t.Errorf("region = %q, want %q", client.region, "us-east-1")
	}
}

func TestNewAWSClient_CustomRegion(t *testing.T) {
	config := map[string]string{
		"AWS_ACCESS_KEY_ID":     "AKIAIOSFODNN7EXAMPLE",
		"AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"AWS_REGION":            "eu-west-1",
	}
	client, err := newAWSClient(config)
	if err != nil {
		t.Fatalf("newAWSClient() returned error: %v", err)
	}
	if client.region != "eu-west-1" {
		t.Errorf("region = %q, want %q", client.region, "eu-west-1")
	}
}

func TestNewAWSClient_SessionToken(t *testing.T) {
	config := map[string]string{
		"AWS_ACCESS_KEY_ID":     "AKIAIOSFODNN7EXAMPLE",
		"AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"AWS_SESSION_TOKEN":     "FwoGZXIvYXdzEBYaDH...",
	}
	client, err := newAWSClient(config)
	if err != nil {
		t.Fatalf("newAWSClient() returned error: %v", err)
	}
	if client.sessionToken != "FwoGZXIvYXdzEBYaDH..." {
		t.Errorf("sessionToken = %q, want %q", client.sessionToken, "FwoGZXIvYXdzEBYaDH...")
	}
}

func TestSha256Hex_EmptyString(t *testing.T) {
	got := sha256Hex("")
	want := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got != want {
		t.Errorf("sha256Hex('') = %q, want %q", got, want)
	}
}

func TestSha256Hex_KnownValue(t *testing.T) {
	got := sha256Hex("hello")
	want := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if got != want {
		t.Errorf("sha256Hex('hello') = %q, want %q", got, want)
	}
}

func TestDeriveSigningKey_NotEmpty(t *testing.T) {
	key := deriveSigningKey("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "20230101", "us-east-1", "iam")
	if len(key) == 0 {
		t.Fatal("deriveSigningKey() returned empty key")
	}
	if len(key) != 32 {
		t.Errorf("deriveSigningKey() returned key of length %d, want 32 (SHA-256)", len(key))
	}
}

func TestIsThrottleError_True(t *testing.T) {
	err := &throttleError{msg: "throttled: HTTP 429"}
	if !isThrottleError(err) {
		t.Error("isThrottleError() should return true for *throttleError")
	}
}

func TestIsThrottleError_False(t *testing.T) {
	err := fmt.Errorf("some other error")
	if isThrottleError(err) {
		t.Error("isThrottleError() should return false for non-throttle errors")
	}
}

func TestIAMObserver_ID(t *testing.T) {
	c := &IAMObserver{}
	if got := c.ID(); got != "aws.iam" {
		t.Errorf("ID() = %q, want %q", got, "aws.iam")
	}
}

func TestIAMObserver_Name(t *testing.T) {
	c := &IAMObserver{}
	if got := c.Name(); got != "AWS IAM Observer" {
		t.Errorf("Name() = %q, want %q", got, "AWS IAM Observer")
	}
}

func TestIAMObserver_ImplementsInterface(t *testing.T) {
	var _ module.Observer = (*IAMObserver)(nil)
}

func TestIAMObserver_CredentialRequirements(t *testing.T) {
	c := &IAMObserver{}
	reqs := c.CredentialRequirements()
	if len(reqs) != 4 {
		t.Fatalf("CredentialRequirements() returned %d reqs, want 4", len(reqs))
	}
	names := make(map[string]bool)
	for _, r := range reqs {
		names[r.Name] = true
	}
	for _, name := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_REGION"} {
		if !names[name] {
			t.Errorf("missing credential requirement %q", name)
		}
	}
}
```

---

## File 4: `/mnt/c/users/justi/code/ocean/modules/observers/github/observer_test.go`

**Target: ~100 lines**

The GitHub observer's `newClient` accepts `GITHUB_API_URL` in config. We CAN test Observe with httptest.

Tests:
- `TestNewClient_MissingToken`
- `TestNewClient_DefaultBaseURL`
- `TestNewClient_CustomBaseURL`
- `TestBranchProtectionObserver_ID`
- `TestBranchProtectionObserver_Name`
- `TestBranchProtectionObserver_Version`
- `TestBranchProtectionObserver_ImplementsInterface`
- `TestBranchProtectionObserver_CredentialRequirements`
- `TestBranchProtectionObserver_Collect_Protected` -- httptest returns 200 with full protection JSON
- `TestBranchProtectionObserver_Collect_NoProtection` -- httptest returns 404

```go
package github

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/grcengineering/ocean/internal/evidence"
	"github.com/grcengineering/ocean/internal/module"
)

func TestNewClient_MissingToken(t *testing.T) {
	_, err := newClient(map[string]string{})
	if err == nil {
		t.Fatal("newClient() should return error when GITHUB_TOKEN is missing")
	}
}

func TestNewClient_DefaultBaseURL(t *testing.T) {
	c, err := newClient(map[string]string{"GITHUB_TOKEN": "ghp_test"})
	if err != nil {
		t.Fatalf("newClient() returned error: %v", err)
	}
	if c.baseURL != "https://api.github.com" {
		t.Errorf("baseURL = %q, want %q", c.baseURL, "https://api.github.com")
	}
}

func TestNewClient_CustomBaseURL(t *testing.T) {
	c, err := newClient(map[string]string{
		"GITHUB_TOKEN":   "ghp_test",
		"GITHUB_API_URL": "https://github.example.com/api/v3",
	})
	if err != nil {
		t.Fatalf("newClient() returned error: %v", err)
	}
	if c.baseURL != "https://github.example.com/api/v3" {
		t.Errorf("baseURL = %q, want %q", c.baseURL, "https://github.example.com/api/v3")
	}
}

func TestBranchProtectionObserver_ID(t *testing.T) {
	c := &BranchProtectionObserver{}
	if got := c.ID(); got != "github.branch_protection" {
		t.Errorf("ID() = %q, want %q", got, "github.branch_protection")
	}
}

func TestBranchProtectionObserver_Name(t *testing.T) {
	c := &BranchProtectionObserver{}
	if got := c.Name(); got != "GitHub Branch Protection Observer" {
		t.Errorf("Name() = %q, want %q", got, "GitHub Branch Protection Observer")
	}
}

func TestBranchProtectionObserver_Version(t *testing.T) {
	c := &BranchProtectionObserver{}
	if got := c.Version(); got != "0.1.0" {
		t.Errorf("Version() = %q, want %q", got, "0.1.0")
	}
}

func TestBranchProtectionObserver_ImplementsInterface(t *testing.T) {
	var _ module.Observer = (*BranchProtectionObserver)(nil)
}

func TestBranchProtectionObserver_CredentialRequirements(t *testing.T) {
	c := &BranchProtectionObserver{}
	reqs := c.CredentialRequirements()
	if len(reqs) != 4 {
		t.Fatalf("CredentialRequirements() returned %d reqs, want 4", len(reqs))
	}
	names := make(map[string]bool)
	for _, r := range reqs {
		names[r.Name] = true
	}
	for _, name := range []string{"GITHUB_TOKEN", "GITHUB_OWNER", "GITHUB_REPO", "GITHUB_BRANCH"} {
		if !names[name] {
			t.Errorf("missing credential requirement %q", name)
		}
	}
}

func TestBranchProtectionObserver_Collect_Protected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "100")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"url": "https://api.github.com/repos/test/repo/branches/main/protection",
			"required_pull_request_reviews": {"dismiss_stale_reviews": true, "require_code_owner_reviews": true, "required_approving_review_count": 2},
			"required_status_checks": {"strict": true, "contexts": ["ci/build"]},
			"enforce_admins": {"enabled": true},
			"allow_force_pushes": {"enabled": false},
			"allow_deletions": {"enabled": false}
		}`))
	}))
	defer server.Close()

	c := &BranchProtectionObserver{}
	config := map[string]string{
		"GITHUB_TOKEN":   "ghp_test",
		"GITHUB_API_URL": server.URL,
		"GITHUB_OWNER":   "test",
		"GITHUB_REPO":    "repo",
	}

	results, err := c.Observe(context.Background(), config)
	if err != nil {
		t.Fatalf("Observe() returned error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Observe() returned %d results, want 1", len(results))
	}
	if results[0].StatusID != evidence.StatusEffective {
		t.Errorf("StatusID = %d, want %d (effective)", results[0].StatusID, evidence.StatusEffective)
	}
}

func TestBranchProtectionObserver_Collect_NoProtection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "100")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message": "Branch not protected"}`))
	}))
	defer server.Close()

	c := &BranchProtectionObserver{}
	config := map[string]string{
		"GITHUB_TOKEN":   "ghp_test",
		"GITHUB_API_URL": server.URL,
		"GITHUB_OWNER":   "test",
		"GITHUB_REPO":    "repo",
	}

	results, err := c.Observe(context.Background(), config)
	if err != nil {
		t.Fatalf("Observe() returned error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Observe() returned %d results, want 1", len(results))
	}
	if results[0].StatusID != evidence.StatusIneffective {
		t.Errorf("StatusID = %d, want %d (ineffective)", results[0].StatusID, evidence.StatusIneffective)
	}
}
```

---

## File 5: `/mnt/c/users/justi/code/ocean/modules/testers/aws/public_access_test.go`

**Target: ~90 lines**

The PublicAccessTester reads `config["AWS_TEST_BUCKET"]` and makes an unauthenticated HTTP GET to that URL. We CAN point it at httptest.

Tests:
- `TestPublicAccessTester_ID`
- `TestPublicAccessTester_Name`
- `TestPublicAccessTester_SafetyClass` -- SafetyClassSafe
- `TestPublicAccessTester_EnvironmentScope` -- ScopeProduction
- `TestPublicAccessTester_ImplementsInterface`
- `TestPublicAccessTester_CredentialRequirements`
- `TestPublicAccessTester_Test_MissingBucket`
- `TestPublicAccessTester_Test_Blocked_403` -- httptest returns 403, expect StatusEffective
- `TestPublicAccessTester_Test_Public_200` -- httptest returns 200, expect StatusIneffective

```go
package aws

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/grcengineering/ocean/internal/evidence"
	"github.com/grcengineering/ocean/internal/module"
)

func TestPublicAccessTester_ID(t *testing.T) {
	tester := &PublicAccessTester{}
	if got := tester.ID(); got != "aws.s3_public_access" {
		t.Errorf("ID() = %q, want %q", got, "aws.s3_public_access")
	}
}

func TestPublicAccessTester_Name(t *testing.T) {
	tester := &PublicAccessTester{}
	if got := tester.Name(); got != "AWS S3 Public Access Tester" {
		t.Errorf("Name() = %q, want %q", got, "AWS S3 Public Access Tester")
	}
}

func TestPublicAccessTester_SafetyClass(t *testing.T) {
	tester := &PublicAccessTester{}
	if got := tester.SafetyClass(); got != module.SafetyClassSafe {
		t.Errorf("SafetyClass() = %q, want %q", got, module.SafetyClassSafe)
	}
}

func TestPublicAccessTester_EnvironmentScope(t *testing.T) {
	tester := &PublicAccessTester{}
	if got := tester.EnvironmentScope(); got != module.ScopeProduction {
		t.Errorf("EnvironmentScope() = %q, want %q", got, module.ScopeProduction)
	}
}

func TestPublicAccessTester_ImplementsInterface(t *testing.T) {
	var _ module.Tester = (*PublicAccessTester)(nil)
}

func TestPublicAccessTester_CredentialRequirements(t *testing.T) {
	tester := &PublicAccessTester{}
	reqs := tester.CredentialRequirements()
	if len(reqs) != 1 {
		t.Fatalf("CredentialRequirements() returned %d reqs, want 1", len(reqs))
	}
	if reqs[0].Name != "AWS_TEST_BUCKET" {
		t.Errorf("first credential name = %q, want %q", reqs[0].Name, "AWS_TEST_BUCKET")
	}
}

func TestPublicAccessTester_Test_MissingBucket(t *testing.T) {
	tester := &PublicAccessTester{}
	_, err := tester.Test(context.Background(), map[string]string{})
	if err == nil {
		t.Fatal("Test() should return error when AWS_TEST_BUCKET is missing")
	}
}

func TestPublicAccessTester_Test_Blocked_403(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("AccessDenied"))
	}))
	defer server.Close()

	tester := &PublicAccessTester{}
	config := map[string]string{
		"AWS_TEST_BUCKET": server.URL,
	}

	results, err := tester.Test(context.Background(), config)
	if err != nil {
		t.Fatalf("Test() returned error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Test() returned %d results, want 1", len(results))
	}
	if results[0].StatusID != evidence.StatusEffective {
		t.Errorf("StatusID = %d, want %d (effective -- access blocked)", results[0].StatusID, evidence.StatusEffective)
	}
}

func TestPublicAccessTester_Test_Public_200(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<ListBucketResult>...</ListBucketResult>"))
	}))
	defer server.Close()

	tester := &PublicAccessTester{}
	config := map[string]string{
		"AWS_TEST_BUCKET": server.URL,
	}

	results, err := tester.Test(context.Background(), config)
	if err != nil {
		t.Fatalf("Test() returned error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Test() returned %d results, want 1", len(results))
	}
	if results[0].StatusID != evidence.StatusIneffective {
		t.Errorf("StatusID = %d, want %d (ineffective -- publicly accessible)", results[0].StatusID, evidence.StatusIneffective)
	}
}
```

---

## File 6: `/mnt/c/users/justi/code/ocean/modules/testers/github/secret_push_test.go`

**Target: ~110 lines**

The `newGHClient` function accepts `GITHUB_API_URL` in config. We CAN test the full flow with httptest.

Tests:
- `TestSecretPushTester_ID`
- `TestSecretPushTester_Name`
- `TestSecretPushTester_SafetyClassification` -- SafetyClassObservable
- `TestSecretPushTester_EnvironmentScope` -- ScopeStaging
- `TestSecretPushTester_ImplementsInterface`
- `TestSecretPushTester_CredentialRequirements`
- `TestSecretPushTester_Test_MissingToken`
- `TestSecretPushTester_Test_MissingOwner`
- `TestSecretPushTester_Test_MissingRepo`
- `TestSecretPushTester_Test_Blocked_409` -- httptest returns 409, expect StatusEffective
- `TestSecretPushTester_Test_Blocked_422` -- httptest returns 422, expect StatusEffective
- `TestSecretPushTester_Test_NotBlocked_201` -- httptest returns 201 on PUT, 200 on DELETE (cleanup)

```go
package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/grcengineering/ocean/internal/evidence"
	"github.com/grcengineering/ocean/internal/module"
)

func TestSecretPushTester_ID(t *testing.T) {
	tester := &SecretPushTester{}
	if got := tester.ID(); got != "github.secret_push" {
		t.Errorf("ID() = %q, want %q", got, "github.secret_push")
	}
}

func TestSecretPushTester_Name(t *testing.T) {
	tester := &SecretPushTester{}
	if got := tester.Name(); got != "GitHub Secret Push Protection Test" {
		t.Errorf("Name() = %q, want %q", got, "GitHub Secret Push Protection Test")
	}
}

func TestSecretPushTester_SafetyClassification(t *testing.T) {
	tester := &SecretPushTester{}
	if got := tester.SafetyClass(); got != module.SafetyClassObservable {
		t.Errorf("SafetyClass() = %q, want %q", got, module.SafetyClassObservable)
	}
}

func TestSecretPushTester_EnvironmentScope(t *testing.T) {
	tester := &SecretPushTester{}
	if got := tester.EnvironmentScope(); got != module.ScopeStaging {
		t.Errorf("EnvironmentScope() = %q, want %q", got, module.ScopeStaging)
	}
}

func TestSecretPushTester_ImplementsInterface(t *testing.T) {
	var _ module.Tester = (*SecretPushTester)(nil)
}

func TestSecretPushTester_CredentialRequirements(t *testing.T) {
	tester := &SecretPushTester{}
	reqs := tester.CredentialRequirements()
	if len(reqs) != 3 {
		t.Fatalf("CredentialRequirements() returned %d reqs, want 3", len(reqs))
	}
	names := make(map[string]bool)
	for _, r := range reqs {
		names[r.Name] = true
	}
	for _, name := range []string{"GITHUB_TOKEN", "GITHUB_OWNER", "GITHUB_REPO"} {
		if !names[name] {
			t.Errorf("missing credential requirement %q", name)
		}
	}
}

func TestSecretPushTester_Test_MissingToken(t *testing.T) {
	tester := &SecretPushTester{}
	_, err := tester.Test(context.Background(), map[string]string{
		"GITHUB_OWNER": "test",
		"GITHUB_REPO":  "repo",
	})
	if err == nil {
		t.Fatal("Test() should return error when GITHUB_TOKEN is missing")
	}
}

func TestSecretPushTester_Test_MissingOwner(t *testing.T) {
	tester := &SecretPushTester{}
	_, err := tester.Test(context.Background(), map[string]string{
		"GITHUB_TOKEN": "ghp_test",
		"GITHUB_REPO":  "repo",
	})
	if err == nil {
		t.Fatal("Test() should return error when GITHUB_OWNER is missing")
	}
}

func TestSecretPushTester_Test_MissingRepo(t *testing.T) {
	tester := &SecretPushTester{}
	_, err := tester.Test(context.Background(), map[string]string{
		"GITHUB_TOKEN": "ghp_test",
		"GITHUB_OWNER": "test",
	})
	if err == nil {
		t.Fatal("Test() should return error when GITHUB_REPO is missing")
	}
}

func TestSecretPushTester_Test_Blocked_409(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "100")
		w.WriteHeader(http.StatusConflict)
		w.Write([]byte(`{"message":"Push protection blocked"}`))
	}))
	defer server.Close()

	tester := &SecretPushTester{}
	config := map[string]string{
		"GITHUB_TOKEN":   "ghp_test",
		"GITHUB_API_URL": server.URL,
		"GITHUB_OWNER":   "test",
		"GITHUB_REPO":    "repo",
	}

	results, err := tester.Test(context.Background(), config)
	if err != nil {
		t.Fatalf("Test() returned error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Test() returned %d results, want 1", len(results))
	}
	if results[0].StatusID != evidence.StatusEffective {
		t.Errorf("StatusID = %d, want %d (effective -- push blocked)", results[0].StatusID, evidence.StatusEffective)
	}
}

func TestSecretPushTester_Test_Blocked_422(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "100")
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Write([]byte(`{"message":"Validation failed"}`))
	}))
	defer server.Close()

	tester := &SecretPushTester{}
	config := map[string]string{
		"GITHUB_TOKEN":   "ghp_test",
		"GITHUB_API_URL": server.URL,
		"GITHUB_OWNER":   "test",
		"GITHUB_REPO":    "repo",
	}

	results, err := tester.Test(context.Background(), config)
	if err != nil {
		t.Fatalf("Test() returned error: %v", err)
	}
	if results[0].StatusID != evidence.StatusEffective {
		t.Errorf("StatusID = %d, want %d (effective -- push blocked)", results[0].StatusID, evidence.StatusEffective)
	}
}

func TestSecretPushTester_Test_NotBlocked_201(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "100")
		if r.Method == http.MethodPut {
			resp := contentsResponse{}
			resp.Content.SHA = "abc123"
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(resp)
		} else if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	tester := &SecretPushTester{}
	config := map[string]string{
		"GITHUB_TOKEN":   "ghp_test",
		"GITHUB_API_URL": server.URL,
		"GITHUB_OWNER":   "test",
		"GITHUB_REPO":    "repo",
	}

	results, err := tester.Test(context.Background(), config)
	if err != nil {
		t.Fatalf("Test() returned error: %v", err)
	}
	if results[0].StatusID != evidence.StatusIneffective {
		t.Errorf("StatusID = %d, want %d (ineffective -- push not blocked)", results[0].StatusID, evidence.StatusIneffective)
	}
}
```

---

## File 7: `/mnt/c/users/justi/code/ocean/pkg/schema/evidence_test.go`

**Target: ~40 lines**

Tests:
- `TestStatusID_Constants` -- verify StatusUnknown=0, StatusEffective=1, StatusIneffective=2, StatusOther=99
- `TestConfidenceLevel_Constants` -- verify PassiveObservation, ActiveVerification values
- `TestEvidence_JSONRoundTrip` -- marshal/unmarshal Evidence, verify fields survive
- `TestControlStatus_JSONRoundTrip` -- marshal/unmarshal ControlStatus, verify fields survive

```go
package schema

import (
	"encoding/json"
	"testing"
	"time"
)

func TestStatusID_Constants(t *testing.T) {
	if StatusUnknown != 0 {
		t.Errorf("StatusUnknown = %d, want 0", StatusUnknown)
	}
	if StatusEffective != 1 {
		t.Errorf("StatusEffective = %d, want 1", StatusEffective)
	}
	if StatusIneffective != 2 {
		t.Errorf("StatusIneffective = %d, want 2", StatusIneffective)
	}
	if StatusOther != 99 {
		t.Errorf("StatusOther = %d, want 99", StatusOther)
	}
}

func TestConfidenceLevel_Constants(t *testing.T) {
	if PassiveObservation != "passive_observation" {
		t.Errorf("PassiveObservation = %q, want %q", PassiveObservation, "passive_observation")
	}
	if ActiveVerification != "active_verification" {
		t.Errorf("ActiveVerification = %q, want %q", ActiveVerification, "active_verification")
	}
}

func TestEvidence_JSONRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	ev := Evidence{
		ID:              "test-id-001",
		ControlID:       "mfa.enforcement",
		ClassUID:        1001,
		CategoryUID:     1,
		ActivityID:      1,
		Time:            now,
		ConfidenceLevel: PassiveObservation,
		StatusID:        StatusEffective,
		Status:          "All checks passed",
		RawData:         json.RawMessage(`{"key":"value"}`),
	}

	data, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("Marshal() returned error: %v", err)
	}

	var decoded Evidence
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal() returned error: %v", err)
	}

	if decoded.ID != ev.ID {
		t.Errorf("ID = %q, want %q", decoded.ID, ev.ID)
	}
	if decoded.ControlID != ev.ControlID {
		t.Errorf("ControlID = %q, want %q", decoded.ControlID, ev.ControlID)
	}
	if decoded.StatusID != ev.StatusID {
		t.Errorf("StatusID = %d, want %d", decoded.StatusID, ev.StatusID)
	}
	if decoded.ConfidenceLevel != ev.ConfidenceLevel {
		t.Errorf("ConfidenceLevel = %q, want %q", decoded.ConfidenceLevel, ev.ConfidenceLevel)
	}
}

func TestControlStatus_JSONRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	cs := ControlStatus{
		ID:                "cs-001",
		ControlID:         "mfa.enforcement",
		Timestamp:         now,
		Status:            "effective",
		Confidence:        "high",
		EvidenceIDs:       []string{"ev-1", "ev-2"},
		EvaluationDetails: "All evidence supports effectiveness",
	}

	data, err := json.Marshal(cs)
	if err != nil {
		t.Fatalf("Marshal() returned error: %v", err)
	}

	var decoded ControlStatus
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal() returned error: %v", err)
	}

	if decoded.ControlID != cs.ControlID {
		t.Errorf("ControlID = %q, want %q", decoded.ControlID, cs.ControlID)
	}
	if len(decoded.EvidenceIDs) != 2 {
		t.Errorf("EvidenceIDs length = %d, want 2", len(decoded.EvidenceIDs))
	}
}
```

---

## File 8: `/mnt/c/users/justi/code/ocean/pkg/ocean/client_test.go`

**Target: ~80 lines**

NewClient uses real SQLite via sqlitestore.Open. We use `t.TempDir()` for the database path.

Tests:
- `TestNewClient_WithTempDir` -- create client with TempDir StoragePath, verify no error
- `TestClient_Registry_NotNil` -- client.Registry() returns non-nil
- `TestClient_Close` -- close works without error
- `TestClient_Collect_UnknownModule` -- Observe with unknown module returns error
- `TestClient_Evaluate_UnknownControl` -- Evaluate with unknown control returns error

```go
package ocean

import (
	"context"
	"path/filepath"
	"testing"
)

func TestNewClient_WithTempDir(t *testing.T) {
	dir := t.TempDir()
	client, err := NewClient(Config{
		StoragePath: filepath.Join(dir, "test.db"),
	})
	if err != nil {
		t.Fatalf("NewClient() returned error: %v", err)
	}
	defer client.Close()
}

func TestClient_Registry_NotNil(t *testing.T) {
	dir := t.TempDir()
	client, err := NewClient(Config{
		StoragePath: filepath.Join(dir, "test.db"),
	})
	if err != nil {
		t.Fatalf("NewClient() returned error: %v", err)
	}
	defer client.Close()

	if client.Registry() == nil {
		t.Error("Registry() should not return nil")
	}
}

func TestClient_Close(t *testing.T) {
	dir := t.TempDir()
	client, err := NewClient(Config{
		StoragePath: filepath.Join(dir, "test.db"),
	})
	if err != nil {
		t.Fatalf("NewClient() returned error: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
}

func TestClient_Collect_UnknownModule(t *testing.T) {
	dir := t.TempDir()
	client, err := NewClient(Config{
		StoragePath: filepath.Join(dir, "test.db"),
	})
	if err != nil {
		t.Fatalf("NewClient() returned error: %v", err)
	}
	defer client.Close()

	_, err = client.Observe(context.Background(), "nonexistent.module", nil)
	if err == nil {
		t.Fatal("Observe() should return error for unknown module")
	}
}

func TestClient_Evaluate_UnknownControl(t *testing.T) {
	dir := t.TempDir()
	client, err := NewClient(Config{
		StoragePath: filepath.Join(dir, "test.db"),
	})
	if err != nil {
		t.Fatalf("NewClient() returned error: %v", err)
	}
	defer client.Close()

	_, err = client.Evaluate(context.Background(), "nonexistent.control")
	if err == nil {
		t.Fatal("Evaluate() should return error for unknown control")
	}
}
```

---

## Execution Order

1. Create all 8 files (no dependencies between them).
2. Run `go test ./...` from the project root to validate all compile and pass.
3. If any fail, fix and re-run.

## Key Design Decisions

- **No testify**: Match the dominant pattern of neighboring test files (27 of 32 use stdlib only).
- **httptest.NewServer for all HTTP**: GitHub observer, GitHub tester, AWS S3 tester all pointed at httptest. AWS IAM observer cannot be tested via httptest due to constant endpoint, so only utility functions are tested.
- **t.TempDir() for all files/DB**: config loader and ocean client tests.
- **t.Setenv() for environment variable tests**: config loader env override test.
- **Approximately 690 lines total** across 8 files.
