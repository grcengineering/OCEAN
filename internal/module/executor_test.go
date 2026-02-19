package module

import (
	"context"
	"fmt"
	"testing"

	"github.com/grcengineering/ocean/internal/evidence"
)

// fakeCollector is a minimal Collector for testing the executor.
type fakeCollector struct {
	id      string
	results []evidence.Evidence
	err     error
}

func (f *fakeCollector) ID() string                             { return f.id }
func (f *fakeCollector) Name() string                           { return "Fake" }
func (f *fakeCollector) Version() string                        { return "0.0.1" }
func (f *fakeCollector) SourceSystem() string                   { return "fake" }
func (f *fakeCollector) EvidenceTypes() []int                   { return []int{9999} }
func (f *fakeCollector) CredentialRequirements() []CredentialReq { return nil }

func (f *fakeCollector) Collect(_ context.Context, _ map[string]string) ([]evidence.Evidence, error) {
	return f.results, f.err
}

func TestExecuteCollector_Success(t *testing.T) {
	reg := NewRegistry()
	fc := &fakeCollector{id: "fake.test", results: []evidence.Evidence{{}}}
	reg.RegisterCollector(fc)

	executor := NewExecutor(reg)
	results, err := executor.ExecuteCollector(context.Background(), "fake.test", nil)
	if err != nil {
		t.Fatalf("ExecuteCollector returned error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("ExecuteCollector returned %d results, want 1", len(results))
	}
}

func TestExecuteCollector_NotFound(t *testing.T) {
	reg := NewRegistry()
	executor := NewExecutor(reg)

	_, err := executor.ExecuteCollector(context.Background(), "nonexistent", nil)
	if err == nil {
		t.Fatal("expected error for nonexistent module, got nil")
	}
}

func TestExecuteCollector_CollectorError(t *testing.T) {
	reg := NewRegistry()
	fc := &fakeCollector{id: "failing.test", err: fmt.Errorf("api error")}
	reg.RegisterCollector(fc)

	executor := NewExecutor(reg)
	_, err := executor.ExecuteCollector(context.Background(), "failing.test", nil)
	if err == nil {
		t.Fatal("expected error from failing collector, got nil")
	}
}

func TestExecuteCollector_PassesConfig(t *testing.T) {
	reg := NewRegistry()
	var receivedConfig map[string]string
	fc := &fakeCollector{id: "config.test"}
	// Override Collect to capture config
	origCollect := fc.Collect
	_ = origCollect // suppress unused warning

	// We'll use a configCapture collector instead
	cc := &configCaptureCollector{id: "config.test", capturedConfig: &receivedConfig}
	reg.RegisterCollector(cc)

	executor := NewExecutor(reg)
	config := map[string]string{"api_key": "test123"}
	_, err := executor.ExecuteCollector(context.Background(), "config.test", config)
	if err != nil {
		t.Fatalf("ExecuteCollector returned error: %v", err)
	}
	if receivedConfig == nil {
		t.Fatal("config was not passed to collector")
	}
	if receivedConfig["api_key"] != "test123" {
		t.Errorf("config[\"api_key\"] = %q, want %q", receivedConfig["api_key"], "test123")
	}
}

// configCaptureCollector captures the config passed to Collect.
type configCaptureCollector struct {
	id             string
	capturedConfig *map[string]string
}

func (c *configCaptureCollector) ID() string                             { return c.id }
func (c *configCaptureCollector) Name() string                           { return "ConfigCapture" }
func (c *configCaptureCollector) Version() string                        { return "0.0.1" }
func (c *configCaptureCollector) SourceSystem() string                   { return "fake" }
func (c *configCaptureCollector) EvidenceTypes() []int                   { return []int{9999} }
func (c *configCaptureCollector) CredentialRequirements() []CredentialReq { return nil }

func (c *configCaptureCollector) Collect(_ context.Context, config map[string]string) ([]evidence.Evidence, error) {
	*c.capturedConfig = config
	return nil, nil
}

// executorFakeTester is a configurable Tester for testing the executor pipeline.
// Named differently from fakeTester in safety_test.go to avoid redeclaration.
type executorFakeTester struct {
	id                string
	safetyClass       SafetyClassification
	environmentScope  EnvironmentScope
	preFlightChecks   []string
	cleanupProcedures []string
	results           []evidence.Evidence
	err               error
}

func (f *executorFakeTester) ID() string                             { return f.id }
func (f *executorFakeTester) Name() string                           { return "FakeTester" }
func (f *executorFakeTester) Version() string                        { return "0.0.1" }
func (f *executorFakeTester) SourceSystem() string                   { return "fake" }
func (f *executorFakeTester) EvidenceTypes() []int                   { return []int{9999} }
func (f *executorFakeTester) CredentialRequirements() []CredentialReq { return nil }
func (f *executorFakeTester) SafetyClass() SafetyClassification      { return f.safetyClass }
func (f *executorFakeTester) EnvironmentScope() EnvironmentScope     { return f.environmentScope }
func (f *executorFakeTester) PreFlightChecks() []string              { return f.preFlightChecks }
func (f *executorFakeTester) CleanupProcedures() []string            { return f.cleanupProcedures }

func (f *executorFakeTester) Test(_ context.Context, _ map[string]string) ([]evidence.Evidence, error) {
	return f.results, f.err
}

// --- Registry tests ---

func TestListCollectors(t *testing.T) {
	reg := NewRegistry()
	c1 := &fakeCollector{id: "col.one"}
	c2 := &fakeCollector{id: "col.two"}
	reg.RegisterCollector(c1)
	reg.RegisterCollector(c2)

	collectors := reg.ListCollectors()
	if len(collectors) != 2 {
		t.Fatalf("ListCollectors returned %d, want 2", len(collectors))
	}
	ids := map[string]bool{}
	for _, c := range collectors {
		ids[c.ID()] = true
	}
	if !ids["col.one"] || !ids["col.two"] {
		t.Errorf("ListCollectors missing expected IDs, got %v", ids)
	}
}

func TestListTesters(t *testing.T) {
	reg := NewRegistry()
	t1 := &executorFakeTester{id: "tst.one", safetyClass: SafetyClassSafe, environmentScope: ScopeProduction}
	t2 := &executorFakeTester{id: "tst.two", safetyClass: SafetyClassSafe, environmentScope: ScopeProduction}
	reg.RegisterTester(t1)
	reg.RegisterTester(t2)

	testers := reg.ListTesters()
	if len(testers) != 2 {
		t.Fatalf("ListTesters returned %d, want 2", len(testers))
	}
	ids := map[string]bool{}
	for _, tr := range testers {
		ids[tr.ID()] = true
	}
	if !ids["tst.one"] || !ids["tst.two"] {
		t.Errorf("ListTesters missing expected IDs, got %v", ids)
	}
}

func TestListAll(t *testing.T) {
	reg := NewRegistry()
	c := &fakeCollector{id: "col.all"}
	tr := &executorFakeTester{id: "tst.all", safetyClass: SafetyClassSafe, environmentScope: ScopeProduction}
	reg.RegisterCollector(c)
	reg.RegisterTester(tr)

	all := reg.ListAll()
	if len(all) != 2 {
		t.Fatalf("ListAll returned %d, want 2", len(all))
	}
	ids := map[string]bool{}
	for _, m := range all {
		ids[m.ID()] = true
	}
	if !ids["col.all"] || !ids["tst.all"] {
		t.Errorf("ListAll missing expected IDs, got %v", ids)
	}
}

func TestGetModule_Collector(t *testing.T) {
	reg := NewRegistry()
	c := &fakeCollector{id: "col.get"}
	reg.RegisterCollector(c)

	m, err := reg.GetModule("col.get")
	if err != nil {
		t.Fatalf("GetModule returned error: %v", err)
	}
	if m.ID() != "col.get" {
		t.Errorf("GetModule ID = %q, want %q", m.ID(), "col.get")
	}
}

func TestGetModule_Tester(t *testing.T) {
	reg := NewRegistry()
	tr := &executorFakeTester{id: "tst.get", safetyClass: SafetyClassSafe, environmentScope: ScopeProduction}
	reg.RegisterTester(tr)

	m, err := reg.GetModule("tst.get")
	if err != nil {
		t.Fatalf("GetModule returned error: %v", err)
	}
	if m.ID() != "tst.get" {
		t.Errorf("GetModule ID = %q, want %q", m.ID(), "tst.get")
	}
}

func TestGetModule_NotFound(t *testing.T) {
	reg := NewRegistry()

	_, err := reg.GetModule("nonexistent.module")
	if err == nil {
		t.Fatal("expected error for nonexistent module, got nil")
	}
}

// --- Executor tester tests ---

func TestDefaultTestConfig(t *testing.T) {
	cfg := DefaultTestConfig()
	if cfg.TargetEnvironment != ScopeProduction {
		t.Errorf("DefaultTestConfig TargetEnvironment = %q, want %q", cfg.TargetEnvironment, ScopeProduction)
	}
	if cfg.Authorizer == nil {
		t.Fatal("DefaultTestConfig Authorizer is nil, want AutoAuthorizer")
	}
	// Verify it is an AutoAuthorizer by checking it auto-authorizes safe tests.
	authorized, err := cfg.Authorizer.Authorize("test", SafetyClassSafe, AuthLevelAuto)
	if err != nil {
		t.Fatalf("Authorizer.Authorize returned error: %v", err)
	}
	if !authorized {
		t.Error("AutoAuthorizer should authorize safe tests")
	}
}

func TestRunPreFlight_SafeTester(t *testing.T) {
	tester := &executorFakeTester{
		id:               "safe.test",
		safetyClass:      SafetyClassSafe,
		environmentScope: ScopeProduction,
	}
	cfg := TestConfig{
		TargetEnvironment: ScopeProduction,
		Authorizer:        &AutoAuthorizer{},
	}

	err := RunPreFlight(tester, cfg)
	if err != nil {
		t.Fatalf("RunPreFlight returned error for safe tester: %v", err)
	}
}

func TestRunCleanup(t *testing.T) {
	tester := &executorFakeTester{
		id:                "cleanup.test",
		safetyClass:       SafetyClassSafe,
		environmentScope:  ScopeProduction,
		cleanupProcedures: []string{"cleanup-step-1", "cleanup-step-2"},
	}

	cleanups := RunCleanup(tester)
	if len(cleanups) != 2 {
		t.Fatalf("RunCleanup returned %d records, want 2", len(cleanups))
	}
	if cleanups[0].Action != "cleanup-step-1" {
		t.Errorf("cleanup[0].Action = %q, want %q", cleanups[0].Action, "cleanup-step-1")
	}
	if cleanups[1].Action != "cleanup-step-2" {
		t.Errorf("cleanup[1].Action = %q, want %q", cleanups[1].Action, "cleanup-step-2")
	}
	if !cleanups[0].Success || !cleanups[1].Success {
		t.Error("expected all cleanup actions to report success")
	}
}

func TestExecuteTester_Success(t *testing.T) {
	reg := NewRegistry()
	ft := &executorFakeTester{
		id:                "safe.exec",
		safetyClass:       SafetyClassSafe,
		environmentScope:  ScopeProduction,
		cleanupProcedures: []string{"cleanup-step-1"},
		results:           []evidence.Evidence{{}},
	}
	reg.RegisterTester(ft)

	executor := NewExecutor(reg)
	results, err := executor.ExecuteTester(context.Background(), "safe.exec", nil)
	if err != nil {
		t.Fatalf("ExecuteTester returned error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("ExecuteTester returned %d results, want 1", len(results))
	}
	// Verify confidence level was set to active_verification.
	if results[0].ConfidenceLevel != evidence.ActiveVerification {
		t.Errorf("ConfidenceLevel = %q, want %q", results[0].ConfidenceLevel, evidence.ActiveVerification)
	}
	// Verify safety classification was set in metadata.
	if results[0].Metadata.SafetyClassification == nil {
		t.Fatal("SafetyClassification in metadata is nil")
	}
	if *results[0].Metadata.SafetyClassification != string(SafetyClassSafe) {
		t.Errorf("SafetyClassification = %q, want %q", *results[0].Metadata.SafetyClassification, SafetyClassSafe)
	}
	// Verify transcript includes cleanup actions.
	if results[0].TestTranscript == nil {
		t.Fatal("TestTranscript is nil")
	}
	if len(results[0].TestTranscript.CleanupActions) != 1 {
		t.Fatalf("CleanupActions count = %d, want 1", len(results[0].TestTranscript.CleanupActions))
	}
	if results[0].TestTranscript.CleanupActions[0].Action != "cleanup-step-1" {
		t.Errorf("CleanupActions[0].Action = %q, want %q", results[0].TestTranscript.CleanupActions[0].Action, "cleanup-step-1")
	}
}

func TestExecuteTester_NotFound(t *testing.T) {
	reg := NewRegistry()
	executor := NewExecutor(reg)

	_, err := executor.ExecuteTester(context.Background(), "nonexistent.tester", nil)
	if err == nil {
		t.Fatal("expected error for nonexistent tester, got nil")
	}
}

// --- Safety classification tests ---

func TestRequiresExplicitAuth(t *testing.T) {
	tests := []struct {
		class SafetyClassification
		want  bool
	}{
		{SafetyClassSafe, false},
		{SafetyClassObservable, true},
		{SafetyClassReversible, true},
		{SafetyClassDestructive, true},
	}
	for _, tc := range tests {
		got := tc.class.RequiresExplicitAuth()
		if got != tc.want {
			t.Errorf("SafetyClassification(%q).RequiresExplicitAuth() = %v, want %v", tc.class, got, tc.want)
		}
	}
}

func TestRequiresWarning(t *testing.T) {
	tests := []struct {
		class SafetyClassification
		want  bool
	}{
		{SafetyClassSafe, false},
		{SafetyClassObservable, false},
		{SafetyClassReversible, false},
		{SafetyClassDestructive, true},
	}
	for _, tc := range tests {
		got := tc.class.RequiresWarning()
		if got != tc.want {
			t.Errorf("SafetyClassification(%q).RequiresWarning() = %v, want %v", tc.class, got, tc.want)
		}
	}
}
