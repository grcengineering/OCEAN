package control

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/grcengineering/ocean/internal/evidence"
	"github.com/grcengineering/ocean/internal/module"
)

// --- inline mock collector for verifier tests ---

type mockCollector struct {
	id     string
	status evidence.StatusID
}

var _ module.Collector = (*mockCollector)(nil)

func (m *mockCollector) ID() string            { return m.id }
func (m *mockCollector) Name() string          { return "Mock Collector" }
func (m *mockCollector) Version() string       { return "0.1.0" }
func (m *mockCollector) SourceSystem() string  { return "mock" }
func (m *mockCollector) EvidenceTypes() []int  { return []int{1001} }
func (m *mockCollector) CredentialRequirements() []module.CredentialReq { return nil }

func (m *mockCollector) Collect(_ context.Context, _ map[string]string) ([]evidence.Evidence, error) {
	rawData, _ := json.Marshal(map[string]string{"mock": "data"})
	return []evidence.Evidence{
		{
			ID:              uuid.New(),
			ControlID:       "mock.mfa_enforcement",
			ClassUID:        1001,
			CategoryUID:     1,
			ActivityID:      1,
			Time:            time.Now().UTC(),
			ConfidenceLevel: evidence.PassiveObservation,
			StatusID:        m.status,
			Status:          "mock passive evidence",
			RawData:         rawData,
			Metadata: evidence.Metadata{
				Module:        evidence.ModuleInfo{Name: m.id, Version: "0.1.0", Type: "collector"},
				Source:        evidence.SourceInfo{System: "mock", APIVersion: "v1", Endpoint: "/mock"},
				ProcessedTime: time.Now().UTC(),
			},
		},
	}, nil
}

// --- inline mock tester for verifier tests ---

type mockTester struct {
	id     string
	status evidence.StatusID
}

var _ module.Tester = (*mockTester)(nil)

func (m *mockTester) ID() string            { return m.id }
func (m *mockTester) Name() string          { return "Mock Tester" }
func (m *mockTester) Version() string       { return "0.1.0" }
func (m *mockTester) SourceSystem() string  { return "mock" }
func (m *mockTester) EvidenceTypes() []int  { return []int{1001} }
func (m *mockTester) CredentialRequirements() []module.CredentialReq { return nil }
func (m *mockTester) SafetyClass() module.SafetyClassification      { return module.SafetyClassSafe }
func (m *mockTester) EnvironmentScope() module.EnvironmentScope      { return module.ScopeIsolated }
func (m *mockTester) PreFlightChecks() []string                      { return nil }
func (m *mockTester) CleanupProcedures() []string                    { return nil }

func (m *mockTester) Test(_ context.Context, _ map[string]string) ([]evidence.Evidence, error) {
	rawData, _ := json.Marshal(map[string]string{"mock": "test_data"})
	return []evidence.Evidence{
		{
			ID:              uuid.New(),
			ControlID:       "mock.mfa_enforcement",
			ClassUID:        1001,
			CategoryUID:     1,
			ActivityID:      2,
			Time:            time.Now().UTC(),
			ConfidenceLevel: evidence.ActiveVerification,
			StatusID:        m.status,
			Status:          "mock active evidence",
			RawData:         rawData,
			Metadata: evidence.Metadata{
				Module:        evidence.ModuleInfo{Name: m.id, Version: "0.1.0", Type: "tester"},
				Source:        evidence.SourceInfo{System: "mock", APIVersion: "v1", Endpoint: "/mock/test"},
				ProcessedTime: time.Now().UTC(),
			},
		},
	}, nil
}

func TestVerifyControl_WithBothModes(t *testing.T) {
	reg := module.NewRegistry()
	reg.RegisterCollector(&mockCollector{id: "mock.test", status: evidence.StatusEffective})
	reg.RegisterTester(&mockTester{id: "mock.safety_test", status: evidence.StatusEffective})

	exec := module.NewExecutor(reg)
	verifier := NewVerifier(reg, exec)

	ctrl := &Control{
		ID:   "mock.mfa_enforcement",
		Name: "MFA Enforcement",
		Collectors: []ModuleRef{{ModuleID: "mock.test"}},
		Testers:    []ModuleRef{{ModuleID: "mock.safety_test"}},
	}

	result, err := verifier.VerifyControl(context.Background(), ctrl)
	if err != nil {
		t.Fatalf("VerifyControl error: %v", err)
	}

	if result.Control.ID != "mock.mfa_enforcement" {
		t.Errorf("Control.ID = %q, want %q", result.Control.ID, "mock.mfa_enforcement")
	}

	if result.Status.Status != "effective" {
		t.Errorf("Status = %q, want %q", result.Status.Status, "effective")
	}

	if result.Status.Confidence != "high" {
		t.Errorf("Confidence = %q, want %q", result.Status.Confidence, "high")
	}

	// Should have 2 evidence records (1 passive + 1 active).
	if len(result.Evidences) != 2 {
		t.Errorf("Evidences len = %d, want 2", len(result.Evidences))
	}

	if len(result.SkippedTests) != 0 {
		t.Errorf("SkippedTests = %v, want empty", result.SkippedTests)
	}
}

func TestVerifyControl_CollectorOnly(t *testing.T) {
	reg := module.NewRegistry()
	reg.RegisterCollector(&mockCollector{id: "mock.test", status: evidence.StatusEffective})
	// No tester registered.

	exec := module.NewExecutor(reg)
	verifier := NewVerifier(reg, exec)

	ctrl := &Control{
		ID:         "mock.mfa_enforcement",
		Name:       "MFA Enforcement",
		Collectors: []ModuleRef{{ModuleID: "mock.test"}},
		// No testers defined in control.
	}

	result, err := verifier.VerifyControl(context.Background(), ctrl)
	if err != nil {
		t.Fatalf("VerifyControl error: %v", err)
	}

	if result.Status.Status != "effective" {
		t.Errorf("Status = %q, want %q", result.Status.Status, "effective")
	}

	// Only passive evidence, so confidence should be medium.
	if result.Status.Confidence != "medium" {
		t.Errorf("Confidence = %q, want %q", result.Status.Confidence, "medium")
	}

	if len(result.Evidences) != 1 {
		t.Errorf("Evidences len = %d, want 1", len(result.Evidences))
	}
}

func TestVerifyControl_SkippedTest(t *testing.T) {
	reg := module.NewRegistry()
	reg.RegisterCollector(&mockCollector{id: "mock.test", status: evidence.StatusEffective})
	// Register one tester but reference a second one that does not exist.
	reg.RegisterTester(&mockTester{id: "mock.safety_test", status: evidence.StatusEffective})

	exec := module.NewExecutor(reg)
	verifier := NewVerifier(reg, exec)

	ctrl := &Control{
		ID:   "mock.mfa_enforcement",
		Name: "MFA Enforcement",
		Collectors: []ModuleRef{{ModuleID: "mock.test"}},
		Testers: []ModuleRef{
			{ModuleID: "mock.safety_test"},
			{ModuleID: "mock.nonexistent_tester"}, // This one should be skipped.
		},
	}

	result, err := verifier.VerifyControl(context.Background(), ctrl)
	if err != nil {
		t.Fatalf("VerifyControl error: %v", err)
	}

	// Should still evaluate successfully.
	if result.Status.Status != "effective" {
		t.Errorf("Status = %q, want %q", result.Status.Status, "effective")
	}

	// Should have skipped the nonexistent tester.
	if len(result.SkippedTests) != 1 {
		t.Fatalf("SkippedTests len = %d, want 1", len(result.SkippedTests))
	}
	if result.SkippedTests[0] != "mock.nonexistent_tester" {
		t.Errorf("SkippedTests[0] = %q, want %q", result.SkippedTests[0], "mock.nonexistent_tester")
	}

	// Should have 2 evidence records (1 passive + 1 from the available tester).
	if len(result.Evidences) != 2 {
		t.Errorf("Evidences len = %d, want 2", len(result.Evidences))
	}
}

func TestVerifyControl_CompositeMultipleSources(t *testing.T) {
	reg := module.NewRegistry()
	reg.RegisterCollector(&mockCollector{id: "mock.test", status: evidence.StatusEffective})
	reg.RegisterCollector(&mockCollector{id: "mock.network", status: evidence.StatusEffective})
	reg.RegisterTester(&mockTester{id: "mock.safety_test", status: evidence.StatusEffective})

	exec := module.NewExecutor(reg)
	verifier := NewVerifier(reg, exec)

	ctrl := &Control{
		ID:   "mock.waf_protection",
		Name: "WAF Protection Composite",
		Collectors: []ModuleRef{
			{ModuleID: "mock.test"},
			{ModuleID: "mock.network"},
		},
		Testers: []ModuleRef{
			{ModuleID: "mock.safety_test"},
		},
		EvaluationLogic: EvaluationLogic{
			CELExpression: "status_counts.effective > 0 && status_counts.ineffective == 0",
		},
	}

	result, err := verifier.VerifyControl(context.Background(), ctrl)
	if err != nil {
		t.Fatalf("VerifyControl error: %v", err)
	}

	if result.Status.Status != "effective" {
		t.Errorf("Status = %q, want %q", result.Status.Status, "effective")
	}

	// Should have 3 evidence records (2 passive + 1 active).
	if len(result.Evidences) != 3 {
		t.Errorf("Evidences len = %d, want 3", len(result.Evidences))
	}

	// Evaluation details should contain per-component breakdown.
	details := result.Status.EvaluationDetails
	if details == "" {
		t.Error("expected non-empty evaluation details")
	}

	// Should mention all three modules.
	for _, name := range []string{"mock.test", "mock.network", "mock.safety_test"} {
		if !containsString(details, name) {
			t.Errorf("evaluation details should mention %q, got: %s", name, details)
		}
	}
}

func TestVerifyControl_CompositePartialFailure(t *testing.T) {
	reg := module.NewRegistry()
	reg.RegisterCollector(&mockCollector{id: "mock.test", status: evidence.StatusEffective})
	// mock.network NOT registered - should be skipped.
	reg.RegisterTester(&mockTester{id: "mock.safety_test", status: evidence.StatusEffective})

	exec := module.NewExecutor(reg)
	verifier := NewVerifier(reg, exec)

	ctrl := &Control{
		ID:   "mock.waf_protection",
		Name: "WAF Protection Composite",
		Collectors: []ModuleRef{
			{ModuleID: "mock.test"},
			{ModuleID: "mock.network"},
		},
		Testers: []ModuleRef{
			{ModuleID: "mock.safety_test"},
		},
		EvaluationLogic: EvaluationLogic{
			CELExpression: "status_counts.effective > 0",
		},
	}

	result, err := verifier.VerifyControl(context.Background(), ctrl)
	if err != nil {
		t.Fatalf("VerifyControl error: %v", err)
	}

	// Should still evaluate as effective (at least one source succeeded).
	if result.Status.Status != "effective" {
		t.Errorf("Status = %q, want %q", result.Status.Status, "effective")
	}

	// mock.network should appear as a skipped collector.
	if len(result.SkippedTests) == 0 {
		t.Error("expected skipped tests for missing collector")
	}

	// Details should mention unavailable component.
	if !containsString(result.Status.EvaluationDetails, "unavailable") {
		t.Errorf("evaluation details should mention unavailable component, got: %s", result.Status.EvaluationDetails)
	}
}

func TestVerifyControl_NoCollectors(t *testing.T) {
	reg := module.NewRegistry()
	exec := module.NewExecutor(reg)
	verifier := NewVerifier(reg, exec)

	ctrl := &Control{
		ID:   "mock.empty",
		Name: "Empty Control",
		// No collectors or testers.
	}

	result, err := verifier.VerifyControl(context.Background(), ctrl)
	if err != nil {
		t.Fatalf("VerifyControl error: %v", err)
	}

	if result.Status.Status != "unknown" {
		t.Errorf("Status = %q, want %q", result.Status.Status, "unknown")
	}
	if result.Status.Confidence != "low" {
		t.Errorf("Confidence = %q, want %q", result.Status.Confidence, "low")
	}
}
