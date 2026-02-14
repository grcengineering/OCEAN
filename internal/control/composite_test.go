package control

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/grcengineering/ocean/internal/evidence"
)

// makeTestEvidence creates evidence with the given module name, status, and confidence level.
func makeTestEvidence(moduleName string, statusID evidence.StatusID, confidence evidence.ConfidenceLevel) evidence.Evidence {
	now := time.Now().UTC()
	rawData := map[string]interface{}{"test": true}
	rawJSON, _ := json.Marshal(rawData)

	status := "unknown"
	switch statusID {
	case evidence.StatusEffective:
		status = "effective"
	case evidence.StatusIneffective:
		status = "ineffective"
	}

	return evidence.Evidence{
		ID:              uuid.New(),
		ControlID:       "test.composite",
		ClassUID:        1001,
		CategoryUID:     1,
		ActivityID:      1,
		Time:            now,
		ConfidenceLevel: confidence,
		Metadata: evidence.Metadata{
			Module: evidence.ModuleInfo{
				Name:    moduleName,
				Version: "0.1.0",
				Type:    "collector",
			},
			Source: evidence.SourceInfo{
				System:     "mock",
				APIVersion: "v1",
				Endpoint:   "/api/v1/test",
			},
			ProcessedTime: now,
		},
		StatusID: statusID,
		Status:   status,
		RawData:  rawJSON,
	}
}

func TestCompositeEvaluateControl_MultipleSourcesAllEffective(t *testing.T) {
	ctrl := &Control{
		ID:   "test.composite",
		Name: "Test Composite Control",
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

	evidences := []evidence.Evidence{
		makeTestEvidence("mock.test", evidence.StatusEffective, evidence.PassiveObservation),
		makeTestEvidence("mock.network", evidence.StatusEffective, evidence.PassiveObservation),
		makeTestEvidence("mock.safety_test", evidence.StatusEffective, evidence.ActiveVerification),
	}

	cs, err := CompositeEvaluateControl(ctrl, evidences)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cs.Status != "effective" {
		t.Errorf("expected status 'effective', got %q", cs.Status)
	}

	if cs.ControlID != "test.composite" {
		t.Errorf("expected control_id 'test.composite', got %q", cs.ControlID)
	}

	// Evaluation details should mention per-component breakdown.
	if cs.EvaluationDetails == "" {
		t.Error("expected non-empty evaluation details")
	}
}

func TestCompositeEvaluateControl_MixedResults(t *testing.T) {
	ctrl := &Control{
		ID:   "test.composite",
		Name: "Test Composite Control",
		Collectors: []ModuleRef{
			{ModuleID: "mock.test"},
			{ModuleID: "mock.network"},
		},
		EvaluationLogic: EvaluationLogic{
			CELExpression: "status_counts.effective > 0 && status_counts.ineffective == 0",
		},
	}

	evidences := []evidence.Evidence{
		makeTestEvidence("mock.test", evidence.StatusEffective, evidence.PassiveObservation),
		makeTestEvidence("mock.network", evidence.StatusIneffective, evidence.PassiveObservation),
	}

	cs, err := CompositeEvaluateControl(ctrl, evidences)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cs.Status != "ineffective" {
		t.Errorf("expected status 'ineffective', got %q", cs.Status)
	}
}

func TestCompositeEvaluateControl_NoEvidence(t *testing.T) {
	ctrl := &Control{
		ID:   "test.composite",
		Name: "Test Composite Control",
		Collectors: []ModuleRef{
			{ModuleID: "mock.test"},
		},
		EvaluationLogic: EvaluationLogic{
			CELExpression: "status_counts.effective > 0",
		},
	}

	cs, err := CompositeEvaluateControl(ctrl, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cs.Status != "unknown" {
		t.Errorf("expected status 'unknown', got %q", cs.Status)
	}

	if cs.Confidence != "low" {
		t.Errorf("expected confidence 'low', got %q", cs.Confidence)
	}
}

func TestCompositeEvaluateControl_PerComponentBreakdown(t *testing.T) {
	ctrl := &Control{
		ID:   "test.composite",
		Name: "Test Composite",
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

	evidences := []evidence.Evidence{
		makeTestEvidence("mock.test", evidence.StatusEffective, evidence.PassiveObservation),
		makeTestEvidence("mock.network", evidence.StatusEffective, evidence.PassiveObservation),
		makeTestEvidence("mock.safety_test", evidence.StatusEffective, evidence.ActiveVerification),
	}

	cs, err := CompositeEvaluateControl(ctrl, evidences)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should contain per-component details for each module.
	details := cs.EvaluationDetails
	if details == "" {
		t.Fatal("expected non-empty evaluation details with per-component breakdown")
	}

	// Check that each module is mentioned in the details.
	for _, moduleName := range []string{"mock.test", "mock.network", "mock.safety_test"} {
		if !containsString(details, moduleName) {
			t.Errorf("evaluation details should mention module %q, got: %s", moduleName, details)
		}
	}
}

func TestCompositeEvaluateControl_PartialAvailability(t *testing.T) {
	// T107: If one source is missing evidence, mark that component as "unknown".
	ctrl := &Control{
		ID:   "test.composite",
		Name: "Test Composite",
		Collectors: []ModuleRef{
			{ModuleID: "mock.test"},
			{ModuleID: "mock.network"},
		},
		EvaluationLogic: EvaluationLogic{
			CELExpression: "status_counts.effective > 0",
		},
	}

	// Only provide evidence from mock.test, nothing from mock.network.
	evidences := []evidence.Evidence{
		makeTestEvidence("mock.test", evidence.StatusEffective, evidence.PassiveObservation),
	}

	cs, err := CompositeEvaluateControl(ctrl, evidences)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// CEL says effective > 0, so overall should be effective.
	if cs.Status != "effective" {
		t.Errorf("expected status 'effective', got %q", cs.Status)
	}

	// But details should note that mock.network is unavailable.
	if !containsString(cs.EvaluationDetails, "mock.network") {
		t.Errorf("evaluation details should mention unavailable component 'mock.network', got: %s", cs.EvaluationDetails)
	}
	if !containsString(cs.EvaluationDetails, "unavailable") {
		t.Errorf("evaluation details should contain 'unavailable' for missing source, got: %s", cs.EvaluationDetails)
	}
}

func TestCompositeEvaluateControl_PresetExpansion(t *testing.T) {
	ctrl := &Control{
		ID:   "test.composite",
		Name: "Test Composite",
		Collectors: []ModuleRef{
			{ModuleID: "mock.test"},
		},
		EvaluationLogic: EvaluationLogic{
			Preset: "all_effective",
		},
	}

	evidences := []evidence.Evidence{
		makeTestEvidence("mock.test", evidence.StatusEffective, evidence.PassiveObservation),
	}

	cs, err := CompositeEvaluateControl(ctrl, evidences)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cs.Status != "effective" {
		t.Errorf("expected status 'effective', got %q", cs.Status)
	}
}

func TestCompositeEvaluateControl_CELEvaluationError(t *testing.T) {
	ctrl := &Control{
		ID:   "test.composite",
		Name: "Test Composite",
		Collectors: []ModuleRef{
			{ModuleID: "mock.test"},
		},
		EvaluationLogic: EvaluationLogic{
			CELExpression: "nonexistent_var > 0",
		},
	}

	evidences := []evidence.Evidence{
		makeTestEvidence("mock.test", evidence.StatusEffective, evidence.PassiveObservation),
	}

	// Should not crash, should return unknown status.
	cs, err := CompositeEvaluateControl(ctrl, evidences)
	// A compile error is a hard error (bad control definition).
	if err == nil && cs != nil && cs.Status == "unknown" {
		// Accept either an error or an unknown status for bad CEL.
		return
	}
	if err != nil {
		// Compile errors are acceptable as hard errors.
		return
	}
	t.Errorf("expected either an error or unknown status, got status=%q err=%v", cs.Status, err)
}

func TestCompositeEvaluateControl_SingleSource(t *testing.T) {
	// Composite evaluation should work fine with a single source too.
	ctrl := &Control{
		ID:   "test.composite",
		Name: "Single Source Composite",
		Collectors: []ModuleRef{
			{ModuleID: "mock.test"},
		},
		EvaluationLogic: EvaluationLogic{
			CELExpression: "status_counts.effective > 0 && status_counts.ineffective == 0",
		},
	}

	evidences := []evidence.Evidence{
		makeTestEvidence("mock.test", evidence.StatusEffective, evidence.PassiveObservation),
	}

	cs, err := CompositeEvaluateControl(ctrl, evidences)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cs.Status != "effective" {
		t.Errorf("expected status 'effective', got %q", cs.Status)
	}
}

func TestGroupEvidenceBySource(t *testing.T) {
	evidences := []evidence.Evidence{
		makeTestEvidence("mock.test", evidence.StatusEffective, evidence.PassiveObservation),
		makeTestEvidence("mock.test", evidence.StatusEffective, evidence.PassiveObservation),
		makeTestEvidence("mock.network", evidence.StatusEffective, evidence.PassiveObservation),
		makeTestEvidence("mock.safety_test", evidence.StatusEffective, evidence.ActiveVerification),
	}

	grouped := groupEvidenceBySource(evidences)

	if len(grouped) != 3 {
		t.Errorf("expected 3 groups, got %d", len(grouped))
	}

	if len(grouped["mock.test"]) != 2 {
		t.Errorf("expected 2 evidence records for mock.test, got %d", len(grouped["mock.test"]))
	}

	if len(grouped["mock.network"]) != 1 {
		t.Errorf("expected 1 evidence record for mock.network, got %d", len(grouped["mock.network"]))
	}

	if len(grouped["mock.safety_test"]) != 1 {
		t.Errorf("expected 1 evidence record for mock.safety_test, got %d", len(grouped["mock.safety_test"]))
	}
}

func TestBuildComponentBreakdown(t *testing.T) {
	ctrl := &Control{
		ID: "test.composite",
		Collectors: []ModuleRef{
			{ModuleID: "mock.test"},
			{ModuleID: "mock.network"},
		},
		Testers: []ModuleRef{
			{ModuleID: "mock.safety_test"},
		},
	}

	grouped := map[string][]evidence.Evidence{
		"mock.test": {
			makeTestEvidence("mock.test", evidence.StatusEffective, evidence.PassiveObservation),
		},
		"mock.safety_test": {
			makeTestEvidence("mock.safety_test", evidence.StatusEffective, evidence.ActiveVerification),
		},
		// mock.network is missing - should show as unavailable.
	}

	breakdown := buildComponentBreakdown(ctrl, grouped)

	if len(breakdown) != 3 {
		t.Errorf("expected 3 components in breakdown, got %d", len(breakdown))
	}

	// Check each component.
	foundTest := false
	foundNetwork := false
	foundSafety := false
	for _, comp := range breakdown {
		switch comp.ModuleID {
		case "mock.test":
			foundTest = true
			if comp.Status != "effective" {
				t.Errorf("mock.test: expected status 'effective', got %q", comp.Status)
			}
			if comp.Confidence != "medium" {
				t.Errorf("mock.test: expected confidence 'medium', got %q", comp.Confidence)
			}
		case "mock.network":
			foundNetwork = true
			if comp.Status != "unavailable" {
				t.Errorf("mock.network: expected status 'unavailable', got %q", comp.Status)
			}
		case "mock.safety_test":
			foundSafety = true
			if comp.Status != "effective" {
				t.Errorf("mock.safety_test: expected status 'effective', got %q", comp.Status)
			}
		}
	}

	if !foundTest {
		t.Error("missing mock.test in breakdown")
	}
	if !foundNetwork {
		t.Error("missing mock.network in breakdown")
	}
	if !foundSafety {
		t.Error("missing mock.safety_test in breakdown")
	}
}

// containsString checks if substr is present in s.
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
