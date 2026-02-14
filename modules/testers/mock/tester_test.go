package mock

import (
	"context"
	"testing"

	"github.com/grcengineering/ocean/internal/evidence"
	"github.com/grcengineering/ocean/internal/module"
)

func TestMockTester_ID(t *testing.T) {
	tester := &MockTester{}
	if got := tester.ID(); got != "mock.safety_test" {
		t.Errorf("ID() = %q, want %q", got, "mock.safety_test")
	}
}

func TestMockTester_SafetyClass(t *testing.T) {
	tester := &MockTester{}
	if got := tester.SafetyClass(); got != module.SafetyClassSafe {
		t.Errorf("SafetyClass() = %q, want %q", got, module.SafetyClassSafe)
	}
}

func TestMockTester_EnvironmentScope(t *testing.T) {
	tester := &MockTester{}
	if got := tester.EnvironmentScope(); got != module.ScopeProduction {
		t.Errorf("EnvironmentScope() = %q, want %q", got, module.ScopeProduction)
	}
}

func TestMockTester_PreFlightChecks(t *testing.T) {
	tester := &MockTester{}
	checks := tester.PreFlightChecks()
	if len(checks) == 0 {
		t.Error("PreFlightChecks() should return at least one check")
	}
}

func TestMockTester_CleanupProcedures(t *testing.T) {
	tester := &MockTester{}
	procs := tester.CleanupProcedures()
	if len(procs) == 0 {
		t.Error("CleanupProcedures() should return at least one procedure")
	}
}

func TestMockTester_ImplementsInterface(t *testing.T) {
	var _ module.Tester = (*MockTester)(nil)
}

func TestMockTester_Test_ReturnsEvidence(t *testing.T) {
	tester := &MockTester{}
	results, err := tester.Test(context.Background(), nil)
	if err != nil {
		t.Fatalf("Test() returned error: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("Test() returned no evidence")
	}
}

func TestMockTester_Test_HasTranscript(t *testing.T) {
	tester := &MockTester{}
	results, err := tester.Test(context.Background(), nil)
	if err != nil {
		t.Fatalf("Test() returned error: %v", err)
	}
	ev := results[0]

	if ev.TestTranscript == nil {
		t.Fatal("evidence should have a TestTranscript")
	}

	if len(ev.TestTranscript.ActionsAttempted) == 0 {
		t.Error("TestTranscript should have at least one action")
	}

	if len(ev.TestTranscript.Observations) == 0 {
		t.Error("TestTranscript should have at least one observation")
	}

	if len(ev.TestTranscript.CleanupActions) == 0 {
		t.Error("TestTranscript should have at least one cleanup action")
	}
}

func TestMockTester_Test_ActiveVerificationConfidence(t *testing.T) {
	tester := &MockTester{}
	results, err := tester.Test(context.Background(), nil)
	if err != nil {
		t.Fatalf("Test() returned error: %v", err)
	}
	ev := results[0]

	if ev.ConfidenceLevel != evidence.ActiveVerification {
		t.Errorf("ConfidenceLevel = %q, want %q",
			ev.ConfidenceLevel, evidence.ActiveVerification)
	}
}

func TestMockTester_Test_StatusEffective(t *testing.T) {
	tester := &MockTester{}
	results, err := tester.Test(context.Background(), nil)
	if err != nil {
		t.Fatalf("Test() returned error: %v", err)
	}
	ev := results[0]

	if ev.StatusID != evidence.StatusEffective {
		t.Errorf("StatusID = %d, want %d", ev.StatusID, evidence.StatusEffective)
	}
}

func TestMockTester_Test_ModuleType(t *testing.T) {
	tester := &MockTester{}
	results, err := tester.Test(context.Background(), nil)
	if err != nil {
		t.Fatalf("Test() returned error: %v", err)
	}
	ev := results[0]

	if ev.Metadata.Module.Type != "tester" {
		t.Errorf("Module.Type = %q, want %q", ev.Metadata.Module.Type, "tester")
	}
}

func TestRegisterAll(t *testing.T) {
	reg := module.NewRegistry()
	RegisterAll(reg)

	testers := reg.ListTesters()
	if len(testers) == 0 {
		t.Fatal("RegisterAll should register at least one tester")
	}

	found := false
	for _, tester := range testers {
		if tester.ID() == "mock.safety_test" {
			found = true
			break
		}
	}
	if !found {
		t.Error("mock.safety_test not found in registered testers")
	}
}
