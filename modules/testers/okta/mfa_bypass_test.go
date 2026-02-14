package okta

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/grcengineering/ocean/internal/evidence"
	"github.com/grcengineering/ocean/internal/module"
)

func TestMFABypassTester_ImplementsInterface(t *testing.T) {
	var _ module.Tester = (*MFABypassTester)(nil)
}

func TestMFABypassTester_ID(t *testing.T) {
	tester := &MFABypassTester{}
	if got := tester.ID(); got != "okta.mfa_bypass" {
		t.Errorf("ID() = %q, want %q", got, "okta.mfa_bypass")
	}
}

func TestMFABypassTester_Name(t *testing.T) {
	tester := &MFABypassTester{}
	if got := tester.Name(); got != "Okta MFA Bypass Tester" {
		t.Errorf("Name() = %q, want %q", got, "Okta MFA Bypass Tester")
	}
}

func TestMFABypassTester_Version(t *testing.T) {
	tester := &MFABypassTester{}
	if got := tester.Version(); got != "0.1.0" {
		t.Errorf("Version() = %q, want %q", got, "0.1.0")
	}
}

func TestMFABypassTester_SourceSystem(t *testing.T) {
	tester := &MFABypassTester{}
	if got := tester.SourceSystem(); got != "okta" {
		t.Errorf("SourceSystem() = %q, want %q", got, "okta")
	}
}

func TestMFABypassTester_EvidenceTypes(t *testing.T) {
	tester := &MFABypassTester{}
	types := tester.EvidenceTypes()
	if len(types) != 1 || types[0] != 1001 {
		t.Errorf("EvidenceTypes() = %v, want [1001]", types)
	}
}

func TestMFABypassTester_SafetyClass(t *testing.T) {
	tester := &MFABypassTester{}
	if got := tester.SafetyClass(); got != module.SafetyClassSafe {
		t.Errorf("SafetyClass() = %q, want %q", got, module.SafetyClassSafe)
	}
}

func TestMFABypassTester_EnvironmentScope(t *testing.T) {
	tester := &MFABypassTester{}
	if got := tester.EnvironmentScope(); got != module.ScopeProduction {
		t.Errorf("EnvironmentScope() = %q, want %q", got, module.ScopeProduction)
	}
}

func TestMFABypassTester_PreFlightChecks(t *testing.T) {
	tester := &MFABypassTester{}
	checks := tester.PreFlightChecks()
	if len(checks) != 2 {
		t.Fatalf("PreFlightChecks() returned %d checks, want 2", len(checks))
	}
	if checks[0] != "verify Okta API reachable" {
		t.Errorf("first check = %q, want %q", checks[0], "verify Okta API reachable")
	}
	if checks[1] != "verify test credentials configured" {
		t.Errorf("second check = %q, want %q", checks[1], "verify test credentials configured")
	}
}

func TestMFABypassTester_CleanupProcedures(t *testing.T) {
	tester := &MFABypassTester{}
	procs := tester.CleanupProcedures()
	if len(procs) != 0 {
		t.Errorf("CleanupProcedures() returned %d procedures, want 0 (safe classification)", len(procs))
	}
}

func TestMFABypassTester_CredentialRequirements(t *testing.T) {
	tester := &MFABypassTester{}
	reqs := tester.CredentialRequirements()
	if len(reqs) != 4 {
		t.Fatalf("CredentialRequirements() returned %d reqs, want 4", len(reqs))
	}
	// Verify all required credential names exist.
	names := make(map[string]bool)
	for _, r := range reqs {
		names[r.Name] = true
	}
	for _, name := range []string{"OKTA_API_TOKEN", "OKTA_DOMAIN", "OKTA_TEST_USER", "OKTA_TEST_PASSWORD"} {
		if !names[name] {
			t.Errorf("missing credential requirement %q", name)
		}
	}
}

func TestMFABypassTester_Test_MissingConfig(t *testing.T) {
	tester := &MFABypassTester{}
	_, err := tester.Test(context.Background(), map[string]string{})
	if err == nil {
		t.Fatal("Test() should return error when config is missing credentials")
	}
}

func TestMFABypassTester_Test_MissingTestUser(t *testing.T) {
	tester := &MFABypassTester{}
	config := map[string]string{
		"OKTA_API_TOKEN": "token",
		"OKTA_DOMAIN":    "example.okta.com",
	}
	_, err := tester.Test(context.Background(), config)
	if err == nil {
		t.Fatal("Test() should return error when test user credentials are missing")
	}
}

func TestMFABypassTester_Test_AuthBlocked(t *testing.T) {
	// Simulate Okta rejecting authentication without MFA.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/authn" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", r.Method)
		}

		// Verify request body has username and password but no MFA token.
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}
		if body["username"] != "testuser@example.com" {
			t.Errorf("unexpected username: %v", body["username"])
		}

		// Return 403 -- MFA required, bypass blocked.
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"errorCode":"E0000069","errorSummary":"MFA required"}`))
	}))
	defer server.Close()

	tester := &MFABypassTester{}
	config := map[string]string{
		"OKTA_API_TOKEN":    "test-token",
		"OKTA_DOMAIN":       server.Listener.Addr().String(),
		"OKTA_TEST_USER":     "testuser@example.com",
		"OKTA_TEST_PASSWORD": "testpass123",
		"OKTA_INSECURE":      "true",
	}

	results, err := tester.Test(context.Background(), config)
	if err != nil {
		t.Fatalf("Test() returned error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Test() returned %d results, want 1", len(results))
	}

	ev := results[0]

	// Verify evidence fields.
	if ev.ID == uuid.Nil {
		t.Error("evidence ID is nil UUID")
	}
	if ev.ControlID != "mfa.enforcement" {
		t.Errorf("ControlID = %q, want %q", ev.ControlID, "mfa.enforcement")
	}
	if ev.ClassUID != 1001 {
		t.Errorf("ClassUID = %d, want %d", ev.ClassUID, 1001)
	}
	if ev.CategoryUID != 1 {
		t.Errorf("CategoryUID = %d, want %d", ev.CategoryUID, 1)
	}
	if ev.ActivityID != 2 {
		t.Errorf("ActivityID = %d, want %d (active test)", ev.ActivityID, 2)
	}
	if ev.ConfidenceLevel != evidence.ActiveVerification {
		t.Errorf("ConfidenceLevel = %q, want %q", ev.ConfidenceLevel, evidence.ActiveVerification)
	}
	if ev.StatusID != evidence.StatusEffective {
		t.Errorf("StatusID = %d, want %d (effective - bypass blocked)", ev.StatusID, evidence.StatusEffective)
	}

	// Metadata checks.
	if ev.Metadata.Module.Type != "tester" {
		t.Errorf("Module.Type = %q, want %q", ev.Metadata.Module.Type, "tester")
	}
	if ev.Metadata.SafetyClassification == nil {
		t.Fatal("SafetyClassification should not be nil for testers")
	}
	if *ev.Metadata.SafetyClassification != "safe" {
		t.Errorf("SafetyClassification = %q, want %q", *ev.Metadata.SafetyClassification, "safe")
	}

	// TestTranscript must be present.
	if ev.TestTranscript == nil {
		t.Fatal("TestTranscript should not be nil for active verification")
	}
	if len(ev.TestTranscript.ActionsAttempted) == 0 {
		t.Error("TestTranscript should have at least one action")
	}
	if len(ev.TestTranscript.Observations) == 0 {
		t.Error("TestTranscript should have at least one observation")
	}

	// Findings.
	if len(ev.Findings) == 0 {
		t.Error("Findings should not be empty")
	}

	// RawData should be valid JSON.
	if ev.RawData == nil {
		t.Fatal("RawData is nil")
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(ev.RawData, &parsed); err != nil {
		t.Fatalf("RawData is not valid JSON: %v", err)
	}
}

func TestMFABypassTester_Test_AuthSucceeded_Ineffective(t *testing.T) {
	// Simulate Okta allowing authentication without MFA -- control failure.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"SUCCESS","sessionToken":"abc123","_embedded":{"user":{"id":"usr001"}}}`))
	}))
	defer server.Close()

	tester := &MFABypassTester{}
	config := map[string]string{
		"OKTA_API_TOKEN":    "test-token",
		"OKTA_DOMAIN":       server.Listener.Addr().String(),
		"OKTA_TEST_USER":     "testuser@example.com",
		"OKTA_TEST_PASSWORD": "testpass123",
		"OKTA_INSECURE":      "true",
	}

	results, err := tester.Test(context.Background(), config)
	if err != nil {
		t.Fatalf("Test() returned error: %v", err)
	}

	ev := results[0]

	// If auth succeeded without MFA, control is ineffective.
	if ev.StatusID != evidence.StatusIneffective {
		t.Errorf("StatusID = %d, want %d (ineffective - bypass succeeded)", ev.StatusID, evidence.StatusIneffective)
	}
}

func TestMFABypassTester_Test_MFARequired_Effective(t *testing.T) {
	// Simulate Okta returning MFA_REQUIRED status (401 or MFA challenge).
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"MFA_REQUIRED","_embedded":{"factors":[{"factorType":"push"}]}}`))
	}))
	defer server.Close()

	tester := &MFABypassTester{}
	config := map[string]string{
		"OKTA_API_TOKEN":    "test-token",
		"OKTA_DOMAIN":       server.Listener.Addr().String(),
		"OKTA_TEST_USER":     "testuser@example.com",
		"OKTA_TEST_PASSWORD": "testpass123",
		"OKTA_INSECURE":      "true",
	}

	results, err := tester.Test(context.Background(), config)
	if err != nil {
		t.Fatalf("Test() returned error: %v", err)
	}

	ev := results[0]

	// MFA_REQUIRED means the control is effective.
	if ev.StatusID != evidence.StatusEffective {
		t.Errorf("StatusID = %d, want %d (effective - MFA required)", ev.StatusID, evidence.StatusEffective)
	}
}

func TestMFABypassTester_Test_UniqueIDs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"errorCode":"E0000069","errorSummary":"MFA required"}`))
	}))
	defer server.Close()

	tester := &MFABypassTester{}
	config := map[string]string{
		"OKTA_API_TOKEN":    "test-token",
		"OKTA_DOMAIN":       server.Listener.Addr().String(),
		"OKTA_TEST_USER":     "testuser@example.com",
		"OKTA_TEST_PASSWORD": "testpass123",
		"OKTA_INSECURE":      "true",
	}

	results1, _ := tester.Test(context.Background(), config)
	results2, _ := tester.Test(context.Background(), config)

	if results1[0].ID == results2[0].ID {
		t.Error("expected unique evidence IDs across calls, got same ID")
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
		if tester.ID() == "okta.mfa_bypass" {
			found = true
			break
		}
	}
	if !found {
		t.Error("okta.mfa_bypass not found in registered testers")
	}
}
