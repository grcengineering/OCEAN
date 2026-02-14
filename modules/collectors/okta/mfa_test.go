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

func TestMFAPolicyCollector_ImplementsInterface(t *testing.T) {
	var _ module.Collector = (*MFAPolicyCollector)(nil)
}

func TestMFAPolicyCollector_ID(t *testing.T) {
	c := &MFAPolicyCollector{}
	if got := c.ID(); got != "okta.mfa_policy" {
		t.Errorf("ID() = %q, want %q", got, "okta.mfa_policy")
	}
}

func TestMFAPolicyCollector_Name(t *testing.T) {
	c := &MFAPolicyCollector{}
	if got := c.Name(); got != "Okta MFA Policy Collector" {
		t.Errorf("Name() = %q, want %q", got, "Okta MFA Policy Collector")
	}
}

func TestMFAPolicyCollector_Version(t *testing.T) {
	c := &MFAPolicyCollector{}
	if got := c.Version(); got != "0.1.0" {
		t.Errorf("Version() = %q, want %q", got, "0.1.0")
	}
}

func TestMFAPolicyCollector_SourceSystem(t *testing.T) {
	c := &MFAPolicyCollector{}
	if got := c.SourceSystem(); got != "okta" {
		t.Errorf("SourceSystem() = %q, want %q", got, "okta")
	}
}

func TestMFAPolicyCollector_EvidenceTypes(t *testing.T) {
	c := &MFAPolicyCollector{}
	types := c.EvidenceTypes()
	if len(types) != 1 || types[0] != 1001 {
		t.Errorf("EvidenceTypes() = %v, want [1001]", types)
	}
}

func TestMFAPolicyCollector_CredentialRequirements(t *testing.T) {
	c := &MFAPolicyCollector{}
	reqs := c.CredentialRequirements()
	if len(reqs) != 2 {
		t.Fatalf("CredentialRequirements() returned %d reqs, want 2", len(reqs))
	}
	if reqs[0].Name != "OKTA_API_TOKEN" {
		t.Errorf("first credential name = %q, want %q", reqs[0].Name, "OKTA_API_TOKEN")
	}
	if reqs[1].Name != "OKTA_DOMAIN" {
		t.Errorf("second credential name = %q, want %q", reqs[1].Name, "OKTA_DOMAIN")
	}
}

func TestMFAPolicyCollector_Collect_MissingConfig(t *testing.T) {
	c := &MFAPolicyCollector{}
	_, err := c.Collect(context.Background(), map[string]string{})
	if err == nil {
		t.Fatal("Collect() should return error when config is missing credentials")
	}
}

func TestMFAPolicyCollector_Collect_SuccessfulResponse(t *testing.T) {
	// Set up a mock Okta API server.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request path and query.
		if r.URL.Path != "/api/v1/policies" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.URL.Query().Get("type") != "MFA_ENROLL" {
			t.Errorf("unexpected type query: %s", r.URL.Query().Get("type"))
		}
		// Verify auth header.
		if r.Header.Get("Authorization") != "SSWS test-token-123" {
			t.Errorf("unexpected Authorization: %s", r.Header.Get("Authorization"))
		}
		// Verify User-Agent.
		if r.Header.Get("User-Agent") != "OCEAN/0.1.0" {
			t.Errorf("unexpected User-Agent: %s", r.Header.Get("User-Agent"))
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Return a realistic Okta MFA policy response.
		resp := `[
			{
				"id": "pol001",
				"name": "Default MFA Policy",
				"status": "ACTIVE",
				"settings": {
					"factors": {
						"okta_otp": {"enroll": {"self": "REQUIRED"}},
						"google_otp": {"enroll": {"self": "OPTIONAL"}},
						"okta_push": {"enroll": {"self": "REQUIRED"}}
					}
				},
				"conditions": {
					"people": {
						"groups": {"include": ["everyone"]}
					}
				}
			}
		]`
		w.Write([]byte(resp))
	}))
	defer server.Close()

	// Extract host from test server URL (strip scheme).
	c := &MFAPolicyCollector{}
	config := map[string]string{
		"OKTA_API_TOKEN": "test-token-123",
		"OKTA_DOMAIN":    server.Listener.Addr().String(),
		// Signal to use http:// instead of https:// for test server.
		"OKTA_INSECURE": "true",
	}

	results, err := c.Collect(context.Background(), config)
	if err != nil {
		t.Fatalf("Collect() returned error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Collect() returned %d results, want 1", len(results))
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
	if ev.ActivityID != 1 {
		t.Errorf("ActivityID = %d, want %d", ev.ActivityID, 1)
	}
	if ev.Time.IsZero() {
		t.Error("evidence Time is zero")
	}
	if ev.ConfidenceLevel != evidence.PassiveObservation {
		t.Errorf("ConfidenceLevel = %q, want %q", ev.ConfidenceLevel, evidence.PassiveObservation)
	}

	// Metadata checks.
	if ev.Metadata.Module.Name != "okta.mfa_policy" {
		t.Errorf("Module.Name = %q, want %q", ev.Metadata.Module.Name, "okta.mfa_policy")
	}
	if ev.Metadata.Module.Version != "0.1.0" {
		t.Errorf("Module.Version = %q, want %q", ev.Metadata.Module.Version, "0.1.0")
	}
	if ev.Metadata.Module.Type != "collector" {
		t.Errorf("Module.Type = %q, want %q", ev.Metadata.Module.Type, "collector")
	}
	if ev.Metadata.Source.System != "okta" {
		t.Errorf("Source.System = %q, want %q", ev.Metadata.Source.System, "okta")
	}
	if ev.Metadata.Source.APIVersion != "v1" {
		t.Errorf("Source.APIVersion = %q, want %q", ev.Metadata.Source.APIVersion, "v1")
	}
	if ev.Metadata.Source.Endpoint != "/api/v1/policies?type=MFA_ENROLL" {
		t.Errorf("Source.Endpoint = %q, want %q", ev.Metadata.Source.Endpoint, "/api/v1/policies?type=MFA_ENROLL")
	}
	if ev.Metadata.ProcessedTime.IsZero() {
		t.Error("Metadata.ProcessedTime is zero")
	}

	// Observables must include mfa_policy.
	foundObs := false
	for _, obs := range ev.Observables {
		if obs.Type == "resource" && obs.Value == "mfa_policy" {
			foundObs = true
			break
		}
	}
	if !foundObs {
		t.Errorf("Observables should contain resource:mfa_policy, got %v", ev.Observables)
	}

	// Findings should not be empty.
	if len(ev.Findings) == 0 {
		t.Error("Findings should not be empty")
	}

	// StatusID should be effective for a valid MFA policy.
	if ev.StatusID != evidence.StatusEffective {
		t.Errorf("StatusID = %d, want %d", ev.StatusID, evidence.StatusEffective)
	}

	// RawData should be valid JSON.
	if ev.RawData == nil {
		t.Fatal("RawData is nil")
	}
	var parsed interface{}
	if err := json.Unmarshal(ev.RawData, &parsed); err != nil {
		t.Fatalf("RawData is not valid JSON: %v", err)
	}

	// TestTranscript must be nil for passive collection.
	if ev.TestTranscript != nil {
		t.Error("TestTranscript should be nil for passive observation")
	}
}

func TestMFAPolicyCollector_Collect_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"errorCode":"E0000011","errorSummary":"Invalid token provided"}`))
	}))
	defer server.Close()

	c := &MFAPolicyCollector{}
	config := map[string]string{
		"OKTA_API_TOKEN": "bad-token",
		"OKTA_DOMAIN":    server.Listener.Addr().String(),
		"OKTA_INSECURE":  "true",
	}

	_, err := c.Collect(context.Background(), config)
	if err == nil {
		t.Fatal("Collect() should return error on API error response")
	}
}

func TestMFAPolicyCollector_Collect_InactivePolicyFindings(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Return a policy that is INACTIVE -- should produce findings about gaps.
		resp := `[
			{
				"id": "pol002",
				"name": "Disabled MFA Policy",
				"status": "INACTIVE",
				"settings": {
					"factors": {
						"okta_otp": {"enroll": {"self": "OPTIONAL"}}
					}
				},
				"conditions": {
					"people": {
						"groups": {"include": ["everyone"]}
					}
				}
			}
		]`
		w.Write([]byte(resp))
	}))
	defer server.Close()

	c := &MFAPolicyCollector{}
	config := map[string]string{
		"OKTA_API_TOKEN": "test-token",
		"OKTA_DOMAIN":    server.Listener.Addr().String(),
		"OKTA_INSECURE":  "true",
	}

	results, err := c.Collect(context.Background(), config)
	if err != nil {
		t.Fatalf("Collect() returned error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Collect() returned %d results, want 1", len(results))
	}

	ev := results[0]

	// An inactive-only policy should be marked ineffective.
	if ev.StatusID != evidence.StatusIneffective {
		t.Errorf("StatusID = %d, want %d (ineffective for inactive policy)", ev.StatusID, evidence.StatusIneffective)
	}

	// Should have a finding about the inactive policy.
	foundGap := false
	for _, f := range ev.Findings {
		if f.SeverityID > 0 {
			foundGap = true
			break
		}
	}
	if !foundGap {
		t.Error("Findings should contain at least one non-informational finding for inactive policies")
	}
}

func TestMFAPolicyCollector_Collect_EmptyPolicies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[]`))
	}))
	defer server.Close()

	c := &MFAPolicyCollector{}
	config := map[string]string{
		"OKTA_API_TOKEN": "test-token",
		"OKTA_DOMAIN":    server.Listener.Addr().String(),
		"OKTA_INSECURE":  "true",
	}

	results, err := c.Collect(context.Background(), config)
	if err != nil {
		t.Fatalf("Collect() returned error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Collect() returned %d results, want 1", len(results))
	}

	ev := results[0]

	// No MFA policies = ineffective.
	if ev.StatusID != evidence.StatusIneffective {
		t.Errorf("StatusID = %d, want %d (ineffective for no policies)", ev.StatusID, evidence.StatusIneffective)
	}
}

func TestMFAPolicyCollector_Collect_UniqueIDs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[{"id":"pol001","name":"Test","status":"ACTIVE","settings":{"factors":{"okta_otp":{"enroll":{"self":"REQUIRED"}}}},"conditions":{"people":{"groups":{"include":["everyone"]}}}}]`))
	}))
	defer server.Close()

	c := &MFAPolicyCollector{}
	config := map[string]string{
		"OKTA_API_TOKEN": "test-token",
		"OKTA_DOMAIN":    server.Listener.Addr().String(),
		"OKTA_INSECURE":  "true",
	}

	results1, _ := c.Collect(context.Background(), config)
	results2, _ := c.Collect(context.Background(), config)

	if results1[0].ID == results2[0].ID {
		t.Error("expected unique evidence IDs across calls, got same ID")
	}
}

func TestRegisterAll(t *testing.T) {
	reg := module.NewRegistry()
	RegisterAll(reg)

	collectors := reg.ListCollectors()
	if len(collectors) == 0 {
		t.Fatal("RegisterAll should register at least one collector")
	}

	found := false
	for _, c := range collectors {
		if c.ID() == "okta.mfa_policy" {
			found = true
			break
		}
	}
	if !found {
		t.Error("okta.mfa_policy not found in registered collectors")
	}
}
