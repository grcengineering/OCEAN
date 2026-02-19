package mock

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/grcengineering/ocean/internal/evidence"
	"github.com/grcengineering/ocean/internal/module"
)

func TestCollector_ImplementsInterface(t *testing.T) {
	var _ module.Collector = (*Collector)(nil)
}

func TestCollector_ID(t *testing.T) {
	c := &Collector{}
	if got := c.ID(); got != "mock.test" {
		t.Errorf("ID() = %q, want %q", got, "mock.test")
	}
}

func TestCollector_Name(t *testing.T) {
	c := &Collector{}
	if got := c.Name(); got != "Mock Test Collector" {
		t.Errorf("Name() = %q, want %q", got, "Mock Test Collector")
	}
}

func TestCollector_Version(t *testing.T) {
	c := &Collector{}
	if got := c.Version(); got != "0.1.0" {
		t.Errorf("Version() = %q, want %q", got, "0.1.0")
	}
}

func TestCollector_SourceSystem(t *testing.T) {
	c := &Collector{}
	if got := c.SourceSystem(); got != "mock" {
		t.Errorf("SourceSystem() = %q, want %q", got, "mock")
	}
}

func TestCollector_EvidenceTypes(t *testing.T) {
	c := &Collector{}
	types := c.EvidenceTypes()
	if len(types) != 1 || types[0] != 1001 {
		t.Errorf("EvidenceTypes() = %v, want [1001]", types)
	}
}

func TestCollector_CredentialRequirements(t *testing.T) {
	c := &Collector{}
	if reqs := c.CredentialRequirements(); reqs != nil {
		t.Errorf("CredentialRequirements() = %v, want nil", reqs)
	}
}

func TestCollector_Collect_ReturnsOneEvidence(t *testing.T) {
	c := &Collector{}
	results, err := c.Collect(context.Background(), nil)
	if err != nil {
		t.Fatalf("Collect() returned error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Collect() returned %d results, want 1", len(results))
	}
}

func TestCollector_Collect_EvidenceFields(t *testing.T) {
	c := &Collector{}
	results, err := c.Collect(context.Background(), nil)
	if err != nil {
		t.Fatalf("Collect() returned error: %v", err)
	}
	ev := results[0]

	// ID must be a valid non-nil UUID
	if ev.ID == uuid.Nil {
		t.Error("evidence ID is nil UUID")
	}

	// ControlID
	if ev.ControlID != "mfa.enforcement" {
		t.Errorf("ControlID = %q, want %q", ev.ControlID, "mfa.enforcement")
	}

	// ClassUID
	if ev.ClassUID != 1001 {
		t.Errorf("ClassUID = %d, want %d", ev.ClassUID, 1001)
	}

	// CategoryUID
	if ev.CategoryUID != 1 {
		t.Errorf("CategoryUID = %d, want %d", ev.CategoryUID, 1)
	}

	// ActivityID
	if ev.ActivityID != 1 {
		t.Errorf("ActivityID = %d, want %d", ev.ActivityID, 1)
	}

	// Time must not be zero
	if ev.Time.IsZero() {
		t.Error("evidence Time is zero")
	}

	// Confidence level
	if ev.ConfidenceLevel != evidence.PassiveObservation {
		t.Errorf("ConfidenceLevel = %q, want %q", ev.ConfidenceLevel, evidence.PassiveObservation)
	}

	// StatusID
	if ev.StatusID != evidence.StatusEffective {
		t.Errorf("StatusID = %d, want %d", ev.StatusID, evidence.StatusEffective)
	}

	// Status description
	if ev.Status == "" {
		t.Error("Status is empty")
	}

	// Metadata.Module
	if ev.Metadata.Module.Name != "mock.test" {
		t.Errorf("Module.Name = %q, want %q", ev.Metadata.Module.Name, "mock.test")
	}
	if ev.Metadata.Module.Version != "0.1.0" {
		t.Errorf("Module.Version = %q, want %q", ev.Metadata.Module.Version, "0.1.0")
	}
	if ev.Metadata.Module.Type != "collector" {
		t.Errorf("Module.Type = %q, want %q", ev.Metadata.Module.Type, "collector")
	}

	// Metadata.Source
	if ev.Metadata.Source.System != "mock" {
		t.Errorf("Source.System = %q, want %q", ev.Metadata.Source.System, "mock")
	}
	if ev.Metadata.Source.APIVersion == "" {
		t.Error("Source.APIVersion is empty")
	}
	if ev.Metadata.Source.Endpoint == "" {
		t.Error("Source.Endpoint is empty")
	}

	// ProcessedTime must not be zero
	if ev.Metadata.ProcessedTime.IsZero() {
		t.Error("Metadata.ProcessedTime is zero")
	}

	// Observables must have at least one entry
	if len(ev.Observables) == 0 {
		t.Error("Observables is empty")
	}

	// Findings must have at least one entry
	if len(ev.Findings) == 0 {
		t.Error("Findings is empty")
	}

	// TestTranscript must be nil for passive observation
	if ev.TestTranscript != nil {
		t.Error("TestTranscript should be nil for passive observation")
	}
}

func TestCollector_Collect_RawDataIsValidJSON(t *testing.T) {
	c := &Collector{}
	results, err := c.Collect(context.Background(), nil)
	if err != nil {
		t.Fatalf("Collect() returned error: %v", err)
	}
	ev := results[0]

	if ev.RawData == nil {
		t.Fatal("RawData is nil")
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(ev.RawData, &parsed); err != nil {
		t.Fatalf("RawData is not valid JSON: %v", err)
	}

	// Verify expected MFA data structure
	if _, ok := parsed["mfa_policy"]; !ok {
		t.Error("RawData missing 'mfa_policy' key")
	}
	if _, ok := parsed["total_users"]; !ok {
		t.Error("RawData missing 'total_users' key")
	}
	if _, ok := parsed["mfa_enrolled"]; !ok {
		t.Error("RawData missing 'mfa_enrolled' key")
	}
}

func TestCollector_Collect_RespectsContext(t *testing.T) {
	c := &Collector{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel

	// Mock collector doesn't make external calls, so cancelled context
	// should not cause an error. This tests the interface contract.
	results, err := c.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Collect() with cancelled context returned error: %v", err)
	}
	if len(results) == 0 {
		t.Error("expected results even with cancelled context (mock has no I/O)")
	}
}

func TestCollector_Collect_UniqueIDs(t *testing.T) {
	c := &Collector{}

	results1, _ := c.Collect(context.Background(), nil)
	results2, _ := c.Collect(context.Background(), nil)

	if results1[0].ID == results2[0].ID {
		t.Error("expected unique evidence IDs across calls, got same ID")
	}
}

// --- NetworkCollector (collector_b.go) tests ---

func TestNetworkCollector_ImplementsInterface(t *testing.T) {
	var _ module.Collector = (*NetworkCollector)(nil)
}

func TestNetworkCollector_Metadata(t *testing.T) {
	c := &NetworkCollector{}

	if got := c.ID(); got != "mock.network" {
		t.Errorf("ID() = %q, want %q", got, "mock.network")
	}
	if got := c.Name(); got != "Mock Network Collector" {
		t.Errorf("Name() = %q, want %q", got, "Mock Network Collector")
	}
	if got := c.Version(); got != "0.1.0" {
		t.Errorf("Version() = %q, want %q", got, "0.1.0")
	}
	if got := c.SourceSystem(); got != "mock" {
		t.Errorf("SourceSystem() = %q, want %q", got, "mock")
	}

	types := c.EvidenceTypes()
	if len(types) != 1 || types[0] != 1002 {
		t.Errorf("EvidenceTypes() = %v, want [1002]", types)
	}

	if reqs := c.CredentialRequirements(); reqs != nil {
		t.Errorf("CredentialRequirements() = %v, want nil", reqs)
	}
}

func TestNetworkCollector_Collect(t *testing.T) {
	c := &NetworkCollector{}
	results, err := c.Collect(context.Background(), nil)
	if err != nil {
		t.Fatalf("Collect() returned error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Collect() returned %d results, want 1", len(results))
	}

	ev := results[0]

	// ID must be a valid non-nil UUID.
	if ev.ID == uuid.Nil {
		t.Error("evidence ID is nil UUID")
	}

	// ControlID
	if ev.ControlID != "waf.protection" {
		t.Errorf("ControlID = %q, want %q", ev.ControlID, "waf.protection")
	}

	// ClassUID
	if ev.ClassUID != 1002 {
		t.Errorf("ClassUID = %d, want %d", ev.ClassUID, 1002)
	}

	// CategoryUID (Network Activity = 4)
	if ev.CategoryUID != 4 {
		t.Errorf("CategoryUID = %d, want %d", ev.CategoryUID, 4)
	}

	// ActivityID (Config Check = 1)
	if ev.ActivityID != 1 {
		t.Errorf("ActivityID = %d, want %d", ev.ActivityID, 1)
	}

	// Time must not be zero.
	if ev.Time.IsZero() {
		t.Error("evidence Time is zero")
	}

	// Confidence level
	if ev.ConfidenceLevel != evidence.PassiveObservation {
		t.Errorf("ConfidenceLevel = %q, want %q", ev.ConfidenceLevel, evidence.PassiveObservation)
	}

	// StatusID
	if ev.StatusID != evidence.StatusEffective {
		t.Errorf("StatusID = %d, want %d", ev.StatusID, evidence.StatusEffective)
	}

	// Status description
	if ev.Status == "" {
		t.Error("Status is empty")
	}

	// Metadata.Module
	if ev.Metadata.Module.Name != "mock.network" {
		t.Errorf("Module.Name = %q, want %q", ev.Metadata.Module.Name, "mock.network")
	}
	if ev.Metadata.Module.Version != "0.1.0" {
		t.Errorf("Module.Version = %q, want %q", ev.Metadata.Module.Version, "0.1.0")
	}
	if ev.Metadata.Module.Type != "collector" {
		t.Errorf("Module.Type = %q, want %q", ev.Metadata.Module.Type, "collector")
	}

	// Metadata.Source
	if ev.Metadata.Source.System != "mock" {
		t.Errorf("Source.System = %q, want %q", ev.Metadata.Source.System, "mock")
	}
	if ev.Metadata.Source.APIVersion != "v1" {
		t.Errorf("Source.APIVersion = %q, want %q", ev.Metadata.Source.APIVersion, "v1")
	}
	if ev.Metadata.Source.Endpoint != "/api/v1/waf/config" {
		t.Errorf("Source.Endpoint = %q, want %q", ev.Metadata.Source.Endpoint, "/api/v1/waf/config")
	}

	// ProcessedTime must not be zero.
	if ev.Metadata.ProcessedTime.IsZero() {
		t.Error("Metadata.ProcessedTime is zero")
	}

	// Observables must have entries.
	if len(ev.Observables) != 2 {
		t.Errorf("Observables length = %d, want 2", len(ev.Observables))
	}

	// Findings must have at least one entry.
	if len(ev.Findings) != 1 {
		t.Errorf("Findings length = %d, want 1", len(ev.Findings))
	}
	if ev.Findings[0].Title != "WAF Active" {
		t.Errorf("Finding.Title = %q, want %q", ev.Findings[0].Title, "WAF Active")
	}

	// TestTranscript must be nil for passive observation.
	if ev.TestTranscript != nil {
		t.Error("TestTranscript should be nil for passive observation")
	}
}

func TestNetworkCollector_Collect_RawDataIsValidJSON(t *testing.T) {
	c := &NetworkCollector{}
	results, err := c.Collect(context.Background(), nil)
	if err != nil {
		t.Fatalf("Collect() returned error: %v", err)
	}
	ev := results[0]

	if ev.RawData == nil {
		t.Fatal("RawData is nil")
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(ev.RawData, &parsed); err != nil {
		t.Fatalf("RawData is not valid JSON: %v", err)
	}

	if _, ok := parsed["waf_config"]; !ok {
		t.Error("RawData missing 'waf_config' key")
	}
	if _, ok := parsed["protected_origins"]; !ok {
		t.Error("RawData missing 'protected_origins' key")
	}
	if _, ok := parsed["blocked_requests_24h"]; !ok {
		t.Error("RawData missing 'blocked_requests_24h' key")
	}
}

func TestNetworkCollector_Collect_UniqueIDs(t *testing.T) {
	c := &NetworkCollector{}

	results1, _ := c.Collect(context.Background(), nil)
	results2, _ := c.Collect(context.Background(), nil)

	if results1[0].ID == results2[0].ID {
		t.Error("expected unique evidence IDs across calls, got same ID")
	}
}
