package testutil

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/grcengineering/ocean/internal/control"
	"github.com/grcengineering/ocean/internal/evidence"
	"github.com/grcengineering/ocean/internal/module"
	"github.com/grcengineering/ocean/internal/scheduler"
	"github.com/grcengineering/ocean/internal/storage"
)

// ---------------------------------------------------------------------------
// EvidenceBuilder tests
// ---------------------------------------------------------------------------

func TestEvidenceBuilder_Defaults(t *testing.T) {
	ev := NewEvidence().Build()

	if ev.ID == uuid.Nil {
		t.Error("expected non-nil UUID, got Nil")
	}
	if ev.ControlID != "test.control" {
		t.Errorf("expected ControlID %q, got %q", "test.control", ev.ControlID)
	}
	if ev.ClassUID != 9999 {
		t.Errorf("expected ClassUID 9999, got %d", ev.ClassUID)
	}
	if ev.CategoryUID != 9 {
		t.Errorf("expected CategoryUID 9, got %d", ev.CategoryUID)
	}
	if ev.ActivityID != 1 {
		t.Errorf("expected ActivityID 1, got %d", ev.ActivityID)
	}
	if ev.Time.IsZero() {
		t.Error("expected non-zero Time")
	}
	if ev.ConfidenceLevel != evidence.PassiveObservation {
		t.Errorf("expected confidence %q, got %q", evidence.PassiveObservation, ev.ConfidenceLevel)
	}
	if ev.StatusID != evidence.StatusEffective {
		t.Errorf("expected StatusID %d, got %d", evidence.StatusEffective, ev.StatusID)
	}
	if ev.Status != "effective" {
		t.Errorf("expected Status %q, got %q", "effective", ev.Status)
	}
	if ev.RawData == nil {
		t.Error("expected non-nil RawData")
	}
	if ev.Metadata.Module.Name != "test.module" {
		t.Errorf("expected Module.Name %q, got %q", "test.module", ev.Metadata.Module.Name)
	}
	if ev.Metadata.Module.Version != "0.1.0" {
		t.Errorf("expected Module.Version %q, got %q", "0.1.0", ev.Metadata.Module.Version)
	}
	if ev.Metadata.Module.Type != "collector" {
		t.Errorf("expected Module.Type %q, got %q", "collector", ev.Metadata.Module.Type)
	}
	if ev.Metadata.Source.System != "test" {
		t.Errorf("expected Source.System %q, got %q", "test", ev.Metadata.Source.System)
	}
	if ev.Metadata.Source.APIVersion != "v1" {
		t.Errorf("expected Source.APIVersion %q, got %q", "v1", ev.Metadata.Source.APIVersion)
	}
	if ev.Metadata.Source.Endpoint != "/test" {
		t.Errorf("expected Source.Endpoint %q, got %q", "/test", ev.Metadata.Source.Endpoint)
	}
	if ev.Metadata.ProcessedTime.IsZero() {
		t.Error("expected non-zero ProcessedTime")
	}
}

func TestEvidenceBuilder_WithFields(t *testing.T) {
	id := uuid.New()
	fixedTime := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)

	ev := NewEvidence().
		WithID(id).
		WithControlID("mfa.enforcement").
		WithClassUID(1001).
		WithStatus(evidence.StatusIneffective).
		WithConfidence(evidence.ActiveVerification).
		WithModule("okta.mfa", "1.0.0", "tester").
		WithSource("okta", "v2", "/api/v1/policies").
		WithRawData(map[string]interface{}{"key": "value"}).
		WithFinding("MFA not enforced", "No MFA policy found", 3).
		WithTranscript().
		WithTime(fixedTime).
		Build()

	if ev.ID != id {
		t.Errorf("expected ID %s, got %s", id, ev.ID)
	}
	if ev.ControlID != "mfa.enforcement" {
		t.Errorf("expected ControlID %q, got %q", "mfa.enforcement", ev.ControlID)
	}
	if ev.ClassUID != 1001 {
		t.Errorf("expected ClassUID 1001, got %d", ev.ClassUID)
	}
	if ev.StatusID != evidence.StatusIneffective {
		t.Errorf("expected StatusID %d, got %d", evidence.StatusIneffective, ev.StatusID)
	}
	if ev.Status != "ineffective" {
		t.Errorf("expected Status %q, got %q", "ineffective", ev.Status)
	}
	if ev.ConfidenceLevel != evidence.ActiveVerification {
		t.Errorf("expected confidence %q, got %q", evidence.ActiveVerification, ev.ConfidenceLevel)
	}
	if ev.Metadata.Module.Name != "okta.mfa" {
		t.Errorf("expected Module.Name %q, got %q", "okta.mfa", ev.Metadata.Module.Name)
	}
	if ev.Metadata.Module.Version != "1.0.0" {
		t.Errorf("expected Module.Version %q, got %q", "1.0.0", ev.Metadata.Module.Version)
	}
	if ev.Metadata.Module.Type != "tester" {
		t.Errorf("expected Module.Type %q, got %q", "tester", ev.Metadata.Module.Type)
	}
	if ev.Metadata.Source.System != "okta" {
		t.Errorf("expected Source.System %q, got %q", "okta", ev.Metadata.Source.System)
	}
	if ev.Metadata.Source.APIVersion != "v2" {
		t.Errorf("expected Source.APIVersion %q, got %q", "v2", ev.Metadata.Source.APIVersion)
	}
	if ev.Metadata.Source.Endpoint != "/api/v1/policies" {
		t.Errorf("expected Source.Endpoint %q, got %q", "/api/v1/policies", ev.Metadata.Source.Endpoint)
	}

	// Verify RawData
	var rawMap map[string]interface{}
	if err := json.Unmarshal(ev.RawData, &rawMap); err != nil {
		t.Fatalf("failed to unmarshal RawData: %v", err)
	}
	if rawMap["key"] != "value" {
		t.Errorf("expected RawData key %q, got %q", "value", rawMap["key"])
	}

	// Verify Finding
	if len(ev.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(ev.Findings))
	}
	if ev.Findings[0].Title != "MFA not enforced" {
		t.Errorf("expected finding title %q, got %q", "MFA not enforced", ev.Findings[0].Title)
	}
	if ev.Findings[0].Description != "No MFA policy found" {
		t.Errorf("expected finding description %q, got %q", "No MFA policy found", ev.Findings[0].Description)
	}
	if ev.Findings[0].SeverityID != 3 {
		t.Errorf("expected finding severity 3, got %d", ev.Findings[0].SeverityID)
	}

	// Verify Transcript
	if ev.TestTranscript == nil {
		t.Fatal("expected non-nil TestTranscript")
	}
	if len(ev.TestTranscript.ActionsAttempted) != 1 {
		t.Errorf("expected 1 transcript action, got %d", len(ev.TestTranscript.ActionsAttempted))
	}
	if len(ev.TestTranscript.Observations) != 1 {
		t.Errorf("expected 1 transcript observation, got %d", len(ev.TestTranscript.Observations))
	}

	// Verify Time
	if !ev.Time.Equal(fixedTime) {
		t.Errorf("expected Time %v, got %v", fixedTime, ev.Time)
	}
}

func TestEvidenceBuilder_WithStatus_AllVariants(t *testing.T) {
	tests := []struct {
		status     evidence.StatusID
		wantString string
	}{
		{evidence.StatusEffective, "effective"},
		{evidence.StatusIneffective, "ineffective"},
		{evidence.StatusUnknown, "unknown"},
		{evidence.StatusOther, "other"},
	}
	for _, tc := range tests {
		ev := NewEvidence().WithStatus(tc.status).Build()
		if ev.Status != tc.wantString {
			t.Errorf("WithStatus(%d): expected %q, got %q", tc.status, tc.wantString, ev.Status)
		}
	}
}

// ---------------------------------------------------------------------------
// MockAPIServer tests
// ---------------------------------------------------------------------------

func TestMockAPIServer_Handle(t *testing.T) {
	srv := NewMockAPIServer(t)
	srv.Handle("GET", "/api/v1/policies", http.StatusOK, `[{"id":"pol001"}]`)

	resp, err := http.Get(srv.URL + "/api/v1/policies")
	if err != nil {
		t.Fatalf("HTTP GET failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}
	if string(body) != `[{"id":"pol001"}]` {
		t.Errorf("expected body %q, got %q", `[{"id":"pol001"}]`, string(body))
	}

	ct := resp.Header.Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type %q, got %q", "application/json", ct)
	}
}

func TestMockAPIServer_Handle_NotFound(t *testing.T) {
	srv := NewMockAPIServer(t)

	resp, err := http.Get(srv.URL + "/nonexistent")
	if err != nil {
		t.Fatalf("HTTP GET failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", resp.StatusCode)
	}
}

func TestMockAPIServer_CallCount(t *testing.T) {
	srv := NewMockAPIServer(t)
	srv.Handle("GET", "/api/v1/users", http.StatusOK, `[]`)

	for i := 0; i < 3; i++ {
		resp, err := http.Get(srv.URL + "/api/v1/users")
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
		resp.Body.Close()
	}

	count := srv.CallCount("GET", "/api/v1/users")
	if count != 3 {
		t.Errorf("expected CallCount 3, got %d", count)
	}

	// Unregistered route should have 0 calls.
	if srv.CallCount("POST", "/api/v1/users") != 0 {
		t.Errorf("expected CallCount 0 for unregistered route, got %d", srv.CallCount("POST", "/api/v1/users"))
	}
}

func TestMockAPIServer_AssertCalled(t *testing.T) {
	srv := NewMockAPIServer(t)
	srv.Handle("POST", "/api/v1/evidence", http.StatusCreated, `{"id":"ev001"}`)

	req, err := http.NewRequest("POST", srv.URL+"/api/v1/evidence", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("HTTP POST failed: %v", err)
	}
	resp.Body.Close()

	// AssertCalled should not fail since we made a call.
	srv.AssertCalled(t, "POST", "/api/v1/evidence")
}

func TestMockAPIServer_Host(t *testing.T) {
	srv := NewMockAPIServer(t)

	host := srv.Host()
	if host == "" {
		t.Error("expected non-empty host")
	}
	// Host should NOT contain the scheme.
	if len(host) > 7 && host[:7] == "http://" {
		t.Errorf("Host() should strip scheme, got %q", host)
	}
}

func TestMockAPIServer_HandleFunc(t *testing.T) {
	srv := NewMockAPIServer(t)
	srv.HandleFunc("GET", "/api/v1/custom", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("custom handler"))
	})

	resp, err := http.Get(srv.URL + "/api/v1/custom")
	if err != nil {
		t.Fatalf("HTTP GET failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}
	if string(body) != "custom handler" {
		t.Errorf("expected body %q, got %q", "custom handler", string(body))
	}
}

// ---------------------------------------------------------------------------
// MemoryStore tests
// ---------------------------------------------------------------------------

func TestMemoryStore_EvidenceRoundTrip(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	ev := NewEvidence().WithControlID("mfa.policy").Build()

	if err := store.StoreEvidence(ctx, ev); err != nil {
		t.Fatalf("StoreEvidence failed: %v", err)
	}

	got, err := store.GetEvidence(ctx, ev.ID)
	if err != nil {
		t.Fatalf("GetEvidence failed: %v", err)
	}

	if got.ID != ev.ID {
		t.Errorf("expected ID %s, got %s", ev.ID, got.ID)
	}
	if got.ControlID != ev.ControlID {
		t.Errorf("expected ControlID %q, got %q", ev.ControlID, got.ControlID)
	}
}

func TestMemoryStore_GetEvidence_NotFound(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	_, err := store.GetEvidence(ctx, uuid.New())
	if err == nil {
		t.Error("expected error for nonexistent evidence, got nil")
	}
}

func TestMemoryStore_QueryEvidence(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	ev1 := NewEvidence().WithControlID("mfa.policy").Build()
	ev2 := NewEvidence().WithControlID("mfa.policy").Build()
	ev3 := NewEvidence().WithControlID("branch.protection").Build()

	for _, ev := range []evidence.Evidence{ev1, ev2, ev3} {
		if err := store.StoreEvidence(ctx, ev); err != nil {
			t.Fatalf("StoreEvidence failed: %v", err)
		}
	}

	// Query by ControlID
	results, err := store.QueryEvidence(ctx, storage.EvidenceQuery{
		ControlID: "mfa.policy",
		Limit:     10,
	})
	if err != nil {
		t.Fatalf("QueryEvidence failed: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("expected 2 results for mfa.policy, got %d", len(results))
	}

	// Query with Limit
	results, err = store.QueryEvidence(ctx, storage.EvidenceQuery{
		ControlID: "mfa.policy",
		Limit:     1,
	})
	if err != nil {
		t.Fatalf("QueryEvidence with limit failed: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("expected 1 result with limit=1, got %d", len(results))
	}

	// Query with no filter returns all
	results, err = store.QueryEvidence(ctx, storage.EvidenceQuery{})
	if err != nil {
		t.Fatalf("QueryEvidence all failed: %v", err)
	}
	if len(results) != 3 {
		t.Errorf("expected 3 total results, got %d", len(results))
	}
}

func TestMemoryStore_QueryEvidence_BySource(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	ev1 := NewEvidence().WithSource("okta", "v1", "/mfa").Build()
	ev2 := NewEvidence().WithSource("github", "v1", "/repos").Build()

	for _, ev := range []evidence.Evidence{ev1, ev2} {
		if err := store.StoreEvidence(ctx, ev); err != nil {
			t.Fatalf("StoreEvidence failed: %v", err)
		}
	}

	results, err := store.QueryEvidence(ctx, storage.EvidenceQuery{Source: "okta"})
	if err != nil {
		t.Fatalf("QueryEvidence by source failed: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("expected 1 result for source okta, got %d", len(results))
	}
}

func TestMemoryStore_ControlStatus(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	cs := control.ControlStatus{
		ID:                uuid.New(),
		ControlID:         "mfa.enforcement",
		Timestamp:         time.Now().UTC(),
		Status:            "effective",
		Confidence:        "high",
		EvidenceIDs:       []uuid.UUID{uuid.New()},
		EvaluationDetails: "All MFA policies active",
	}

	if err := store.StoreControlStatus(ctx, cs); err != nil {
		t.Fatalf("StoreControlStatus failed: %v", err)
	}

	got, err := store.GetControlStatus(ctx, "mfa.enforcement")
	if err != nil {
		t.Fatalf("GetControlStatus failed: %v", err)
	}

	if got.ControlID != cs.ControlID {
		t.Errorf("expected ControlID %q, got %q", cs.ControlID, got.ControlID)
	}
	if got.Status != cs.Status {
		t.Errorf("expected Status %q, got %q", cs.Status, got.Status)
	}
}

func TestMemoryStore_GetControlStatus_NotFound(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	_, err := store.GetControlStatus(ctx, "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent control status, got nil")
	}
}

func TestMemoryStore_ControlStatus_ReturnsLatest(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	cs1 := control.ControlStatus{
		ID:        uuid.New(),
		ControlID: "mfa.enforcement",
		Timestamp: time.Now().UTC().Add(-time.Hour),
		Status:    "ineffective",
	}
	cs2 := control.ControlStatus{
		ID:        uuid.New(),
		ControlID: "mfa.enforcement",
		Timestamp: time.Now().UTC(),
		Status:    "effective",
	}

	if err := store.StoreControlStatus(ctx, cs1); err != nil {
		t.Fatalf("StoreControlStatus failed: %v", err)
	}
	if err := store.StoreControlStatus(ctx, cs2); err != nil {
		t.Fatalf("StoreControlStatus failed: %v", err)
	}

	got, err := store.GetControlStatus(ctx, "mfa.enforcement")
	if err != nil {
		t.Fatalf("GetControlStatus failed: %v", err)
	}
	if got.Status != "effective" {
		t.Errorf("expected latest status %q, got %q", "effective", got.Status)
	}
}

func TestMemoryStore_QueryHistory(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	now := time.Now().UTC()
	cs1 := control.ControlStatus{
		ID:        uuid.New(),
		ControlID: "mfa.enforcement",
		Timestamp: now.Add(-2 * time.Hour),
		Status:    "ineffective",
	}
	cs2 := control.ControlStatus{
		ID:        uuid.New(),
		ControlID: "mfa.enforcement",
		Timestamp: now.Add(-1 * time.Hour),
		Status:    "effective",
	}
	cs3 := control.ControlStatus{
		ID:        uuid.New(),
		ControlID: "mfa.enforcement",
		Timestamp: now,
		Status:    "effective",
	}

	for _, cs := range []control.ControlStatus{cs1, cs2, cs3} {
		if err := store.StoreControlStatus(ctx, cs); err != nil {
			t.Fatalf("StoreControlStatus failed: %v", err)
		}
	}

	// Query for the last 90 minutes (should include cs2 and cs3 only).
	from := now.Add(-90 * time.Minute)
	results, err := store.QueryHistory(ctx, "mfa.enforcement", from, now)
	if err != nil {
		t.Fatalf("QueryHistory failed: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("expected 2 results in time range, got %d", len(results))
	}
}

func TestMemoryStore_Attestation(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	ref := "sha256:abc123"
	envelope := []byte(`{"payloadType":"application/vnd.in-toto+json","payload":"..."}`)

	if err := store.StoreAttestation(ctx, ref, envelope); err != nil {
		t.Fatalf("StoreAttestation failed: %v", err)
	}

	got, err := store.GetAttestation(ctx, ref)
	if err != nil {
		t.Fatalf("GetAttestation failed: %v", err)
	}
	if string(got) != string(envelope) {
		t.Errorf("expected envelope %q, got %q", string(envelope), string(got))
	}
}

func TestMemoryStore_GetAttestation_NotFound(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	_, err := store.GetAttestation(ctx, "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent attestation, got nil")
	}
}

func TestMemoryStore_Schedule(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	sched := scheduler.Schedule{
		ID:               "sched-001",
		ControlID:        "mfa.enforcement",
		CronExpr:         "0 */6 * * *",
		Modules:          []string{"okta.mfa_policy"},
		MaxSafetyLevel:   "safe",
		EnvironmentScope: "production",
		Enabled:          true,
		CreatedAt:        time.Now().UTC(),
		UpdatedAt:        time.Now().UTC(),
	}

	// Store
	if err := store.StoreSchedule(ctx, sched); err != nil {
		t.Fatalf("StoreSchedule failed: %v", err)
	}

	// Get
	got, err := store.GetSchedule(ctx, "sched-001")
	if err != nil {
		t.Fatalf("GetSchedule failed: %v", err)
	}
	if got.ID != sched.ID {
		t.Errorf("expected ID %q, got %q", sched.ID, got.ID)
	}
	if got.CronExpr != sched.CronExpr {
		t.Errorf("expected CronExpr %q, got %q", sched.CronExpr, got.CronExpr)
	}

	// List
	list, err := store.ListSchedules(ctx)
	if err != nil {
		t.Fatalf("ListSchedules failed: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("expected 1 schedule, got %d", len(list))
	}

	// Delete
	if err := store.DeleteSchedule(ctx, "sched-001"); err != nil {
		t.Fatalf("DeleteSchedule failed: %v", err)
	}

	list, err = store.ListSchedules(ctx)
	if err != nil {
		t.Fatalf("ListSchedules after delete failed: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("expected 0 schedules after delete, got %d", len(list))
	}
}

func TestMemoryStore_GetSchedule_NotFound(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	_, err := store.GetSchedule(ctx, "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent schedule, got nil")
	}
}

func TestMemoryStore_ScheduleRun(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	run1 := scheduler.ScheduleRun{
		ID:          "run-001",
		ScheduleID:  "sched-001",
		StartedAt:   time.Now().UTC().Add(-time.Minute),
		CompletedAt: time.Now().UTC(),
		Status:      scheduler.RunStatusSuccess,
		ModuleResults: []scheduler.ModuleRunResult{
			{ModuleID: "okta.mfa_policy", Status: scheduler.ModuleStatusSuccess, EvidenceCount: 1},
		},
	}
	run2 := scheduler.ScheduleRun{
		ID:          "run-002",
		ScheduleID:  "sched-001",
		StartedAt:   time.Now().UTC(),
		CompletedAt: time.Now().UTC().Add(time.Minute),
		Status:      scheduler.RunStatusSuccess,
	}

	if err := store.StoreScheduleRun(ctx, run1); err != nil {
		t.Fatalf("StoreScheduleRun failed: %v", err)
	}
	if err := store.StoreScheduleRun(ctx, run2); err != nil {
		t.Fatalf("StoreScheduleRun failed: %v", err)
	}

	// List all runs
	runs, err := store.ListScheduleRuns(ctx, "sched-001", 0)
	if err != nil {
		t.Fatalf("ListScheduleRuns failed: %v", err)
	}
	if len(runs) != 2 {
		t.Errorf("expected 2 runs, got %d", len(runs))
	}

	// List with limit
	runs, err = store.ListScheduleRuns(ctx, "sched-001", 1)
	if err != nil {
		t.Fatalf("ListScheduleRuns with limit failed: %v", err)
	}
	if len(runs) != 1 {
		t.Errorf("expected 1 run with limit=1, got %d", len(runs))
	}

	// List runs for nonexistent schedule returns empty
	runs, err = store.ListScheduleRuns(ctx, "nonexistent", 0)
	if err != nil {
		t.Fatalf("ListScheduleRuns nonexistent failed: %v", err)
	}
	if len(runs) != 0 {
		t.Errorf("expected 0 runs for nonexistent schedule, got %d", len(runs))
	}
}

func TestMemoryStore_Close(t *testing.T) {
	store := NewMemoryStore()
	if err := store.Close(); err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
}

func TestMemoryStore_EvidenceCount(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	if store.EvidenceCount() != 0 {
		t.Errorf("expected 0 evidence count, got %d", store.EvidenceCount())
	}

	for i := 0; i < 5; i++ {
		ev := NewEvidence().WithControlID(fmt.Sprintf("ctrl.%d", i)).Build()
		if err := store.StoreEvidence(ctx, ev); err != nil {
			t.Fatalf("StoreEvidence failed: %v", err)
		}
	}

	if store.EvidenceCount() != 5 {
		t.Errorf("expected 5 evidence count, got %d", store.EvidenceCount())
	}
}

// Verify that MemoryStore satisfies the storage.Store interface at compile time.
func TestMemoryStore_ImplementsStoreInterface(t *testing.T) {
	var _ storage.Store = (*MemoryStore)(nil)
}

// ---------------------------------------------------------------------------
// Assertion tests
// ---------------------------------------------------------------------------

func TestAssertValidEvidence(t *testing.T) {
	ev := NewEvidence().Build()
	// Should not produce any test failures on a well-formed evidence.
	AssertValidEvidence(t, ev)
}

func TestAssertEvidenceCount(t *testing.T) {
	evs := []evidence.Evidence{
		NewEvidence().Build(),
		NewEvidence().Build(),
		NewEvidence().Build(),
	}
	// Should not fail when count matches.
	AssertEvidenceCount(t, evs, 3)
}

func TestAssertModuleRegistered(t *testing.T) {
	reg := module.NewRegistry()
	collector := NewStubCollector("test.collector")
	reg.RegisterCollector(collector)

	// Should not fail when module is registered.
	AssertModuleRegistered(t, reg, "test.collector")
}

// ---------------------------------------------------------------------------
// StubCollector tests
// ---------------------------------------------------------------------------

func TestStubCollector(t *testing.T) {
	c := NewStubCollector("mock.test")

	if c.ID() != "mock.test" {
		t.Errorf("expected ID %q, got %q", "mock.test", c.ID())
	}
	if c.Name() != "Stub Collector: mock.test" {
		t.Errorf("expected Name %q, got %q", "Stub Collector: mock.test", c.Name())
	}
	if c.Version() != "0.1.0" {
		t.Errorf("expected Version %q, got %q", "0.1.0", c.Version())
	}
	if c.SourceSystem() != "test" {
		t.Errorf("expected SourceSystem %q, got %q", "test", c.SourceSystem())
	}
	if len(c.EvidenceTypes()) != 1 || c.EvidenceTypes()[0] != 9999 {
		t.Errorf("expected EvidenceTypes [9999], got %v", c.EvidenceTypes())
	}
	if len(c.CredentialRequirements()) != 0 {
		t.Errorf("expected 0 CredentialRequirements, got %d", len(c.CredentialRequirements()))
	}

	// Collect should return evidence
	evs, err := c.Collect(context.Background(), nil)
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("expected 1 evidence, got %d", len(evs))
	}
	if evs[0].Metadata.Module.Name != "mock.test" {
		t.Errorf("expected module name %q, got %q", "mock.test", evs[0].Metadata.Module.Name)
	}
}

func TestStubCollector_NilCollectFunc(t *testing.T) {
	c := NewStubCollector("test.nil")
	c.CollectFunc = nil

	evs, err := c.Collect(context.Background(), nil)
	if err != nil {
		t.Fatalf("Collect with nil func failed: %v", err)
	}
	if evs != nil {
		t.Errorf("expected nil evidence, got %v", evs)
	}
}

func TestStubCollector_ImplementsInterface(t *testing.T) {
	var _ module.Collector = (*StubCollector)(nil)
}

// ---------------------------------------------------------------------------
// StubTester tests
// ---------------------------------------------------------------------------

func TestStubTester(t *testing.T) {
	tester := NewStubTester("mock.safety_test")

	if tester.ID() != "mock.safety_test" {
		t.Errorf("expected ID %q, got %q", "mock.safety_test", tester.ID())
	}
	if tester.Name() != "Stub Tester: mock.safety_test" {
		t.Errorf("expected Name %q, got %q", "Stub Tester: mock.safety_test", tester.Name())
	}
	if tester.Version() != "0.1.0" {
		t.Errorf("expected Version %q, got %q", "0.1.0", tester.Version())
	}
	if tester.SourceSystem() != "test" {
		t.Errorf("expected SourceSystem %q, got %q", "test", tester.SourceSystem())
	}
	if len(tester.EvidenceTypes()) != 1 || tester.EvidenceTypes()[0] != 9999 {
		t.Errorf("expected EvidenceTypes [9999], got %v", tester.EvidenceTypes())
	}
	if len(tester.CredentialRequirements()) != 0 {
		t.Errorf("expected 0 CredentialRequirements, got %d", len(tester.CredentialRequirements()))
	}
	if tester.SafetyClass() != module.SafetyClassSafe {
		t.Errorf("expected SafetyClass %q, got %q", module.SafetyClassSafe, tester.SafetyClass())
	}
	if tester.EnvironmentScope() != module.ScopeIsolated {
		t.Errorf("expected EnvironmentScope %q, got %q", module.ScopeIsolated, tester.EnvironmentScope())
	}
	if len(tester.PreFlightChecks()) != 1 || tester.PreFlightChecks()[0] != "check test environment" {
		t.Errorf("expected PreFlightChecks [\"check test environment\"], got %v", tester.PreFlightChecks())
	}
	if tester.CleanupProcedures() != nil {
		t.Errorf("expected nil CleanupProcedures, got %v", tester.CleanupProcedures())
	}

	// Test should return evidence with active verification confidence and transcript
	evs, err := tester.Test(context.Background(), nil)
	if err != nil {
		t.Fatalf("Test failed: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("expected 1 evidence, got %d", len(evs))
	}
	if evs[0].ConfidenceLevel != evidence.ActiveVerification {
		t.Errorf("expected confidence %q, got %q", evidence.ActiveVerification, evs[0].ConfidenceLevel)
	}
	if evs[0].TestTranscript == nil {
		t.Error("expected non-nil TestTranscript from tester")
	}
}

func TestStubTester_NilTestFunc(t *testing.T) {
	tester := NewStubTester("test.nil")
	tester.TestFunc = nil

	evs, err := tester.Test(context.Background(), nil)
	if err != nil {
		t.Fatalf("Test with nil func failed: %v", err)
	}
	if evs != nil {
		t.Errorf("expected nil evidence, got %v", evs)
	}
}

func TestStubTester_ImplementsInterface(t *testing.T) {
	var _ module.Tester = (*StubTester)(nil)
}

// ---------------------------------------------------------------------------
// RunCollectorTests / RunTesterTests tests
// ---------------------------------------------------------------------------

func TestRunCollectorTests(t *testing.T) {
	c := NewStubCollector("contract.collector")
	RunCollectorTests(t, c, nil)
}

func TestRunTesterTests(t *testing.T) {
	tester := NewStubTester("contract.tester")
	RunTesterTests(t, tester, nil)
}

// ---------------------------------------------------------------------------
// LoadFixture tests
// ---------------------------------------------------------------------------

func TestLoadFixture(t *testing.T) {
	data := LoadFixture(t, "okta_mfa_policy_response.json")
	if len(data) == 0 {
		t.Error("expected non-empty fixture data")
	}

	// Verify it's valid JSON.
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Errorf("fixture is not valid JSON: %v", err)
	}
}
