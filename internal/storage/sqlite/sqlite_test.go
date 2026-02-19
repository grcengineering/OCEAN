package sqlite

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grcengineering/ocean/internal/control"
	"github.com/grcengineering/ocean/internal/evidence"
	"github.com/grcengineering/ocean/internal/scheduler"
	"github.com/grcengineering/ocean/internal/storage"
)

func testEvidence(controlID string) evidence.Evidence {
	return evidence.Evidence{
		ID:              uuid.New(),
		ControlID:       controlID,
		ClassUID:        3001,
		CategoryUID:     3,
		ActivityID:      1,
		Time:            time.Now().UTC().Truncate(time.Millisecond),
		ConfidenceLevel: evidence.PassiveObservation,
		Metadata: evidence.Metadata{
			Module: evidence.ModuleInfo{
				Name:    "mock.test",
				Version: "0.1.0",
				Type:    "collector",
			},
			Source: evidence.SourceInfo{
				System:     "mock",
				APIVersion: "v1",
				Endpoint:   "/api/v1/test",
			},
			ProcessedTime: time.Now().UTC().Truncate(time.Millisecond),
		},
		Observables: []evidence.Observable{
			{Type: "resource", Value: "mfa-policy"},
		},
		StatusID: evidence.StatusEffective,
		Status:   "effective",
		RawData:  json.RawMessage(`{"mfa_enforced": true}`),
		Findings: []evidence.Finding{},
		Attestation: evidence.AttestationRef{
			Type:            "collection",
			DSSEEnvelopeRef: "sha256:abc123",
			Digest:          "sha256:def456",
			Signer:          "test-key",
		},
	}
}

func openTestStore(t *testing.T) *Store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { s.Close() })
	return s
}

func TestOpen_CreatesDB(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "subdir", "test.db")
	s, err := Open(dbPath)
	require.NoError(t, err)
	require.NotNil(t, s)
	s.Close()
}

func TestStoreAndGetEvidence(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	ev := testEvidence("mock.test")

	err := s.StoreEvidence(ctx, ev)
	require.NoError(t, err)

	got, err := s.GetEvidence(ctx, ev.ID)
	require.NoError(t, err)
	require.NotNil(t, got)

	assert.Equal(t, ev.ID, got.ID)
	assert.Equal(t, ev.ControlID, got.ControlID)
	assert.Equal(t, ev.ClassUID, got.ClassUID)
	assert.Equal(t, ev.StatusID, got.StatusID)
	assert.Equal(t, ev.ConfidenceLevel, got.ConfidenceLevel)
	assert.Equal(t, ev.Metadata.Module.Name, got.Metadata.Module.Name)
	assert.Equal(t, ev.Attestation.DSSEEnvelopeRef, got.Attestation.DSSEEnvelopeRef)
}

func TestQueryEvidence_ByControlID(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	ev1 := testEvidence("control-a")
	ev2 := testEvidence("control-b")
	ev3 := testEvidence("control-a")

	require.NoError(t, s.StoreEvidence(ctx, ev1))
	require.NoError(t, s.StoreEvidence(ctx, ev2))
	require.NoError(t, s.StoreEvidence(ctx, ev3))

	results, err := s.QueryEvidence(ctx, storage.EvidenceQuery{ControlID: "control-a"})
	require.NoError(t, err)
	assert.Len(t, results, 2)
	for _, r := range results {
		assert.Equal(t, "control-a", r.ControlID)
	}
}

func TestQueryEvidence_ByTimeRange(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC()
	old := testEvidence("ctrl")
	old.Time = now.Add(-48 * time.Hour)
	recent := testEvidence("ctrl")
	recent.Time = now.Add(-1 * time.Hour)

	require.NoError(t, s.StoreEvidence(ctx, old))
	require.NoError(t, s.StoreEvidence(ctx, recent))

	from := now.Add(-24 * time.Hour)
	to := now
	results, err := s.QueryEvidence(ctx, storage.EvidenceQuery{
		FromTime: &from,
		ToTime:   &to,
	})
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, recent.ID, results[0].ID)
}

func TestQueryEvidence_Limit(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		require.NoError(t, s.StoreEvidence(ctx, testEvidence("ctrl")))
	}

	results, err := s.QueryEvidence(ctx, storage.EvidenceQuery{Limit: 2})
	require.NoError(t, err)
	assert.Len(t, results, 2)
}

func TestStoreAndGetAttestation(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	ref := "sha256:abc123def456"
	envelope := []byte(`{"payload": "test", "signatures": []}`)

	err := s.StoreAttestation(ctx, ref, envelope)
	require.NoError(t, err)

	got, err := s.GetAttestation(ctx, ref)
	require.NoError(t, err)
	assert.Equal(t, envelope, got)
}

func TestStoreAttestation_Idempotent(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	ref := "sha256:abc123"
	envelope1 := []byte(`{"v": 1}`)
	envelope2 := []byte(`{"v": 2}`)

	require.NoError(t, s.StoreAttestation(ctx, ref, envelope1))
	require.NoError(t, s.StoreAttestation(ctx, ref, envelope2))

	got, err := s.GetAttestation(ctx, ref)
	require.NoError(t, err)
	assert.Equal(t, envelope2, got)
}

func TestStoreAndGetControlStatus(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	cs := control.ControlStatus{
		ID:                uuid.New(),
		ControlID:         "mock.test",
		Timestamp:         time.Now().UTC().Truncate(time.Millisecond),
		Status:            "effective",
		Confidence:        "high",
		EvidenceIDs:       []uuid.UUID{uuid.New(), uuid.New()},
		EvaluationDetails: "all checks passed",
	}

	err := s.StoreControlStatus(ctx, cs)
	require.NoError(t, err)

	got, err := s.GetControlStatus(ctx, "mock.test")
	require.NoError(t, err)
	require.NotNil(t, got)

	assert.Equal(t, cs.ID, got.ID)
	assert.Equal(t, cs.Status, got.Status)
	assert.Equal(t, cs.Confidence, got.Confidence)
	assert.Len(t, got.EvidenceIDs, 2)
}

func TestQueryHistory(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC()
	for i := 0; i < 5; i++ {
		cs := control.ControlStatus{
			ID:          uuid.New(),
			ControlID:   "mock.test",
			Timestamp:   now.Add(time.Duration(-5+i) * 24 * time.Hour),
			Status:      "effective",
			Confidence:  "high",
			EvidenceIDs: []uuid.UUID{uuid.New()},
		}
		require.NoError(t, s.StoreControlStatus(ctx, cs))
	}

	from := now.Add(-3 * 24 * time.Hour)
	to := now
	results, err := s.QueryHistory(ctx, "mock.test", from, to)
	require.NoError(t, err)
	assert.Len(t, results, 3)

	// Should be ordered ASC by timestamp.
	for i := 1; i < len(results); i++ {
		assert.True(t, results[i].Timestamp.After(results[i-1].Timestamp))
	}
}

func TestGetEvidence_NotFound(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	_, err := s.GetEvidence(ctx, uuid.New())
	assert.Error(t, err)
}

// --- T190: PruneEvidence tests ---

func TestPruneEvidence_RemovesOldRecords(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC()

	// Insert old evidence (60 days ago).
	old := testEvidence("ctrl-old")
	old.Time = now.Add(-60 * 24 * time.Hour)
	require.NoError(t, s.StoreEvidence(ctx, old))

	// Insert recent evidence (1 hour ago).
	recent := testEvidence("ctrl-recent")
	recent.Time = now.Add(-1 * time.Hour)
	require.NoError(t, s.StoreEvidence(ctx, recent))

	// Prune evidence older than 30 days.
	pruned, err := s.PruneEvidence(ctx, 30*24*time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 1, pruned, "should have pruned 1 old record")

	// Verify old is gone, recent remains.
	_, err = s.GetEvidence(ctx, old.ID)
	assert.Error(t, err, "old evidence should be deleted")

	got, err := s.GetEvidence(ctx, recent.ID)
	require.NoError(t, err)
	assert.Equal(t, recent.ID, got.ID)
}

func TestPruneEvidence_NothingToPrune(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	// Insert only recent evidence.
	recent := testEvidence("ctrl")
	recent.Time = time.Now().UTC().Add(-1 * time.Hour)
	require.NoError(t, s.StoreEvidence(ctx, recent))

	pruned, err := s.PruneEvidence(ctx, 30*24*time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 0, pruned, "should have pruned 0 records")
}

func TestPruneEvidence_EmptyStore(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	pruned, err := s.PruneEvidence(ctx, 30*24*time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 0, pruned)
}

func TestPruneEvidence_PreservesReferencedAttestations(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC()

	// Store an attestation.
	ref := "sha256:keep-this"
	require.NoError(t, s.StoreAttestation(ctx, ref, []byte(`{"test": true}`)))

	// Insert old evidence referencing that attestation.
	old := testEvidence("ctrl")
	old.Time = now.Add(-60 * 24 * time.Hour)
	old.Attestation.DSSEEnvelopeRef = ref
	require.NoError(t, s.StoreEvidence(ctx, old))

	// Insert recent evidence referencing the same attestation.
	recent := testEvidence("ctrl")
	recent.Time = now.Add(-1 * time.Hour)
	recent.Attestation.DSSEEnvelopeRef = ref
	require.NoError(t, s.StoreEvidence(ctx, recent))

	// Prune old evidence.
	pruned, err := s.PruneEvidence(ctx, 30*24*time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 1, pruned)

	// Attestation should still exist because recent evidence references it.
	envelope, err := s.GetAttestation(ctx, ref)
	require.NoError(t, err)
	assert.NotNil(t, envelope)
}

// --- T190: PruneOldEvidence tests (transactional with orphaned attestation cleanup) ---

func TestPruneOldEvidence_RemovesOldRecords(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC()

	// Insert old evidence (60 days ago).
	old := testEvidence("ctrl-old")
	old.Time = now.Add(-60 * 24 * time.Hour)
	require.NoError(t, s.StoreEvidence(ctx, old))

	// Insert recent evidence (1 hour ago).
	recent := testEvidence("ctrl-recent")
	recent.Time = now.Add(-1 * time.Hour)
	require.NoError(t, s.StoreEvidence(ctx, recent))

	// Prune evidence older than 30 days.
	pruned, err := s.PruneOldEvidence(ctx, 30*24*time.Hour)
	require.NoError(t, err)
	assert.Equal(t, int64(1), pruned, "should have pruned 1 old record")

	// Verify old is gone, recent remains.
	_, err = s.GetEvidence(ctx, old.ID)
	assert.Error(t, err, "old evidence should be deleted")

	got, err := s.GetEvidence(ctx, recent.ID)
	require.NoError(t, err)
	assert.Equal(t, recent.ID, got.ID)
}

func TestPruneOldEvidence_NothingToPrune(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	// Insert only recent evidence.
	recent := testEvidence("ctrl")
	recent.Time = time.Now().UTC().Add(-1 * time.Hour)
	require.NoError(t, s.StoreEvidence(ctx, recent))

	pruned, err := s.PruneOldEvidence(ctx, 30*24*time.Hour)
	require.NoError(t, err)
	assert.Equal(t, int64(0), pruned, "should have pruned 0 records")
}

func TestPruneOldEvidence_EmptyStore(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	pruned, err := s.PruneOldEvidence(ctx, 30*24*time.Hour)
	require.NoError(t, err)
	assert.Equal(t, int64(0), pruned)
}

func TestPruneOldEvidence_CleansOrphanedAttestations(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC()

	// Store an attestation only referenced by old evidence.
	orphanRef := "sha256:orphan-ref"
	require.NoError(t, s.StoreAttestation(ctx, orphanRef, []byte(`{"orphan": true}`)))

	// Insert old evidence referencing that attestation.
	old := testEvidence("ctrl")
	old.Time = now.Add(-60 * 24 * time.Hour)
	old.Attestation.DSSEEnvelopeRef = orphanRef
	require.NoError(t, s.StoreEvidence(ctx, old))

	// Prune old evidence.
	pruned, err := s.PruneOldEvidence(ctx, 30*24*time.Hour)
	require.NoError(t, err)
	assert.Equal(t, int64(1), pruned)

	// The orphaned attestation should be removed since no evidence references it.
	_, err = s.GetAttestation(ctx, orphanRef)
	assert.Error(t, err, "orphaned attestation should be deleted")
}

func TestPruneOldEvidence_PreservesReferencedAttestations(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC()

	// Store an attestation referenced by both old and recent evidence.
	sharedRef := "sha256:shared-ref"
	require.NoError(t, s.StoreAttestation(ctx, sharedRef, []byte(`{"shared": true}`)))

	// Insert old evidence referencing the attestation.
	old := testEvidence("ctrl")
	old.Time = now.Add(-60 * 24 * time.Hour)
	old.Attestation.DSSEEnvelopeRef = sharedRef
	require.NoError(t, s.StoreEvidence(ctx, old))

	// Insert recent evidence referencing the same attestation.
	recent := testEvidence("ctrl")
	recent.Time = now.Add(-1 * time.Hour)
	recent.Attestation.DSSEEnvelopeRef = sharedRef
	require.NoError(t, s.StoreEvidence(ctx, recent))

	// Prune old evidence.
	pruned, err := s.PruneOldEvidence(ctx, 30*24*time.Hour)
	require.NoError(t, err)
	assert.Equal(t, int64(1), pruned)

	// The attestation should still exist because recent evidence references it.
	envelope, err := s.GetAttestation(ctx, sharedRef)
	require.NoError(t, err)
	assert.NotNil(t, envelope)
}

func TestPruneOldEvidence_MultipleOldRecords(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC()

	// Insert 3 old evidence records.
	for i := 0; i < 3; i++ {
		old := testEvidence("ctrl")
		old.Time = now.Add(-60 * 24 * time.Hour)
		require.NoError(t, s.StoreEvidence(ctx, old))
	}

	// Insert 2 recent evidence records.
	for i := 0; i < 2; i++ {
		recent := testEvidence("ctrl")
		recent.Time = now.Add(-1 * time.Hour)
		require.NoError(t, s.StoreEvidence(ctx, recent))
	}

	pruned, err := s.PruneOldEvidence(ctx, 30*24*time.Hour)
	require.NoError(t, err)
	assert.Equal(t, int64(3), pruned, "should have pruned 3 old records")

	// Verify only 2 remain.
	results, err := s.QueryEvidence(ctx, storage.EvidenceQuery{ControlID: "ctrl"})
	require.NoError(t, err)
	assert.Len(t, results, 2)
}

// --- Schedule CRUD tests ---

func testSchedule(id string) scheduler.Schedule {
	now := time.Now().UTC().Truncate(time.Millisecond)
	lastRun := now.Add(-1 * time.Hour)
	nextRun := now.Add(1 * time.Hour)
	return scheduler.Schedule{
		ID:               id,
		ControlID:        "ctrl-" + id,
		CronExpr:         "*/5 * * * *",
		Modules:          []string{"mock.test", "mock.network"},
		MaxSafetyLevel:   "safe",
		EnvironmentScope: "production",
		Enabled:          true,
		CatchUp:          false,
		LastRun:          &lastRun,
		NextRun:          &nextRun,
		CreatedAt:        now,
	}
}

func TestStoreSchedule_RoundTrip(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	sched := testSchedule("sched-001")

	err := s.StoreSchedule(ctx, sched)
	require.NoError(t, err)

	got, err := s.GetSchedule(ctx, "sched-001")
	require.NoError(t, err)
	require.NotNil(t, got)

	assert.Equal(t, sched.ID, got.ID)
	assert.Equal(t, sched.ControlID, got.ControlID)
	assert.Equal(t, sched.CronExpr, got.CronExpr)
	assert.Equal(t, sched.Modules, got.Modules)
	assert.Equal(t, sched.MaxSafetyLevel, got.MaxSafetyLevel)
	assert.Equal(t, sched.EnvironmentScope, got.EnvironmentScope)
	assert.Equal(t, sched.Enabled, got.Enabled)
	assert.Equal(t, sched.CatchUp, got.CatchUp)
	assert.NotNil(t, got.LastRun)
	assert.NotNil(t, got.NextRun)
	assert.Equal(t, sched.LastRun.Format(time.RFC3339Nano), got.LastRun.Format(time.RFC3339Nano))
	assert.Equal(t, sched.NextRun.Format(time.RFC3339Nano), got.NextRun.Format(time.RFC3339Nano))
	assert.Equal(t, sched.CreatedAt.Format(time.RFC3339Nano), got.CreatedAt.Format(time.RFC3339Nano))
	// UpdatedAt is set by StoreSchedule to time.Now(), so just verify it's non-zero.
	assert.False(t, got.UpdatedAt.IsZero())
}

func TestListSchedules_Empty(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	results, err := s.ListSchedules(ctx)
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestListSchedules_Multiple(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Millisecond)
	for i, id := range []string{"sched-a", "sched-b", "sched-c"} {
		sched := testSchedule(id)
		// Stagger created_at so ordering is deterministic.
		sched.CreatedAt = now.Add(time.Duration(i) * time.Second)
		require.NoError(t, s.StoreSchedule(ctx, sched))
	}

	results, err := s.ListSchedules(ctx)
	require.NoError(t, err)
	require.Len(t, results, 3)

	// ListSchedules orders by created_at ASC.
	assert.Equal(t, "sched-a", results[0].ID)
	assert.Equal(t, "sched-b", results[1].ID)
	assert.Equal(t, "sched-c", results[2].ID)
}

func TestDeleteSchedule_Success(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	sched := testSchedule("sched-del")
	require.NoError(t, s.StoreSchedule(ctx, sched))

	err := s.DeleteSchedule(ctx, "sched-del")
	require.NoError(t, err)

	_, err = s.GetSchedule(ctx, "sched-del")
	assert.Error(t, err, "GetSchedule should return error after deletion")
}

func TestDeleteSchedule_NotFound(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	err := s.DeleteSchedule(ctx, "nonexistent-id")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestStoreScheduleRun_RoundTrip(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	// Must create the schedule first for the run to reference.
	sched := testSchedule("sched-run")
	require.NoError(t, s.StoreSchedule(ctx, sched))

	now := time.Now().UTC().Truncate(time.Millisecond)
	run := scheduler.ScheduleRun{
		ID:          "run-001",
		ScheduleID:  "sched-run",
		StartedAt:   now.Add(-5 * time.Minute),
		CompletedAt: now,
		Status:      scheduler.RunStatusSuccess,
		ModuleResults: []scheduler.ModuleRunResult{
			{ModuleID: "mock.test", Status: scheduler.ModuleStatusSuccess, EvidenceCount: 3},
			{ModuleID: "mock.network", Status: scheduler.ModuleStatusFailure, EvidenceCount: 0, Error: "timeout"},
		},
		Error: "",
	}

	err := s.StoreScheduleRun(ctx, run)
	require.NoError(t, err)

	runs, err := s.ListScheduleRuns(ctx, "sched-run", 10)
	require.NoError(t, err)
	require.Len(t, runs, 1)

	got := runs[0]
	assert.Equal(t, run.ID, got.ID)
	assert.Equal(t, run.ScheduleID, got.ScheduleID)
	assert.Equal(t, run.StartedAt.Format(time.RFC3339Nano), got.StartedAt.Format(time.RFC3339Nano))
	assert.Equal(t, run.CompletedAt.Format(time.RFC3339Nano), got.CompletedAt.Format(time.RFC3339Nano))
	assert.Equal(t, run.Status, got.Status)
	assert.Equal(t, run.Error, got.Error)
	require.Len(t, got.ModuleResults, 2)
	assert.Equal(t, "mock.test", got.ModuleResults[0].ModuleID)
	assert.Equal(t, 3, got.ModuleResults[0].EvidenceCount)
	assert.Equal(t, "timeout", got.ModuleResults[1].Error)
}

func TestListScheduleRuns_DefaultLimit(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	sched := testSchedule("sched-limit")
	require.NoError(t, s.StoreSchedule(ctx, sched))

	now := time.Now().UTC().Truncate(time.Millisecond)
	// Insert 15 runs.
	for i := 0; i < 15; i++ {
		run := scheduler.ScheduleRun{
			ID:          fmt.Sprintf("run-%03d", i),
			ScheduleID:  "sched-limit",
			StartedAt:   now.Add(time.Duration(i) * time.Minute),
			CompletedAt: now.Add(time.Duration(i)*time.Minute + 30*time.Second),
			Status:      scheduler.RunStatusSuccess,
		}
		require.NoError(t, s.StoreScheduleRun(ctx, run))
	}

	// Pass 0 as limit -> should default to 10.
	runs, err := s.ListScheduleRuns(ctx, "sched-limit", 0)
	require.NoError(t, err)
	assert.Len(t, runs, 10)

	// Runs should be ordered by started_at DESC (most recent first).
	for i := 1; i < len(runs); i++ {
		assert.True(t, runs[i-1].StartedAt.After(runs[i].StartedAt),
			"runs should be ordered most recent first")
	}
}

func TestDeleteSchedule_CascadesRuns(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	sched := testSchedule("sched-cascade")
	require.NoError(t, s.StoreSchedule(ctx, sched))

	now := time.Now().UTC().Truncate(time.Millisecond)
	for i := 0; i < 3; i++ {
		run := scheduler.ScheduleRun{
			ID:          fmt.Sprintf("cascade-run-%d", i),
			ScheduleID:  "sched-cascade",
			StartedAt:   now.Add(time.Duration(i) * time.Minute),
			CompletedAt: now.Add(time.Duration(i)*time.Minute + 10*time.Second),
			Status:      scheduler.RunStatusSuccess,
		}
		require.NoError(t, s.StoreScheduleRun(ctx, run))
	}

	// Verify runs exist before delete.
	runs, err := s.ListScheduleRuns(ctx, "sched-cascade", 10)
	require.NoError(t, err)
	require.Len(t, runs, 3)

	// Delete the schedule - should cascade to runs.
	err = s.DeleteSchedule(ctx, "sched-cascade")
	require.NoError(t, err)

	// Schedule should be gone.
	_, err = s.GetSchedule(ctx, "sched-cascade")
	assert.Error(t, err)

	// Runs should also be gone.
	runs, err = s.ListScheduleRuns(ctx, "sched-cascade", 10)
	require.NoError(t, err)
	assert.Empty(t, runs)
}

// Compile-time check that *Store satisfies storage.Store.
var _ storage.Store = (*Store)(nil)
