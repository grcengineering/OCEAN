package scheduler

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grcengineering/ocean/internal/evidence"
	"github.com/grcengineering/ocean/internal/module"
)

// --- mock collector ---

type mockCollector struct {
	id       string
	evidence []evidence.Evidence
	err      error
}

func (m *mockCollector) ID() string             { return m.id }
func (m *mockCollector) Name() string            { return "Mock Collector " + m.id }
func (m *mockCollector) Version() string         { return "1.0.0" }
func (m *mockCollector) SourceSystem() string    { return "mock" }
func (m *mockCollector) EvidenceTypes() []int    { return []int{1001} }
func (m *mockCollector) CredentialRequirements() []module.CredentialReq { return nil }
func (m *mockCollector) Collect(_ context.Context, _ map[string]string) ([]evidence.Evidence, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.evidence, nil
}

// --- mock tester ---

type mockTester struct {
	id          string
	safetyClass module.SafetyClassification
	envScope    module.EnvironmentScope
	evidence    []evidence.Evidence
	err         error
}

func (m *mockTester) ID() string             { return m.id }
func (m *mockTester) Name() string            { return "Mock Tester " + m.id }
func (m *mockTester) Version() string         { return "1.0.0" }
func (m *mockTester) SourceSystem() string    { return "mock" }
func (m *mockTester) EvidenceTypes() []int    { return []int{2001} }
func (m *mockTester) CredentialRequirements() []module.CredentialReq { return nil }
func (m *mockTester) SafetyClass() module.SafetyClassification { return m.safetyClass }
func (m *mockTester) EnvironmentScope() module.EnvironmentScope { return m.envScope }
func (m *mockTester) PreFlightChecks() []string   { return nil }
func (m *mockTester) CleanupProcedures() []string  { return nil }
func (m *mockTester) Test(_ context.Context, _ map[string]string) ([]evidence.Evidence, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.evidence, nil
}

// --- mock store ---

type mockStore struct {
	evidence     []evidence.Evidence
	schedules    map[string]Schedule
	runs         map[string][]ScheduleRun
	storeErr     error
}

func newMockStore() *mockStore {
	return &mockStore{
		schedules: make(map[string]Schedule),
		runs:      make(map[string][]ScheduleRun),
	}
}

func (m *mockStore) StoreEvidence(_ context.Context, ev evidence.Evidence) error {
	if m.storeErr != nil {
		return m.storeErr
	}
	m.evidence = append(m.evidence, ev)
	return nil
}

func (m *mockStore) StoreScheduleRun(_ context.Context, run ScheduleRun) error {
	if m.storeErr != nil {
		return m.storeErr
	}
	m.runs[run.ScheduleID] = append(m.runs[run.ScheduleID], run)
	return nil
}

// --- helper to create evidence ---

func makeEvidence(controlID string) evidence.Evidence {
	return evidence.Evidence{
		ID:              uuid.New(),
		ControlID:       controlID,
		ClassUID:        1001,
		CategoryUID:     1,
		ActivityID:      1,
		Time:            time.Now(),
		ConfidenceLevel: evidence.PassiveObservation,
		StatusID:        evidence.StatusEffective,
		Status:          "effective",
	}
}

// --- tests ---

func TestRunnerRunSchedule_CollectorSuccess(t *testing.T) {
	reg := module.NewRegistry()
	ev := makeEvidence("ctrl-1")
	reg.RegisterCollector(&mockCollector{id: "mock-collector-a", evidence: []evidence.Evidence{ev}})

	store := newMockStore()
	executor := module.NewExecutor(reg)
	runner := NewRunner(reg, executor, store)

	sched := Schedule{
		ID:               "sched-1",
		ControlID:        "ctrl-1",
		Modules:          []string{"mock-collector-a"},
		MaxSafetyLevel:   "safe",
		EnvironmentScope: "production",
		Enabled:          true,
	}

	err := runner.RunSchedule(context.Background(), sched)
	require.NoError(t, err)

	// Evidence should be stored.
	assert.Len(t, store.evidence, 1)
	// A run record should be stored.
	assert.Len(t, store.runs["sched-1"], 1)
	assert.Equal(t, RunStatusSuccess, store.runs["sched-1"][0].Status)
}

func TestRunnerRunSchedule_CollectorFailure(t *testing.T) {
	reg := module.NewRegistry()
	reg.RegisterCollector(&mockCollector{id: "fail-collector", err: errors.New("API timeout")})

	store := newMockStore()
	executor := module.NewExecutor(reg)
	runner := NewRunner(reg, executor, store)

	sched := Schedule{
		ID:               "sched-fail",
		Modules:          []string{"fail-collector"},
		MaxSafetyLevel:   "safe",
		EnvironmentScope: "production",
		Enabled:          true,
	}

	err := runner.RunSchedule(context.Background(), sched)
	// RunSchedule should not return an error for module-level failures;
	// it logs them and stores a partial_failure/failure run.
	require.NoError(t, err)

	require.Len(t, store.runs["sched-fail"], 1)
	assert.Equal(t, RunStatusFailure, store.runs["sched-fail"][0].Status)
	require.Len(t, store.runs["sched-fail"][0].ModuleResults, 1)
	assert.Equal(t, ModuleStatusFailure, store.runs["sched-fail"][0].ModuleResults[0].Status)
	assert.Contains(t, store.runs["sched-fail"][0].ModuleResults[0].Error, "API timeout")
}

func TestRunnerRunSchedule_PartialFailure(t *testing.T) {
	reg := module.NewRegistry()
	ev := makeEvidence("ctrl-1")
	reg.RegisterCollector(&mockCollector{id: "good-collector", evidence: []evidence.Evidence{ev}})
	reg.RegisterCollector(&mockCollector{id: "bad-collector", err: errors.New("failed")})

	store := newMockStore()
	executor := module.NewExecutor(reg)
	runner := NewRunner(reg, executor, store)

	sched := Schedule{
		ID:               "sched-partial",
		Modules:          []string{"good-collector", "bad-collector"},
		MaxSafetyLevel:   "safe",
		EnvironmentScope: "production",
		Enabled:          true,
	}

	err := runner.RunSchedule(context.Background(), sched)
	require.NoError(t, err)

	// One evidence from good collector.
	assert.Len(t, store.evidence, 1)
	// Run should be partial_failure.
	require.Len(t, store.runs["sched-partial"], 1)
	assert.Equal(t, RunStatusPartialFailure, store.runs["sched-partial"][0].Status)
}

func TestRunnerRunSchedule_TesterSafetyEnforced(t *testing.T) {
	reg := module.NewRegistry()
	reg.RegisterTester(&mockTester{
		id:          "observable-tester",
		safetyClass: module.SafetyClassObservable,
		envScope:    module.ScopeProduction,
		evidence:    []evidence.Evidence{makeEvidence("ctrl-1")},
	})

	store := newMockStore()
	executor := module.NewExecutor(reg)
	runner := NewRunner(reg, executor, store)

	// Schedule only allows "safe" — observable tester should be skipped.
	sched := Schedule{
		ID:               "sched-safety",
		Modules:          []string{"observable-tester"},
		MaxSafetyLevel:   "safe",
		EnvironmentScope: "production",
		Enabled:          true,
	}

	err := runner.RunSchedule(context.Background(), sched)
	require.NoError(t, err)

	// Tester should be skipped due to safety level.
	require.Len(t, store.runs["sched-safety"], 1)
	require.Len(t, store.runs["sched-safety"][0].ModuleResults, 1)
	assert.Equal(t, ModuleStatusSkipped, store.runs["sched-safety"][0].ModuleResults[0].Status)
	assert.Contains(t, store.runs["sched-safety"][0].ModuleResults[0].Error, "safety level")
}

func TestRunnerRunSchedule_DestructiveTesterAlwaysBlocked(t *testing.T) {
	reg := module.NewRegistry()
	reg.RegisterTester(&mockTester{
		id:          "destructive-tester",
		safetyClass: module.SafetyClassDestructive,
		envScope:    module.ScopeIsolated,
		evidence:    []evidence.Evidence{makeEvidence("ctrl-1")},
	})

	store := newMockStore()
	executor := module.NewExecutor(reg)
	runner := NewRunner(reg, executor, store)

	// Even with max_safety_level=destructive, destructive testers are blocked
	// in scheduled mode.
	sched := Schedule{
		ID:               "sched-destructive",
		Modules:          []string{"destructive-tester"},
		MaxSafetyLevel:   "destructive",
		EnvironmentScope: "isolated",
		Enabled:          true,
	}

	err := runner.RunSchedule(context.Background(), sched)
	require.NoError(t, err)

	require.Len(t, store.runs["sched-destructive"], 1)
	require.Len(t, store.runs["sched-destructive"][0].ModuleResults, 1)
	assert.Equal(t, ModuleStatusSkipped, store.runs["sched-destructive"][0].ModuleResults[0].Status)
	assert.Contains(t, store.runs["sched-destructive"][0].ModuleResults[0].Error, "destructive")
}

func TestRunnerRunSchedule_EnvironmentScopeEnforced(t *testing.T) {
	reg := module.NewRegistry()
	reg.RegisterTester(&mockTester{
		id:          "reversible-tester",
		safetyClass: module.SafetyClassReversible,
		envScope:    module.ScopeStaging,
		evidence:    []evidence.Evidence{makeEvidence("ctrl-1")},
	})

	store := newMockStore()
	executor := module.NewExecutor(reg)
	runner := NewRunner(reg, executor, store)

	// Schedule targets production, but reversible testers can only run
	// in staging or isolated.
	sched := Schedule{
		ID:               "sched-scope",
		Modules:          []string{"reversible-tester"},
		MaxSafetyLevel:   "reversible",
		EnvironmentScope: "production",
		Enabled:          true,
	}

	err := runner.RunSchedule(context.Background(), sched)
	require.NoError(t, err)

	require.Len(t, store.runs["sched-scope"], 1)
	require.Len(t, store.runs["sched-scope"][0].ModuleResults, 1)
	assert.Equal(t, ModuleStatusSkipped, store.runs["sched-scope"][0].ModuleResults[0].Status)
}

func TestRunnerRunSchedule_TesterSuccess(t *testing.T) {
	reg := module.NewRegistry()
	reg.RegisterTester(&mockTester{
		id:          "safe-tester",
		safetyClass: module.SafetyClassSafe,
		envScope:    module.ScopeProduction,
		evidence:    []evidence.Evidence{makeEvidence("ctrl-1")},
	})

	store := newMockStore()
	executor := module.NewExecutor(reg)
	runner := NewRunner(reg, executor, store)

	sched := Schedule{
		ID:               "sched-tester-ok",
		Modules:          []string{"safe-tester"},
		MaxSafetyLevel:   "safe",
		EnvironmentScope: "production",
		Enabled:          true,
	}

	err := runner.RunSchedule(context.Background(), sched)
	require.NoError(t, err)

	assert.Len(t, store.evidence, 1)
	require.Len(t, store.runs["sched-tester-ok"], 1)
	assert.Equal(t, RunStatusSuccess, store.runs["sched-tester-ok"][0].Status)
}

func TestRunnerRunSchedule_ModuleNotFound(t *testing.T) {
	reg := module.NewRegistry()
	store := newMockStore()
	executor := module.NewExecutor(reg)
	runner := NewRunner(reg, executor, store)

	sched := Schedule{
		ID:               "sched-notfound",
		Modules:          []string{"nonexistent-module"},
		MaxSafetyLevel:   "safe",
		EnvironmentScope: "production",
		Enabled:          true,
	}

	err := runner.RunSchedule(context.Background(), sched)
	require.NoError(t, err)

	require.Len(t, store.runs["sched-notfound"], 1)
	assert.Equal(t, RunStatusFailure, store.runs["sched-notfound"][0].Status)
}

func TestSafetyLevelOrder(t *testing.T) {
	tests := []struct {
		maxLevel    string
		testerLevel module.SafetyClassification
		allowed     bool
	}{
		{"safe", module.SafetyClassSafe, true},
		{"safe", module.SafetyClassObservable, false},
		{"safe", module.SafetyClassReversible, false},
		{"safe", module.SafetyClassDestructive, false},
		{"observable", module.SafetyClassSafe, true},
		{"observable", module.SafetyClassObservable, true},
		{"observable", module.SafetyClassReversible, false},
		{"observable", module.SafetyClassDestructive, false},
		{"reversible", module.SafetyClassSafe, true},
		{"reversible", module.SafetyClassObservable, true},
		{"reversible", module.SafetyClassReversible, true},
		{"reversible", module.SafetyClassDestructive, false},
	}

	for _, tt := range tests {
		name := tt.maxLevel + "_allows_" + string(tt.testerLevel)
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tt.allowed, SafetyLevelAllows(tt.maxLevel, tt.testerLevel))
		})
	}
}

func TestCatchUpExecution(t *testing.T) {
	reg := module.NewRegistry()
	ev := makeEvidence("ctrl-1")
	reg.RegisterCollector(&mockCollector{id: "catch-collector", evidence: []evidence.Evidence{ev}})

	store := newMockStore()
	executor := module.NewExecutor(reg)
	runner := NewRunner(reg, executor, store)

	// Schedule with CatchUp enabled, last run was 2 hours ago,
	// cron expression is every 30 minutes — should trigger catch-up.
	twoHoursAgo := time.Now().Add(-2 * time.Hour)
	sched := Schedule{
		ID:               "sched-catchup",
		CronExpr:         "*/30 * * * *",
		Modules:          []string{"catch-collector"},
		MaxSafetyLevel:   "safe",
		EnvironmentScope: "production",
		Enabled:          true,
		CatchUp:          true,
		LastRun:          &twoHoursAgo,
	}

	needsCatchUp := runner.NeedsCatchUp(sched)
	assert.True(t, needsCatchUp, "schedule that missed its window should need catch-up")

	// Recent last run should not need catch-up. Use a last run time
	// just 1 second ago -- regardless of the cron expression, the next
	// fire is guaranteed to be in the future.
	recent := time.Now().Add(-1 * time.Second)
	sched.LastRun = &recent
	assert.False(t, runner.NeedsCatchUp(sched), "recently run schedule should not need catch-up")

	// CatchUp disabled should not need catch-up.
	sched.CatchUp = false
	sched.LastRun = &twoHoursAgo
	assert.False(t, runner.NeedsCatchUp(sched), "schedule with CatchUp disabled should not need catch-up")
}

func TestCatchUpNilLastRun(t *testing.T) {
	runner := NewRunner(module.NewRegistry(), nil, newMockStore())

	// A schedule that has never run and has CatchUp enabled should
	// need catch-up (first run).
	sched := Schedule{
		ID:       "sched-first",
		CronExpr: "*/30 * * * *",
		Modules:  []string{"mod-a"},
		CatchUp:  true,
		Enabled:  true,
	}

	assert.True(t, runner.NeedsCatchUp(sched), "schedule with nil LastRun and CatchUp enabled should need catch-up")
}
