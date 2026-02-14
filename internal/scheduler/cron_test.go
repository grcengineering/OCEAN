package scheduler

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewScheduler(t *testing.T) {
	s := NewScheduler()
	require.NotNil(t, s)

	// Should start with no schedules.
	assert.Empty(t, s.List())
}

func TestSchedulerAddAndList(t *testing.T) {
	s := NewScheduler()

	sched := Schedule{
		ID:               "sched-1",
		CronExpr:         "*/5 * * * *",
		Modules:          []string{"mock-collector-a"},
		MaxSafetyLevel:   "safe",
		EnvironmentScope: "production",
		Enabled:          true,
	}

	err := s.Add(sched, nil) // nil runner func = no-op for listing test
	require.NoError(t, err)

	list := s.List()
	require.Len(t, list, 1)
	assert.Equal(t, "sched-1", list[0].ID)
}

func TestSchedulerAddInvalidCron(t *testing.T) {
	s := NewScheduler()

	sched := Schedule{
		ID:       "bad-cron",
		CronExpr: "not a cron expression",
		Modules:  []string{"mod-a"},
		Enabled:  true,
	}

	err := s.Add(sched, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid cron expression")
}

func TestSchedulerRemove(t *testing.T) {
	s := NewScheduler()

	sched := Schedule{
		ID:       "sched-rm",
		CronExpr: "*/5 * * * *",
		Modules:  []string{"mod-a"},
		Enabled:  true,
	}

	err := s.Add(sched, nil)
	require.NoError(t, err)
	require.Len(t, s.List(), 1)

	err = s.Remove("sched-rm")
	require.NoError(t, err)
	assert.Empty(t, s.List())
}

func TestSchedulerRemoveNotFound(t *testing.T) {
	s := NewScheduler()

	err := s.Remove("nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestSchedulerDuplicateAdd(t *testing.T) {
	s := NewScheduler()

	sched := Schedule{
		ID:       "dup",
		CronExpr: "*/5 * * * *",
		Modules:  []string{"mod-a"},
		Enabled:  true,
	}

	err := s.Add(sched, nil)
	require.NoError(t, err)

	// Adding the same ID again should error.
	err = s.Add(sched, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestSchedulerStartStop(t *testing.T) {
	s := NewScheduler()

	// Start and stop should not panic even with no schedules.
	s.Start()
	s.Stop()
}

func TestSchedulerJobExecution(t *testing.T) {
	s := NewScheduler()

	var mu sync.Mutex
	var execCount int

	sched := Schedule{
		ID:       "exec-test",
		CronExpr: "* * * * * *", // every second (with seconds enabled)
		Modules:  []string{"mod-a"},
		Enabled:  true,
	}

	runFn := func(ctx context.Context, schedule Schedule) error {
		mu.Lock()
		defer mu.Unlock()
		execCount++
		return nil
	}

	err := s.Add(sched, runFn)
	require.NoError(t, err)

	s.Start()
	// Wait enough time for at least one execution.
	time.Sleep(2500 * time.Millisecond)
	s.Stop()

	mu.Lock()
	count := execCount
	mu.Unlock()

	assert.GreaterOrEqual(t, count, 1, "scheduler should have executed at least once")
}

func TestSchedulerDisabledScheduleNotExecuted(t *testing.T) {
	s := NewScheduler()

	var mu sync.Mutex
	var execCount int

	sched := Schedule{
		ID:       "disabled-test",
		CronExpr: "* * * * * *",
		Modules:  []string{"mod-a"},
		Enabled:  false,
	}

	runFn := func(ctx context.Context, schedule Schedule) error {
		mu.Lock()
		defer mu.Unlock()
		execCount++
		return nil
	}

	err := s.Add(sched, runFn)
	require.NoError(t, err)

	s.Start()
	time.Sleep(2500 * time.Millisecond)
	s.Stop()

	mu.Lock()
	count := execCount
	mu.Unlock()

	assert.Equal(t, 0, count, "disabled schedule should not execute")
}
