package scheduler

import (
	"context"
	"fmt"
	"sync"

	"github.com/robfig/cron/v3"
	"github.com/rs/zerolog/log"
)

// RunFunc is the function signature invoked when a scheduled job fires.
// It receives the schedule that triggered it and should return an error
// only if the run infrastructure itself fails (module-level failures are
// recorded in the run results, not here).
type RunFunc func(ctx context.Context, schedule Schedule) error

// entry tracks a schedule and its cron entry ID so we can remove it later.
type entry struct {
	schedule Schedule
	entryID  cron.EntryID
	runFn    RunFunc
}

// Scheduler manages cron-based scheduled jobs. It wraps robfig/cron with
// OCEAN-specific schedule management, supporting add/remove/list operations
// and per-schedule enable/disable.
type Scheduler struct {
	mu      sync.RWMutex
	cron    *cron.Cron
	entries map[string]*entry // keyed by schedule ID
}

// standardParser accepts both 5-field (minute-level) and 6-field (second-level)
// cron expressions, plus descriptors like @every and @hourly.
var standardParser = cron.NewParser(
	cron.SecondOptional | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor,
)

// NewScheduler creates a scheduler that accepts both standard 5-field
// and extended 6-field (with seconds) cron expressions.
func NewScheduler() *Scheduler {
	return &Scheduler{
		cron:    cron.New(cron.WithParser(standardParser)),
		entries: make(map[string]*entry),
	}
}

// Add registers a schedule with the scheduler. The runFn is invoked each time
// the cron expression fires (only if the schedule is enabled). If runFn is nil,
// the schedule is registered but will not execute (useful for list-only mode).
func (s *Scheduler) Add(schedule Schedule, runFn RunFunc) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.entries[schedule.ID]; exists {
		return fmt.Errorf("schedule %q already exists", schedule.ID)
	}

	// Validate the cron expression by parsing it.
	_, err := standardParser.Parse(schedule.CronExpr)
	if err != nil {
		return fmt.Errorf("invalid cron expression %q: %w", schedule.CronExpr, err)
	}

	e := &entry{
		schedule: schedule,
		runFn:    runFn,
	}

	// Only add to cron if enabled and has a run function.
	if schedule.Enabled && runFn != nil {
		sched := schedule // capture for closure
		entryID, err := s.cron.AddFunc(schedule.CronExpr, func() {
			ctx := context.Background()
			if err := runFn(ctx, sched); err != nil {
				log.Error().Err(err).Str("schedule_id", sched.ID).Msg("scheduled run failed")
			}
		})
		if err != nil {
			return fmt.Errorf("adding cron job for schedule %q: %w", schedule.ID, err)
		}
		e.entryID = entryID
	}

	s.entries[schedule.ID] = e
	return nil
}

// Remove unregisters a schedule by ID and removes it from the cron engine.
func (s *Scheduler) Remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, exists := s.entries[id]
	if !exists {
		return fmt.Errorf("schedule %q not found", id)
	}

	if e.entryID != 0 {
		s.cron.Remove(e.entryID)
	}
	delete(s.entries, id)
	return nil
}

// List returns all registered schedules.
func (s *Scheduler) List() []Schedule {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]Schedule, 0, len(s.entries))
	for _, e := range s.entries {
		result = append(result, e.schedule)
	}
	return result
}

// Start begins the cron scheduler. Jobs will fire according to their
// cron expressions after this call.
func (s *Scheduler) Start() {
	s.cron.Start()
}

// Stop gracefully stops the cron scheduler, waiting for running jobs to
// complete.
func (s *Scheduler) Stop() {
	ctx := s.cron.Stop()
	<-ctx.Done()
}

// LoadAll rehydrates schedules from a ScheduleStore, registering each
// enabled schedule with the provided run function.
func (s *Scheduler) LoadAll(ctx context.Context, store ScheduleStore, runFn RunFunc) error {
	schedules, err := store.ListSchedules(ctx)
	if err != nil {
		return fmt.Errorf("loading schedules from store: %w", err)
	}

	for _, sched := range schedules {
		if err := s.Add(sched, runFn); err != nil {
			log.Warn().Err(err).Str("schedule_id", sched.ID).Msg("failed to load schedule")
		}
	}
	return nil
}

// ScheduleStore is the subset of the storage interface needed by the scheduler
// to load persisted schedules.
type ScheduleStore interface {
	ListSchedules(ctx context.Context) ([]Schedule, error)
}
