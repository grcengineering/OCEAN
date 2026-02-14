package scheduler

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/grcengineering/ocean/internal/evidence"
	"github.com/grcengineering/ocean/internal/module"
)

// safetyOrder defines the severity ordering of safety classifications.
// Lower index = less dangerous.
var safetyOrder = map[string]int{
	"safe":        0,
	"observable":  1,
	"reversible":  2,
	"destructive": 3,
}

// SafetyLevelAllows returns true if the maxLevel permits executing a tester
// with the given classification. Destructive is never allowed regardless of
// maxLevel (enforced separately).
func SafetyLevelAllows(maxLevel string, classification module.SafetyClassification) bool {
	maxIdx, ok := safetyOrder[maxLevel]
	if !ok {
		return false
	}
	classIdx, ok := safetyOrder[string(classification)]
	if !ok {
		return false
	}
	return classIdx <= maxIdx
}

// EvidenceStorer is the subset of the storage interface the runner needs to
// persist evidence and run records.
type EvidenceStorer interface {
	StoreEvidence(ctx context.Context, ev evidence.Evidence) error
	StoreScheduleRun(ctx context.Context, run ScheduleRun) error
}

// Runner executes scheduled jobs, coordinating the registry, executor, and
// store. It handles safety enforcement, partial failure recording, and
// catch-up detection.
type Runner struct {
	Registry *module.Registry
	Executor *module.Executor
	Store    EvidenceStorer
}

// NewRunner creates a runner backed by the given registry, executor, and store.
func NewRunner(registry *module.Registry, executor *module.Executor, store EvidenceStorer) *Runner {
	return &Runner{
		Registry: registry,
		Executor: executor,
		Store:    store,
	}
}

// RunSchedule executes all modules configured in the schedule, stores the
// resulting evidence, and records a ScheduleRun. Module-level failures are
// captured in the run results rather than returned as errors. An error is
// returned only if the run infrastructure itself fails (e.g., cannot store
// the run record).
func (r *Runner) RunSchedule(ctx context.Context, schedule Schedule) error {
	startedAt := time.Now()
	runID := uuid.New().String()

	results := make([]ModuleRunResult, 0, len(schedule.Modules))
	var successCount, failCount, skipCount int

	for _, modID := range schedule.Modules {
		result := r.executeModule(ctx, modID, schedule)
		results = append(results, result)

		switch result.Status {
		case ModuleStatusSuccess:
			successCount++
		case ModuleStatusFailure:
			failCount++
		case ModuleStatusSkipped:
			skipCount++
		}
	}

	// Determine overall run status.
	var runStatus string
	switch {
	case failCount == 0 && skipCount == 0:
		runStatus = RunStatusSuccess
	case successCount > 0:
		runStatus = RunStatusPartialFailure
	default:
		runStatus = RunStatusFailure
	}

	run := ScheduleRun{
		ID:            runID,
		ScheduleID:    schedule.ID,
		StartedAt:     startedAt,
		CompletedAt:   time.Now(),
		Status:        runStatus,
		ModuleResults: results,
	}

	if err := r.Store.StoreScheduleRun(ctx, run); err != nil {
		return fmt.Errorf("storing schedule run: %w", err)
	}

	log.Info().
		Str("schedule_id", schedule.ID).
		Str("run_id", runID).
		Str("status", runStatus).
		Int("success", successCount).
		Int("failed", failCount).
		Int("skipped", skipCount).
		Msg("scheduled run completed")

	return nil
}

// executeModule runs a single module within a scheduled execution. It detects
// whether the module is a collector or tester and applies appropriate safety
// checks for testers.
func (r *Runner) executeModule(ctx context.Context, modID string, schedule Schedule) ModuleRunResult {
	result := ModuleRunResult{ModuleID: modID}

	// Look up the module to determine its type.
	mod, err := r.Registry.GetModule(modID)
	if err != nil {
		result.Status = ModuleStatusFailure
		result.Error = fmt.Sprintf("module not found: %s", err)
		return result
	}

	// Check if it's a tester by attempting to get it from the tester registry.
	if tester, tErr := r.Registry.GetTester(modID); tErr == nil {
		return r.executeTester(ctx, tester, schedule, result)
	}

	// It's a collector.
	_ = mod // already validated existence
	return r.executeCollector(ctx, modID, schedule, result)
}

// executeCollector runs a collector module and stores the evidence.
func (r *Runner) executeCollector(ctx context.Context, modID string, schedule Schedule, result ModuleRunResult) ModuleRunResult {
	evidences, err := r.Executor.ExecuteCollector(ctx, modID, nil)
	if err != nil {
		result.Status = ModuleStatusFailure
		result.Error = err.Error()
		log.Error().Err(err).Str("module_id", modID).Str("schedule_id", schedule.ID).Msg("collector execution failed")
		return result
	}

	// Store each evidence record.
	for _, ev := range evidences {
		if err := r.Store.StoreEvidence(ctx, ev); err != nil {
			log.Error().Err(err).Str("module_id", modID).Msg("failed to store evidence")
		}
	}

	result.Status = ModuleStatusSuccess
	result.EvidenceCount = len(evidences)
	return result
}

// executeTester runs a tester module with safety enforcement.
func (r *Runner) executeTester(ctx context.Context, tester module.Tester, schedule Schedule, result ModuleRunResult) ModuleRunResult {
	modID := tester.ID()

	// T123: Refuse destructive tests in scheduled mode entirely.
	if tester.SafetyClass() == module.SafetyClassDestructive {
		result.Status = ModuleStatusSkipped
		result.Error = "destructive testers cannot run in scheduled mode"
		log.Warn().Str("module_id", modID).Msg("skipped destructive tester in scheduled mode")
		return result
	}

	// T123: Enforce MaxSafetyLevel from schedule config.
	if !SafetyLevelAllows(schedule.MaxSafetyLevel, tester.SafetyClass()) {
		result.Status = ModuleStatusSkipped
		result.Error = fmt.Sprintf(
			"tester safety level %q exceeds schedule max safety level %q",
			tester.SafetyClass(), schedule.MaxSafetyLevel,
		)
		log.Warn().
			Str("module_id", modID).
			Str("tester_safety", string(tester.SafetyClass())).
			Str("max_safety", schedule.MaxSafetyLevel).
			Msg("skipped tester due to safety level restriction")
		return result
	}

	// T123: Enforce EnvironmentScope from schedule config.
	targetEnv := module.EnvironmentScope(schedule.EnvironmentScope)
	if !module.CanRunInEnvironment(tester.SafetyClass(), targetEnv) {
		result.Status = ModuleStatusSkipped
		result.Error = fmt.Sprintf(
			"tester %q (safety: %s) cannot run in %s environment",
			modID, tester.SafetyClass(), schedule.EnvironmentScope,
		)
		log.Warn().
			Str("module_id", modID).
			Str("environment", schedule.EnvironmentScope).
			Msg("skipped tester due to environment scope")
		return result
	}

	// Build a test config that uses a schedule-aware authorizer.
	// In scheduled mode, we pre-authorize based on the schedule's MaxSafetyLevel.
	testCfg := &module.TestConfig{
		TargetEnvironment: targetEnv,
		Authorizer:        &scheduleAuthorizer{maxLevel: schedule.MaxSafetyLevel},
	}

	evidences, err := r.Executor.ExecuteTester(ctx, modID, testCfg)
	if err != nil {
		result.Status = ModuleStatusFailure
		result.Error = err.Error()
		log.Error().Err(err).Str("module_id", modID).Str("schedule_id", schedule.ID).Msg("tester execution failed")
		return result
	}

	// Store each evidence record.
	for _, ev := range evidences {
		if err := r.Store.StoreEvidence(ctx, ev); err != nil {
			log.Error().Err(err).Str("module_id", modID).Msg("failed to store evidence")
		}
	}

	result.Status = ModuleStatusSuccess
	result.EvidenceCount = len(evidences)
	return result
}

// NeedsCatchUp determines if a schedule missed its execution window while
// offline. If the schedule has CatchUp enabled and lastRun + cronInterval < now,
// it needs a catch-up execution.
func (r *Runner) NeedsCatchUp(schedule Schedule) bool {
	if !schedule.CatchUp {
		return false
	}

	// If the schedule has never run, it needs catch-up (first run).
	if schedule.LastRun == nil {
		return true
	}

	// Parse the cron expression to determine the next expected run.
	cronSched, err := standardParser.Parse(schedule.CronExpr)
	if err != nil {
		log.Error().Err(err).Str("schedule_id", schedule.ID).Msg("failed to parse cron for catch-up check")
		return false
	}

	nextExpected := cronSched.Next(*schedule.LastRun)
	return time.Now().After(nextExpected)
}

// scheduleAuthorizer pre-authorizes testers based on the schedule's
// MaxSafetyLevel. This avoids interactive prompts during automated execution.
type scheduleAuthorizer struct {
	maxLevel string
}

func (a *scheduleAuthorizer) Authorize(_ string, classification module.SafetyClassification, _ module.AuthorizationLevel) (bool, error) {
	return SafetyLevelAllows(a.maxLevel, classification), nil
}
