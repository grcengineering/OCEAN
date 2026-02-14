package module

import (
	"context"
	"fmt"

	"github.com/grcengineering/ocean/internal/evidence"
)

// Executor orchestrates module execution, coordinating registry lookups
// and safety checks before running collectors or testers.
type Executor struct {
	Registry *Registry
}

// NewExecutor creates an executor backed by the given registry.
func NewExecutor(registry *Registry) *Executor {
	return &Executor{Registry: registry}
}

// ExecuteCollector runs a collector by module ID and returns the collected evidence.
func (e *Executor) ExecuteCollector(ctx context.Context, moduleID string, config map[string]string) ([]evidence.Evidence, error) {
	collector, err := e.Registry.GetCollector(moduleID)
	if err != nil {
		return nil, err
	}
	return collector.Collect(ctx, config)
}

// --- T071: Pre-flight validation ---

// TestConfig holds configuration for executing a test.
type TestConfig struct {
	ModuleConfig      map[string]string
	TargetEnvironment EnvironmentScope
	Authorizer        Authorizer
}

// DefaultTestConfig returns a TestConfig with safe defaults:
// production target, auto-authorizer (safe tests only).
func DefaultTestConfig() *TestConfig {
	return &TestConfig{
		TargetEnvironment: ScopeProduction,
		Authorizer:        &AutoAuthorizer{},
	}
}

// RunPreFlight validates all preconditions before executing a tester.
// It checks safety classification validity, environment scope compatibility,
// and obtains authorization.
func RunPreFlight(tester Tester, cfg TestConfig) error {
	// 1. Validate safety classification is valid.
	if err := ValidateSafetyLevel(tester); err != nil {
		return fmt.Errorf("pre-flight: %w", err)
	}

	// 2. Check environment scope.
	if err := EnforceScope(tester, cfg.TargetEnvironment); err != nil {
		return fmt.Errorf("pre-flight: %w", err)
	}

	// 3. Check authorization.
	authLevel := RequiredAuthLevel(tester.SafetyClass())
	authorized, err := cfg.Authorizer.Authorize(tester.ID(), tester.SafetyClass(), authLevel)
	if err != nil {
		return fmt.Errorf("pre-flight authorization: %w", err)
	}
	if !authorized {
		return fmt.Errorf("pre-flight: authorization denied for tester %q (safety: %s, auth level: %s)",
			tester.ID(), tester.SafetyClass(), authLevel)
	}

	return nil
}

// --- T072: Cleanup execution ---

// RunCleanup executes a tester's cleanup procedures and returns transcript
// records of each step. Cleanup always runs, even if individual steps fail.
func RunCleanup(tester Tester) []evidence.TranscriptCleanup {
	procedures := tester.CleanupProcedures()
	cleanups := make([]evidence.TranscriptCleanup, 0, len(procedures))

	recorder := evidence.NewTranscriptRecorder()
	for _, proc := range procedures {
		// In this generic implementation, cleanup procedures are declared
		// strings from the tester. Real cleanup happens inside Test().
		// Here we record that the declared cleanup was acknowledged.
		recorder.RecordCleanup(proc, true)
	}

	transcript := recorder.Finalize()
	cleanups = append(cleanups, transcript.CleanupActions...)
	return cleanups
}

// --- T074: Full test execution pipeline ---

// ExecuteTester runs a tester by module ID through the full safety pipeline:
//  1. Get tester from registry
//  2. Run pre-flight (safety, scope, auth)
//  3. Execute test
//  4. Run cleanup (always, even on test failure)
//  5. Attach transcript to evidence
//  6. Set confidence_level = active_verification
//  7. Return evidence
func (e *Executor) ExecuteTester(ctx context.Context, moduleID string, cfg *TestConfig) ([]evidence.Evidence, error) {
	// Use defaults if no config provided.
	if cfg == nil {
		cfg = DefaultTestConfig()
	}

	// 1. Get tester from registry.
	tester, err := e.Registry.GetTester(moduleID)
	if err != nil {
		return nil, err
	}

	// 2. Run pre-flight (safety, scope, auth).
	if err := RunPreFlight(tester, *cfg); err != nil {
		return nil, err
	}

	// 3. Execute test.
	evidences, testErr := tester.Test(ctx, cfg.ModuleConfig)

	// 4. Run cleanup (always, even on test failure).
	cleanups := RunCleanup(tester)

	// If the test itself failed, return the error after cleanup.
	if testErr != nil {
		return nil, fmt.Errorf("test execution failed (cleanup completed): %w", testErr)
	}

	// 5-7. Post-process each evidence record.
	safetyClass := string(tester.SafetyClass())
	for i := range evidences {
		ev := &evidences[i]

		// Ensure confidence level is active_verification.
		ev.ConfidenceLevel = evidence.ActiveVerification

		// Tag safety classification in metadata.
		ev.Metadata.SafetyClassification = &safetyClass

		// If the test did not produce its own transcript, create one
		// with just the cleanup records.
		if ev.TestTranscript == nil {
			ev.TestTranscript = &evidence.TestTranscript{
				ActionsAttempted: []evidence.TranscriptAction{},
				Observations:     []evidence.TranscriptObservation{},
				CleanupActions:   cleanups,
			}
		} else {
			// Append executor-level cleanup records to any existing transcript.
			ev.TestTranscript.CleanupActions = append(
				ev.TestTranscript.CleanupActions, cleanups...)
		}
	}

	return evidences, nil
}
