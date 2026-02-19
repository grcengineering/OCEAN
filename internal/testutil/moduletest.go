package testutil

import (
	"context"
	"testing"

	"github.com/grcengineering/ocean/internal/evidence"
	"github.com/grcengineering/ocean/internal/module"
)

// RunCollectorTests runs standard contract tests against a Collector.
// It validates that all metadata fields are populated, that Collect returns
// valid evidence, and that each evidence record passes structural validation.
//
// The config parameter is passed directly to the Collector's Collect method.
// For mock/stub collectors it can be nil; for real collectors it should
// contain whatever credentials or configuration the collector requires
// (e.g., API URLs, tokens).
func RunCollectorTests(t *testing.T, c module.Collector, config map[string]string) {
	t.Helper()

	// --- Metadata contract ---

	t.Run("ID is non-empty", func(t *testing.T) {
		if c.ID() == "" {
			t.Error("collector ID is empty")
		}
	})

	t.Run("Name is non-empty", func(t *testing.T) {
		if c.Name() == "" {
			t.Error("collector Name is empty")
		}
	})

	t.Run("Version is non-empty", func(t *testing.T) {
		if c.Version() == "" {
			t.Error("collector Version is empty")
		}
	})

	t.Run("SourceSystem is non-empty", func(t *testing.T) {
		if c.SourceSystem() == "" {
			t.Error("collector SourceSystem is empty")
		}
	})

	t.Run("EvidenceTypes is non-empty", func(t *testing.T) {
		if len(c.EvidenceTypes()) == 0 {
			t.Error("collector EvidenceTypes is empty")
		}
	})

	// --- Collect contract ---

	t.Run("Collect returns valid evidence", func(t *testing.T) {
		evs, err := c.Collect(context.Background(), config)
		if err != nil {
			t.Fatalf("Collect error: %v", err)
		}
		if len(evs) == 0 {
			t.Error("Collect returned no evidence")
		}
		for i, ev := range evs {
			t.Run("", func(t *testing.T) {
				AssertValidEvidence(t, ev)

				// Collectors must produce passive_observation confidence.
				if ev.ConfidenceLevel != evidence.PassiveObservation {
					t.Errorf("evidence[%d]: expected confidence %q, got %q",
						i, evidence.PassiveObservation, ev.ConfidenceLevel)
				}
			})
		}
	})
}

// RunTesterTests runs standard contract tests against a Tester.
// It validates all Module metadata, tester-specific safety metadata,
// and that the Test method returns evidence with ActiveVerification
// confidence and a TestTranscript.
//
// The config parameter is passed directly to the Tester's Test method.
func RunTesterTests(t *testing.T, tester module.Tester, config map[string]string) {
	t.Helper()

	// --- Module metadata contract (same as collector) ---

	t.Run("ID is non-empty", func(t *testing.T) {
		if tester.ID() == "" {
			t.Error("tester ID is empty")
		}
	})

	t.Run("Name is non-empty", func(t *testing.T) {
		if tester.Name() == "" {
			t.Error("tester Name is empty")
		}
	})

	t.Run("Version is non-empty", func(t *testing.T) {
		if tester.Version() == "" {
			t.Error("tester Version is empty")
		}
	})

	t.Run("SourceSystem is non-empty", func(t *testing.T) {
		if tester.SourceSystem() == "" {
			t.Error("tester SourceSystem is empty")
		}
	})

	t.Run("EvidenceTypes is non-empty", func(t *testing.T) {
		if len(tester.EvidenceTypes()) == 0 {
			t.Error("tester EvidenceTypes is empty")
		}
	})

	// --- Tester-specific metadata ---

	t.Run("SafetyClass is valid", func(t *testing.T) {
		if !tester.SafetyClass().Valid() {
			t.Errorf("tester SafetyClass %q is not valid", tester.SafetyClass())
		}
	})

	t.Run("EnvironmentScope is valid", func(t *testing.T) {
		if !tester.EnvironmentScope().Valid() {
			t.Errorf("tester EnvironmentScope %q is not valid", tester.EnvironmentScope())
		}
	})

	t.Run("PreFlightChecks is non-nil", func(t *testing.T) {
		if tester.PreFlightChecks() == nil {
			t.Error("tester PreFlightChecks returned nil (should return empty slice or populated slice)")
		}
	})

	// --- Test method contract ---

	t.Run("Test returns valid evidence", func(t *testing.T) {
		evs, err := tester.Test(context.Background(), config)
		if err != nil {
			t.Fatalf("Test error: %v", err)
		}
		if len(evs) == 0 {
			t.Error("Test returned no evidence")
		}
		for i, ev := range evs {
			t.Run("", func(t *testing.T) {
				AssertValidEvidence(t, ev)

				// Testers must produce active_verification confidence.
				if ev.ConfidenceLevel != evidence.ActiveVerification {
					t.Errorf("evidence[%d]: expected confidence %q, got %q",
						i, evidence.ActiveVerification, ev.ConfidenceLevel)
				}

				// Testers must include a test transcript.
				if ev.TestTranscript == nil {
					t.Errorf("evidence[%d]: TestTranscript is nil (testers must include transcripts)", i)
				}
			})
		}
	})
}
