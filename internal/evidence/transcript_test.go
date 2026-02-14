package evidence

import (
	"testing"
)

func TestTranscriptRecorder_RecordAction(t *testing.T) {
	r := NewTranscriptRecorder()

	r.RecordAction("attempt MFA bypass", map[string]string{"method": "totp"})
	r.RecordAction("submit credentials", nil)

	transcript := r.Finalize()
	if len(transcript.ActionsAttempted) != 2 {
		t.Fatalf("expected 2 actions, got %d", len(transcript.ActionsAttempted))
	}

	if transcript.ActionsAttempted[0].Action != "attempt MFA bypass" {
		t.Errorf("action[0].Action = %q, want %q",
			transcript.ActionsAttempted[0].Action, "attempt MFA bypass")
	}

	if transcript.ActionsAttempted[0].Timestamp.IsZero() {
		t.Error("action[0].Timestamp should not be zero")
	}

	if transcript.ActionsAttempted[0].Parameters == nil {
		t.Error("action[0].Parameters should not be nil when params provided")
	}
}

func TestTranscriptRecorder_RecordObservation(t *testing.T) {
	r := NewTranscriptRecorder()

	r.RecordObservation("MFA prompt displayed", true)
	r.RecordObservation("bypass blocked", true)
	r.RecordObservation("unexpected error", false)

	transcript := r.Finalize()
	if len(transcript.Observations) != 3 {
		t.Fatalf("expected 3 observations, got %d", len(transcript.Observations))
	}

	if transcript.Observations[0].Observation != "MFA prompt displayed" {
		t.Errorf("observation[0] = %q, want %q",
			transcript.Observations[0].Observation, "MFA prompt displayed")
	}

	if !transcript.Observations[0].Expected {
		t.Error("observation[0].Expected should be true")
	}

	if transcript.Observations[2].Expected {
		t.Error("observation[2].Expected should be false")
	}

	if transcript.Observations[0].Timestamp.IsZero() {
		t.Error("observation[0].Timestamp should not be zero")
	}
}

func TestTranscriptRecorder_RecordCleanup(t *testing.T) {
	r := NewTranscriptRecorder()

	r.RecordCleanup("remove test artifacts", true)
	r.RecordCleanup("restore config", false)

	transcript := r.Finalize()
	if len(transcript.CleanupActions) != 2 {
		t.Fatalf("expected 2 cleanup actions, got %d", len(transcript.CleanupActions))
	}

	if !transcript.CleanupActions[0].Success {
		t.Error("cleanup[0].Success should be true")
	}

	if transcript.CleanupActions[1].Success {
		t.Error("cleanup[1].Success should be false")
	}

	if transcript.CleanupActions[0].Timestamp.IsZero() {
		t.Error("cleanup[0].Timestamp should not be zero")
	}
}

func TestTranscriptRecorder_Finalize(t *testing.T) {
	r := NewTranscriptRecorder()

	// Empty recorder should produce valid transcript with empty slices.
	transcript := r.Finalize()
	if transcript == nil {
		t.Fatal("Finalize() returned nil")
	}

	if transcript.ActionsAttempted == nil {
		t.Error("ActionsAttempted should be non-nil empty slice, not nil")
	}

	if transcript.Observations == nil {
		t.Error("Observations should be non-nil empty slice, not nil")
	}

	if transcript.CleanupActions == nil {
		t.Error("CleanupActions should be non-nil empty slice, not nil")
	}
}
