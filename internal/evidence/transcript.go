package evidence

import (
	"encoding/json"
	"time"
)

// TestTranscript captures the full audit trail of an active verification test,
// including what was attempted, what was observed, and what was cleaned up.
type TestTranscript struct {
	ActionsAttempted []TranscriptAction      `json:"actions_attempted"`
	Observations     []TranscriptObservation `json:"observations"`
	CleanupActions   []TranscriptCleanup     `json:"cleanup_actions"`
}

// TranscriptAction records a single action attempted during an active test.
type TranscriptAction struct {
	Action     string          `json:"action"`
	Timestamp  time.Time       `json:"timestamp"`
	Parameters json.RawMessage `json:"parameters"`
}

// TranscriptObservation records what was observed during an active test,
// and whether it matched expectations.
type TranscriptObservation struct {
	Observation string    `json:"observation"`
	Timestamp   time.Time `json:"timestamp"`
	Expected    bool      `json:"expected"`
}

// TranscriptCleanup records a cleanup action taken after an active test
// to restore the environment to its original state.
type TranscriptCleanup struct {
	Action    string    `json:"action"`
	Timestamp time.Time `json:"timestamp"`
	Success   bool      `json:"success"`
}

// --- T073: TranscriptRecorder ---

// TranscriptRecorder builds a TestTranscript incrementally during test execution.
type TranscriptRecorder struct {
	actions      []TranscriptAction
	observations []TranscriptObservation
	cleanups     []TranscriptCleanup
}

// NewTranscriptRecorder creates a new empty transcript recorder.
func NewTranscriptRecorder() *TranscriptRecorder {
	return &TranscriptRecorder{
		actions:      []TranscriptAction{},
		observations: []TranscriptObservation{},
		cleanups:     []TranscriptCleanup{},
	}
}

// RecordAction records an action attempted during the test.
func (r *TranscriptRecorder) RecordAction(action string, params interface{}) {
	var paramJSON json.RawMessage
	if params != nil {
		data, err := json.Marshal(params)
		if err == nil {
			paramJSON = data
		}
	}
	r.actions = append(r.actions, TranscriptAction{
		Action:     action,
		Timestamp:  time.Now().UTC(),
		Parameters: paramJSON,
	})
}

// RecordObservation records what was observed and whether it matched expectations.
func (r *TranscriptRecorder) RecordObservation(observation string, expected bool) {
	r.observations = append(r.observations, TranscriptObservation{
		Observation: observation,
		Timestamp:   time.Now().UTC(),
		Expected:    expected,
	})
}

// RecordCleanup records a cleanup action and whether it succeeded.
func (r *TranscriptRecorder) RecordCleanup(action string, success bool) {
	r.cleanups = append(r.cleanups, TranscriptCleanup{
		Action:    action,
		Timestamp: time.Now().UTC(),
		Success:   success,
	})
}

// Finalize returns the completed TestTranscript. The recorder should not be
// used after calling Finalize.
func (r *TranscriptRecorder) Finalize() *TestTranscript {
	return &TestTranscript{
		ActionsAttempted: r.actions,
		Observations:     r.observations,
		CleanupActions:   r.cleanups,
	}
}
