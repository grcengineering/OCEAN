package testutil

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/grcengineering/ocean/internal/evidence"
)

// EvidenceBuilder provides a fluent builder for constructing evidence.Evidence
// values in tests. All fields have sensible defaults; callers override only
// the fields they care about.
//
// Usage:
//
//	ev := testutil.NewEvidence().
//	    WithControlID("mfa.enforcement").
//	    WithStatus(evidence.StatusEffective).
//	    Build()
type EvidenceBuilder struct {
	ev evidence.Evidence
}

// NewEvidence returns an EvidenceBuilder with sensible defaults.
func NewEvidence() *EvidenceBuilder {
	return &EvidenceBuilder{
		ev: evidence.Evidence{
			ID:              uuid.New(),
			ControlID:       "test.control",
			ClassUID:        9999,
			CategoryUID:     9,
			ActivityID:      1,
			Time:            time.Now().UTC().Truncate(time.Millisecond),
			ConfidenceLevel: evidence.PassiveObservation,
			StatusID:        evidence.StatusEffective,
			Status:          "effective",
			RawData:         json.RawMessage(`{"test": true}`),
			Metadata: evidence.Metadata{
				Module: evidence.ModuleInfo{
					Name:    "test.module",
					Version: "0.1.0",
					Type:    "collector",
				},
				Source: evidence.SourceInfo{
					System:     "test",
					APIVersion: "v1",
					Endpoint:   "/test",
				},
				ProcessedTime: time.Now().UTC().Truncate(time.Millisecond),
			},
		},
	}
}

// WithID sets the evidence ID.
func (b *EvidenceBuilder) WithID(id uuid.UUID) *EvidenceBuilder {
	b.ev.ID = id
	return b
}

// WithControlID sets the control ID.
func (b *EvidenceBuilder) WithControlID(id string) *EvidenceBuilder {
	b.ev.ControlID = id
	return b
}

// WithClassUID sets the OCSF class UID.
func (b *EvidenceBuilder) WithClassUID(uid int) *EvidenceBuilder {
	b.ev.ClassUID = uid
	return b
}

// WithStatus sets the StatusID and Status string.
func (b *EvidenceBuilder) WithStatus(id evidence.StatusID) *EvidenceBuilder {
	b.ev.StatusID = id
	switch id {
	case evidence.StatusEffective:
		b.ev.Status = "effective"
	case evidence.StatusIneffective:
		b.ev.Status = "ineffective"
	case evidence.StatusUnknown:
		b.ev.Status = "unknown"
	default:
		b.ev.Status = "other"
	}
	return b
}

// WithConfidence sets the confidence level.
func (b *EvidenceBuilder) WithConfidence(c evidence.ConfidenceLevel) *EvidenceBuilder {
	b.ev.ConfidenceLevel = c
	return b
}

// WithModule sets the module metadata.
func (b *EvidenceBuilder) WithModule(name, version, typ string) *EvidenceBuilder {
	b.ev.Metadata.Module = evidence.ModuleInfo{Name: name, Version: version, Type: typ}
	return b
}

// WithSource sets the source metadata.
func (b *EvidenceBuilder) WithSource(system, apiVersion, endpoint string) *EvidenceBuilder {
	b.ev.Metadata.Source = evidence.SourceInfo{System: system, APIVersion: apiVersion, Endpoint: endpoint}
	return b
}

// WithRawData sets the raw data payload.
func (b *EvidenceBuilder) WithRawData(data map[string]interface{}) *EvidenceBuilder {
	raw, _ := json.Marshal(data)
	b.ev.RawData = raw
	return b
}

// WithFinding appends a finding.
func (b *EvidenceBuilder) WithFinding(title, desc string, severity int) *EvidenceBuilder {
	b.ev.Findings = append(b.ev.Findings, evidence.Finding{
		Title:       title,
		Description: desc,
		SeverityID:  severity,
	})
	return b
}

// WithTranscript adds a test transcript to the evidence.
func (b *EvidenceBuilder) WithTranscript() *EvidenceBuilder {
	now := time.Now().UTC()
	b.ev.TestTranscript = &evidence.TestTranscript{
		ActionsAttempted: []evidence.TranscriptAction{
			{
				Action:    "test_action",
				Timestamp: now,
			},
		},
		Observations: []evidence.TranscriptObservation{
			{
				Observation: "test observation",
				Timestamp:   now,
				Expected:    true,
			},
		},
		CleanupActions: []evidence.TranscriptCleanup{},
	}
	return b
}

// WithTime sets the evidence timestamp.
func (b *EvidenceBuilder) WithTime(t time.Time) *EvidenceBuilder {
	b.ev.Time = t.UTC().Truncate(time.Millisecond)
	return b
}

// Build returns the constructed Evidence value.
func (b *EvidenceBuilder) Build() evidence.Evidence {
	return b.ev
}
