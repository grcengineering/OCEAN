package evidence

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// StatusID represents the outcome of an evidence collection or test.
type StatusID int

const (
	// StatusUnknown indicates the outcome could not be determined.
	StatusUnknown StatusID = 0

	// StatusEffective indicates the control is operating effectively.
	StatusEffective StatusID = 1

	// StatusIneffective indicates the control is not operating effectively.
	StatusIneffective StatusID = 2

	// StatusOther indicates a non-standard outcome that requires human review.
	StatusOther StatusID = 99
)

// Evidence is the foundational entity in OCEAN -- a structured, immutable,
// cryptographically attestable record that proves a control was (or was not)
// operating effectively at a given point in time.
type Evidence struct {
	ID              uuid.UUID       `json:"id"`
	ControlID       string          `json:"control_id"`
	ClassUID        int             `json:"class_uid"`
	CategoryUID     int             `json:"category_uid"`
	ActivityID      int             `json:"activity_id"`
	Time            time.Time       `json:"time"`
	ConfidenceLevel ConfidenceLevel `json:"confidence_level"`
	Metadata        Metadata        `json:"metadata"`
	Observables     []Observable    `json:"observables"`
	StatusID        StatusID        `json:"status_id"`
	Status          string          `json:"status"`
	RawData         json.RawMessage `json:"raw_data"`
	Findings        []Finding       `json:"findings"`
	TestTranscript  *TestTranscript `json:"test_transcript,omitempty"`
	Attestation     AttestationRef  `json:"attestation"`
	Enrichments     []Enrichment    `json:"enrichments,omitempty"`
}

// Metadata holds provenance information about how the evidence was collected,
// including the module that produced it and the source system it came from.
type Metadata struct {
	Module               ModuleInfo                    `json:"module"`
	Source               SourceInfo                    `json:"source"`
	OriginalTime         *time.Time                    `json:"original_time,omitempty"`
	ProcessedTime        time.Time                     `json:"processed_time"`
	SafetyClassification *string `json:"safety_classification,omitempty"`
}

// ModuleInfo identifies the OCEAN module that produced this evidence.
type ModuleInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"` // collector, tester, dual
}

// SourceInfo identifies the external system from which evidence was gathered.
type SourceInfo struct {
	System     string `json:"system"`
	APIVersion string `json:"api_version"`
	Endpoint   string `json:"endpoint"`
}

// Observable represents a single observable value extracted from evidence,
// such as a username, IP address, or policy identifier.
type Observable struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Finding represents a discrete finding within an evidence record, typically
// used when a control is found to be misconfigured or ineffective.
type Finding struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	SeverityID  int    `json:"severity_id"`
}

// Enrichment holds additional context added to evidence after initial collection,
// such as threat intelligence lookups or asset inventory correlations.
type Enrichment struct {
	Type         string          `json:"type"`
	Data         json.RawMessage `json:"data"`
	EnrichedTime time.Time       `json:"enriched_time"`
}

// AttestationRef links an evidence record to its cryptographic attestation
// envelope (DSSE), providing tamper-evident provenance.
type AttestationRef struct {
	Type            string `json:"type"` // collection, evaluation
	DSSEEnvelopeRef string `json:"dsse_envelope_ref"`
	Digest          string `json:"digest"`
	Signer          string `json:"signer"`
}
