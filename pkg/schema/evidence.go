// Package schema provides stable, exported types for OCEAN library consumers.
// These types mirror internal evidence types but are part of the public API
// contract and will maintain backward compatibility across minor versions.
package schema

import (
	"encoding/json"
	"time"
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

// ConfidenceLevel represents the degree of confidence in an evidence record.
type ConfidenceLevel string

const (
	// PassiveObservation indicates evidence was gathered by reading state.
	PassiveObservation ConfidenceLevel = "passive_observation"

	// ActiveVerification indicates evidence was gathered by performing an active test.
	ActiveVerification ConfidenceLevel = "active_verification"
)

// Evidence is the public representation of an OCEAN evidence record.
// This type is stable and safe for use in external integrations.
type Evidence struct {
	ID              string          `json:"id"`
	ControlID       string          `json:"control_id"`
	ClassUID        int             `json:"class_uid"`
	CategoryUID     int             `json:"category_uid"`
	ActivityID      int             `json:"activity_id"`
	Time            time.Time       `json:"time"`
	ConfidenceLevel ConfidenceLevel `json:"confidence_level"`
	StatusID        StatusID        `json:"status_id"`
	Status          string          `json:"status"`
	RawData         json.RawMessage `json:"raw_data,omitempty"`
	Metadata        Metadata        `json:"metadata"`
	Findings        []Finding       `json:"findings,omitempty"`
	Attestation     AttestationRef  `json:"attestation"`
}

// Metadata holds provenance information about how the evidence was collected.
type Metadata struct {
	Module ModuleInfo `json:"module"`
	Source SourceInfo `json:"source"`
}

// ModuleInfo identifies the OCEAN module that produced the evidence.
type ModuleInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
}

// SourceInfo identifies the external system from which evidence was gathered.
type SourceInfo struct {
	System     string `json:"system"`
	APIVersion string `json:"api_version,omitempty"`
	Endpoint   string `json:"endpoint,omitempty"`
}

// Finding represents a discrete finding within an evidence record.
type Finding struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	SeverityID  int    `json:"severity_id"`
}

// AttestationRef links an evidence record to its cryptographic attestation.
type AttestationRef struct {
	Type            string `json:"type"`
	DSSEEnvelopeRef string `json:"dsse_envelope_ref"`
	Digest          string `json:"digest"`
	Signer          string `json:"signer,omitempty"`
}
