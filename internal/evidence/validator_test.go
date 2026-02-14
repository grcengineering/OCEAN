package evidence

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

// validEvidence returns a fully-populated Evidence that passes all validation
// rules. Tests that need an invalid record should modify the returned value.
func validEvidence() Evidence {
	return Evidence{
		ID:              uuid.New(),
		ControlID:       "AC-2",
		ClassUID:        3001,
		CategoryUID:     3,
		ActivityID:      1,
		Time:            time.Now(),
		ConfidenceLevel: PassiveObservation,
		Metadata: Metadata{
			Module: ModuleInfo{
				Name:    "okta_mfa_collector",
				Version: "0.1.0",
				Type:    "collector",
			},
			Source: SourceInfo{
				System:     "okta",
				APIVersion: "v1",
				Endpoint:   "/api/v1/policies",
			},
			ProcessedTime: time.Now(),
		},
		StatusID: StatusEffective,
		Status:   "effective",
		RawData:  json.RawMessage(`{"mfa_enabled": true}`),
		Attestation: AttestationRef{
			Type:   "collection",
			Digest: "sha256:abc123",
		},
	}
}

func TestValidate_ValidPassiveEvidence(t *testing.T) {
	e := validEvidence()
	if err := e.Validate(); err != nil {
		t.Fatalf("expected valid evidence to pass validation, got: %v", err)
	}
}

func TestValidate_ValidActiveEvidence(t *testing.T) {
	e := validEvidence()
	e.ConfidenceLevel = ActiveVerification
	e.TestTranscript = &TestTranscript{
		ActionsAttempted: []TranscriptAction{
			{Action: "attempt_login_without_mfa", Timestamp: time.Now(), Parameters: json.RawMessage(`{}`)},
		},
		Observations: []TranscriptObservation{
			{Observation: "login_blocked", Timestamp: time.Now(), Expected: true},
		},
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("expected valid active evidence to pass validation, got: %v", err)
	}
}

func TestValidate_ActiveVerificationWithoutTranscript(t *testing.T) {
	e := validEvidence()
	e.ConfidenceLevel = ActiveVerification
	e.TestTranscript = nil

	err := e.Validate()
	if err == nil {
		t.Fatal("expected error for active_verification without TestTranscript, got nil")
	}
}

func TestValidate_PassiveObservationWithTranscript(t *testing.T) {
	e := validEvidence()
	e.ConfidenceLevel = PassiveObservation
	e.TestTranscript = &TestTranscript{}

	err := e.Validate()
	if err == nil {
		t.Fatal("expected error for passive_observation with TestTranscript, got nil")
	}
}

func TestValidate_InvalidStatusID(t *testing.T) {
	e := validEvidence()
	e.StatusID = StatusID(42)

	err := e.Validate()
	if err == nil {
		t.Fatal("expected error for invalid StatusID, got nil")
	}
}

func TestValidate_InvalidConfidenceLevel(t *testing.T) {
	e := validEvidence()
	e.ConfidenceLevel = ConfidenceLevel("guessing")

	err := e.Validate()
	if err == nil {
		t.Fatal("expected error for invalid confidence level, got nil")
	}
}

func TestValidate_EmptyControlID(t *testing.T) {
	e := validEvidence()
	e.ControlID = ""

	err := e.Validate()
	if err == nil {
		t.Fatal("expected error for empty ControlID, got nil")
	}
}

func TestValidate_ZeroID(t *testing.T) {
	e := validEvidence()
	e.ID = uuid.Nil

	err := e.Validate()
	if err == nil {
		t.Fatal("expected error for zero-value UUID, got nil")
	}
}

func TestValidate_EmptyModuleName(t *testing.T) {
	e := validEvidence()
	e.Metadata.Module.Name = ""

	err := e.Validate()
	if err == nil {
		t.Fatal("expected error for empty module name, got nil")
	}
}

func TestValidate_EmptySourceSystem(t *testing.T) {
	e := validEvidence()
	e.Metadata.Source.System = ""

	err := e.Validate()
	if err == nil {
		t.Fatal("expected error for empty source system, got nil")
	}
}

func TestValidate_EmptyAttestationDigest(t *testing.T) {
	e := validEvidence()
	e.Attestation.Digest = ""

	err := e.Validate()
	if err == nil {
		t.Fatal("expected error for empty attestation digest, got nil")
	}
}

func TestValidate_InvalidAttestationType(t *testing.T) {
	e := validEvidence()
	e.Attestation.Type = "random"

	err := e.Validate()
	if err == nil {
		t.Fatal("expected error for invalid attestation type, got nil")
	}
}

func TestValidate_NilRawData(t *testing.T) {
	e := validEvidence()
	e.RawData = nil

	err := e.Validate()
	if err == nil {
		t.Fatal("expected error for nil RawData, got nil")
	}
}

func TestValidate_ZeroTime(t *testing.T) {
	e := validEvidence()
	e.Time = time.Time{}

	err := e.Validate()
	if err == nil {
		t.Fatal("expected error for zero Time, got nil")
	}
}

func TestValidate_EmptyStatus(t *testing.T) {
	e := validEvidence()
	e.Status = ""

	err := e.Validate()
	if err == nil {
		t.Fatal("expected error for empty Status, got nil")
	}
}

func TestValidateAll_AllValid(t *testing.T) {
	evidences := []Evidence{validEvidence(), validEvidence()}
	if err := ValidateAll(evidences); err != nil {
		t.Fatalf("expected ValidateAll to pass, got: %v", err)
	}
}

func TestValidateAll_OneInvalid(t *testing.T) {
	good := validEvidence()
	bad := validEvidence()
	bad.ControlID = ""

	err := ValidateAll([]Evidence{good, bad})
	if err == nil {
		t.Fatal("expected ValidateAll to fail when one record is invalid, got nil")
	}
}

func TestValidateAll_Empty(t *testing.T) {
	if err := ValidateAll(nil); err != nil {
		t.Fatalf("expected ValidateAll on nil slice to pass, got: %v", err)
	}
	if err := ValidateAll([]Evidence{}); err != nil {
		t.Fatalf("expected ValidateAll on empty slice to pass, got: %v", err)
	}
}
