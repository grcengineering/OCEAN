package schema

import (
	"encoding/json"
	"testing"
	"time"
)

func TestStatusID_Constants(t *testing.T) {
	tests := []struct {
		name string
		got  StatusID
		want StatusID
	}{
		{"StatusUnknown", StatusUnknown, 0},
		{"StatusEffective", StatusEffective, 1},
		{"StatusIneffective", StatusIneffective, 2},
		{"StatusOther", StatusOther, 99},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("%s = %d, want %d", tt.name, tt.got, tt.want)
			}
		})
	}
}

func TestConfidenceLevel_Constants(t *testing.T) {
	if PassiveObservation != "passive_observation" {
		t.Errorf("PassiveObservation = %q, want %q", PassiveObservation, "passive_observation")
	}
	if ActiveVerification != "active_verification" {
		t.Errorf("ActiveVerification = %q, want %q", ActiveVerification, "active_verification")
	}
}

func TestEvidence_JSONRoundTrip(t *testing.T) {
	now := time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC)

	original := Evidence{
		ID:              "ev-001",
		ControlID:       "ctrl-mfa-01",
		ClassUID:        6003,
		CategoryUID:     6,
		ActivityID:      1,
		Time:            now,
		ConfidenceLevel: ActiveVerification,
		StatusID:        StatusEffective,
		Status:          "effective",
		RawData:         json.RawMessage(`{"key":"value"}`),
		Metadata: Metadata{
			Module: ModuleInfo{
				Name:    "okta.mfa_policy",
				Version: "1.0.0",
				Type:    "collector",
			},
			Source: SourceInfo{
				System:     "okta",
				APIVersion: "v1",
				Endpoint:   "/api/v1/policies",
			},
		},
		Findings: []Finding{
			{
				Title:       "MFA Enabled",
				Description: "MFA policy is active for all users",
				SeverityID:  1,
			},
		},
		Attestation: AttestationRef{
			Type:            "collection",
			DSSEEnvelopeRef: "sha256:abc123",
			Digest:          "sha256:def456",
			Signer:          "ocean-ci",
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var restored Evidence
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	// Compare scalar fields.
	if restored.ID != original.ID {
		t.Errorf("ID = %q, want %q", restored.ID, original.ID)
	}
	if restored.ControlID != original.ControlID {
		t.Errorf("ControlID = %q, want %q", restored.ControlID, original.ControlID)
	}
	if restored.ClassUID != original.ClassUID {
		t.Errorf("ClassUID = %d, want %d", restored.ClassUID, original.ClassUID)
	}
	if restored.CategoryUID != original.CategoryUID {
		t.Errorf("CategoryUID = %d, want %d", restored.CategoryUID, original.CategoryUID)
	}
	if restored.ActivityID != original.ActivityID {
		t.Errorf("ActivityID = %d, want %d", restored.ActivityID, original.ActivityID)
	}
	if !restored.Time.Equal(original.Time) {
		t.Errorf("Time = %v, want %v", restored.Time, original.Time)
	}
	if restored.ConfidenceLevel != original.ConfidenceLevel {
		t.Errorf("ConfidenceLevel = %q, want %q", restored.ConfidenceLevel, original.ConfidenceLevel)
	}
	if restored.StatusID != original.StatusID {
		t.Errorf("StatusID = %d, want %d", restored.StatusID, original.StatusID)
	}
	if restored.Status != original.Status {
		t.Errorf("Status = %q, want %q", restored.Status, original.Status)
	}

	// Compare RawData as strings.
	if string(restored.RawData) != string(original.RawData) {
		t.Errorf("RawData = %s, want %s", restored.RawData, original.RawData)
	}

	// Compare nested Metadata.
	if restored.Metadata.Module.Name != original.Metadata.Module.Name {
		t.Errorf("Module.Name = %q, want %q", restored.Metadata.Module.Name, original.Metadata.Module.Name)
	}
	if restored.Metadata.Module.Version != original.Metadata.Module.Version {
		t.Errorf("Module.Version = %q, want %q", restored.Metadata.Module.Version, original.Metadata.Module.Version)
	}
	if restored.Metadata.Module.Type != original.Metadata.Module.Type {
		t.Errorf("Module.Type = %q, want %q", restored.Metadata.Module.Type, original.Metadata.Module.Type)
	}
	if restored.Metadata.Source.System != original.Metadata.Source.System {
		t.Errorf("Source.System = %q, want %q", restored.Metadata.Source.System, original.Metadata.Source.System)
	}
	if restored.Metadata.Source.APIVersion != original.Metadata.Source.APIVersion {
		t.Errorf("Source.APIVersion = %q, want %q", restored.Metadata.Source.APIVersion, original.Metadata.Source.APIVersion)
	}
	if restored.Metadata.Source.Endpoint != original.Metadata.Source.Endpoint {
		t.Errorf("Source.Endpoint = %q, want %q", restored.Metadata.Source.Endpoint, original.Metadata.Source.Endpoint)
	}

	// Compare Findings.
	if len(restored.Findings) != len(original.Findings) {
		t.Fatalf("Findings length = %d, want %d", len(restored.Findings), len(original.Findings))
	}
	if restored.Findings[0].Title != original.Findings[0].Title {
		t.Errorf("Finding.Title = %q, want %q", restored.Findings[0].Title, original.Findings[0].Title)
	}
	if restored.Findings[0].Description != original.Findings[0].Description {
		t.Errorf("Finding.Description = %q, want %q", restored.Findings[0].Description, original.Findings[0].Description)
	}
	if restored.Findings[0].SeverityID != original.Findings[0].SeverityID {
		t.Errorf("Finding.SeverityID = %d, want %d", restored.Findings[0].SeverityID, original.Findings[0].SeverityID)
	}

	// Compare Attestation.
	if restored.Attestation.Type != original.Attestation.Type {
		t.Errorf("Attestation.Type = %q, want %q", restored.Attestation.Type, original.Attestation.Type)
	}
	if restored.Attestation.DSSEEnvelopeRef != original.Attestation.DSSEEnvelopeRef {
		t.Errorf("Attestation.DSSEEnvelopeRef = %q, want %q", restored.Attestation.DSSEEnvelopeRef, original.Attestation.DSSEEnvelopeRef)
	}
	if restored.Attestation.Digest != original.Attestation.Digest {
		t.Errorf("Attestation.Digest = %q, want %q", restored.Attestation.Digest, original.Attestation.Digest)
	}
	if restored.Attestation.Signer != original.Attestation.Signer {
		t.Errorf("Attestation.Signer = %q, want %q", restored.Attestation.Signer, original.Attestation.Signer)
	}
}
