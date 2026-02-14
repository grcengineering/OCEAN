package evidence

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeRedactionTestEvidence() *Evidence {
	return &Evidence{
		ID:              uuid.New(),
		ControlID:       "iam.mfa_enforcement",
		ClassUID:        1001,
		CategoryUID:     1,
		ActivityID:      1,
		Time:            time.Now().UTC(),
		ConfidenceLevel: PassiveObservation,
		Metadata: Metadata{
			Module: ModuleInfo{
				Name:    "mock.test",
				Version: "0.1.0",
				Type:    "collector",
			},
			Source: SourceInfo{
				System:     "okta",
				APIVersion: "v1",
				Endpoint:   "https://dev-123456.okta.com/api/v1/policies",
			},
			ProcessedTime: time.Now().UTC(),
		},
		Observables: []Observable{
			{Type: "user", Value: "admin@example.com"},
			{Type: "ip_address", Value: "10.0.1.42"},
			{Type: "resource", Value: "mfa_policy_global"},
		},
		StatusID: StatusEffective,
		Status:   "MFA enforcement is required for all users",
		RawData: json.RawMessage(`{
			"email": "admin@example.com",
			"ip": "10.0.1.42",
			"mfa_policy": {"enforcement": "required"},
			"ssn": "123-45-6789"
		}`),
		Findings: []Finding{
			{
				Title:       "MFA Policy Active",
				Description: "User admin@example.com has MFA enabled",
				SeverityID:  0,
			},
		},
		Attestation: AttestationRef{
			Type:            "collection",
			DSSEEnvelopeRef: "sha256:abc123",
			Digest:          "sha256:def456",
			Signer:          "ocean-key",
		},
	}
}

func TestRedactEvidence_RemovesRawData(t *testing.T) {
	ev := makeRedactionTestEvidence()
	config := RedactionConfig{
		RemoveRawData: true,
	}

	redacted := RedactEvidence(ev, config)

	// Original should be unchanged.
	require.NotNil(t, ev.RawData)

	// Redacted should have nil raw data.
	assert.Nil(t, redacted.RawData)

	// Other fields should remain.
	assert.Equal(t, ev.ControlID, redacted.ControlID)
	assert.Equal(t, ev.StatusID, redacted.StatusID)
}

func TestRedactEvidence_MasksObservables(t *testing.T) {
	ev := makeRedactionTestEvidence()
	config := RedactionConfig{
		MaskObservableTypes: []string{"user", "ip_address"},
	}

	redacted := RedactEvidence(ev, config)

	// Original should be unchanged.
	assert.Equal(t, "admin@example.com", ev.Observables[0].Value)

	// Redacted user and ip should be masked.
	for _, obs := range redacted.Observables {
		if obs.Type == "user" || obs.Type == "ip_address" {
			assert.Equal(t, "***REDACTED***", obs.Value,
				"observable type %q should be masked", obs.Type)
		}
	}

	// Resource type should NOT be masked.
	for _, obs := range redacted.Observables {
		if obs.Type == "resource" {
			assert.Equal(t, "mfa_policy_global", obs.Value)
		}
	}
}

func TestRedactEvidence_RemovesSpecifiedFields(t *testing.T) {
	ev := makeRedactionTestEvidence()
	config := RedactionConfig{
		RemoveFields: []string{"findings", "attestation"},
	}

	redacted := RedactEvidence(ev, config)

	// Original findings should remain.
	require.Len(t, ev.Findings, 1)

	// Redacted findings should be nil/empty.
	assert.Empty(t, redacted.Findings)

	// Attestation should be zeroed.
	assert.Empty(t, redacted.Attestation.DSSEEnvelopeRef)
	assert.Empty(t, redacted.Attestation.Digest)
}

func TestRedactEvidence_HashesResourceIDs(t *testing.T) {
	ev := makeRedactionTestEvidence()
	config := RedactionConfig{
		HashObservableTypes: []string{"resource"},
	}

	redacted := RedactEvidence(ev, config)

	// Resource observable should be hashed, not the original value.
	for _, obs := range redacted.Observables {
		if obs.Type == "resource" {
			assert.NotEqual(t, "mfa_policy_global", obs.Value,
				"resource value should be hashed")
			assert.Contains(t, obs.Value, "sha256:",
				"hashed value should have sha256 prefix")
		}
	}

	// Non-hashed types should remain.
	for _, obs := range redacted.Observables {
		if obs.Type == "user" {
			assert.Equal(t, "admin@example.com", obs.Value)
		}
	}
}

func TestRedactEvidence_CombinedConfig(t *testing.T) {
	ev := makeRedactionTestEvidence()
	config := RedactionConfig{
		RemoveRawData:       true,
		MaskObservableTypes: []string{"user", "ip_address"},
		HashObservableTypes: []string{"resource"},
		RemoveFields:        []string{"findings"},
	}

	redacted := RedactEvidence(ev, config)

	assert.Nil(t, redacted.RawData)
	assert.Empty(t, redacted.Findings)

	for _, obs := range redacted.Observables {
		switch obs.Type {
		case "user", "ip_address":
			assert.Equal(t, "***REDACTED***", obs.Value)
		case "resource":
			assert.Contains(t, obs.Value, "sha256:")
		}
	}
}

func TestRedactEvidence_EmptyConfig(t *testing.T) {
	ev := makeRedactionTestEvidence()
	config := RedactionConfig{}

	redacted := RedactEvidence(ev, config)

	// With empty config, evidence should be a copy but unchanged in content.
	assert.Equal(t, ev.ID, redacted.ID)
	assert.Equal(t, ev.ControlID, redacted.ControlID)
	assert.NotNil(t, redacted.RawData)
	assert.Len(t, redacted.Observables, 3)
	assert.Len(t, redacted.Findings, 1)
}

func TestRedactEvidence_DoesNotMutateOriginal(t *testing.T) {
	ev := makeRedactionTestEvidence()
	originalEmail := ev.Observables[0].Value
	config := RedactionConfig{
		RemoveRawData:       true,
		MaskObservableTypes: []string{"user"},
	}

	_ = RedactEvidence(ev, config)

	// Original evidence should be completely unchanged.
	assert.NotNil(t, ev.RawData)
	assert.Equal(t, originalEmail, ev.Observables[0].Value)
}
