// Package mock provides a mock collector for testing OCEAN's collection
// pipeline end-to-end without external dependencies. It returns realistic
// MFA-policy-style evidence suitable for validating schema, output
// formatting, and CLI wiring.
package mock

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/grcengineering/ocean/internal/evidence"
	"github.com/grcengineering/ocean/internal/module"
)

// Collector is a mock collector for testing OCEAN's collection pipeline.
// It produces realistic MFA enforcement evidence without requiring any
// external system access or credentials.
type Collector struct{}

// Compile-time interface check.
var _ module.Collector = (*Collector)(nil)

func (c *Collector) ID() string            { return "mock.test" }
func (c *Collector) Name() string          { return "Mock Test Collector" }
func (c *Collector) Version() string       { return "0.1.0" }
func (c *Collector) SourceSystem() string  { return "mock" }
func (c *Collector) EvidenceTypes() []int  { return []int{1001} }
func (c *Collector) CredentialRequirements() []module.CredentialReq { return nil }

// Collect returns a single evidence record representing an MFA policy
// configuration check. The evidence has all fields populated except
// Attestation, which is filled by the signing pipeline.
func (c *Collector) Collect(_ context.Context, _ map[string]string) ([]evidence.Evidence, error) {
	now := time.Now().UTC()

	rawData := map[string]interface{}{
		"mfa_policy": map[string]interface{}{
			"enforcement":     "required",
			"user_exceptions": []string{},
			"factors_allowed": []string{"push", "totp", "webauthn"},
		},
		"total_users":       150,
		"mfa_enrolled":      150,
		"last_policy_update": "2026-01-15T10:30:00Z",
	}
	rawJSON, _ := json.Marshal(rawData)

	ev := evidence.Evidence{
		ID:              uuid.New(),
		ControlID:       "mfa.enforcement",
		ClassUID:        1001,
		CategoryUID:     1,
		ActivityID:      1, // Config Check
		Time:            now,
		ConfidenceLevel: evidence.PassiveObservation,
		Metadata: evidence.Metadata{
			Module: evidence.ModuleInfo{
				Name:    "mock.test",
				Version: "0.1.0",
				Type:    "collector",
			},
			Source: evidence.SourceInfo{
				System:     "mock",
				APIVersion: "v1",
				Endpoint:   "/api/v1/policies",
			},
			ProcessedTime: now,
		},
		Observables: []evidence.Observable{
			{Type: "resource", Value: "mfa_policy_global"},
		},
		StatusID: evidence.StatusEffective,
		Status:   "MFA enforcement is required for all users",
		RawData:  rawJSON,
		Findings: []evidence.Finding{
			{
				Title:       "MFA Policy Active",
				Description: "MFA enforcement is set to 'required' with zero user exceptions",
				SeverityID:  0,
			},
		},
		// Attestation is intentionally empty — filled by the signing pipeline.
	}

	return []evidence.Evidence{ev}, nil
}
