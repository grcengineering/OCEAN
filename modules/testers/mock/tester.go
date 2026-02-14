// Package mock provides a mock tester for testing OCEAN's active control
// testing pipeline end-to-end without external dependencies. It simulates
// an MFA bypass test that is safely blocked, producing evidence with a
// full test transcript at the active_verification confidence level.
package mock

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/grcengineering/ocean/internal/evidence"
	"github.com/grcengineering/ocean/internal/module"
)

// MockTester simulates an MFA bypass test that is safely blocked.
// It implements the Tester interface with SafetyClassSafe classification,
// meaning it can run in any environment without authorization prompts.
type MockTester struct{}

// Compile-time interface check.
var _ module.Tester = (*MockTester)(nil)

func (m *MockTester) ID() string            { return "mock.safety_test" }
func (m *MockTester) Name() string          { return "Mock Safety Test" }
func (m *MockTester) Version() string       { return "0.1.0" }
func (m *MockTester) SourceSystem() string  { return "mock" }
func (m *MockTester) EvidenceTypes() []int  { return []int{1001} }
func (m *MockTester) CredentialRequirements() []module.CredentialReq { return nil }

func (m *MockTester) SafetyClass() module.SafetyClassification { return module.SafetyClassSafe }
func (m *MockTester) EnvironmentScope() module.EnvironmentScope { return module.ScopeProduction }

func (m *MockTester) PreFlightChecks() []string {
	return []string{"verify mock target available"}
}

func (m *MockTester) CleanupProcedures() []string {
	return []string{"remove test artifacts"}
}

// Test simulates an MFA bypass attempt that is properly blocked. It returns
// evidence showing the control is effective with a full test transcript
// documenting actions, observations, and cleanup.
func (m *MockTester) Test(_ context.Context, _ map[string]string) ([]evidence.Evidence, error) {
	now := time.Now().UTC()

	// Build a realistic test transcript.
	recorder := evidence.NewTranscriptRecorder()

	// Record the simulated actions.
	recorder.RecordAction("initiate mock MFA bypass attempt", map[string]string{
		"target":  "mock-idp.example.com",
		"method":  "totp_replay",
		"user":    "test-user@example.com",
	})
	recorder.RecordAction("submit credentials without valid MFA token", map[string]string{
		"credentials": "redacted",
		"mfa_token":   "expired_token_000000",
	})

	// Record what was observed.
	recorder.RecordObservation("MFA challenge presented to user", true)
	recorder.RecordObservation("invalid MFA token rejected with HTTP 403", true)
	recorder.RecordObservation("authentication attempt logged in audit trail", true)

	// Record cleanup.
	recorder.RecordCleanup("remove test artifacts", true)

	transcript := recorder.Finalize()

	// Build raw data showing the test scenario.
	rawData := map[string]interface{}{
		"test_scenario": "mfa_bypass_attempt",
		"target_system": "mock-idp.example.com",
		"test_result":   "blocked",
		"mfa_policy": map[string]interface{}{
			"enforcement":   "required",
			"bypass_allowed": false,
		},
		"attempt_details": map[string]interface{}{
			"method":       "totp_replay",
			"token_status": "expired",
			"http_status":  403,
		},
	}
	rawJSON, _ := json.Marshal(rawData)

	safetyClass := string(module.SafetyClassSafe)

	ev := evidence.Evidence{
		ID:              uuid.New(),
		ControlID:       "mfa.enforcement",
		ClassUID:        1001,
		CategoryUID:     1,
		ActivityID:      2, // Active Test
		Time:            now,
		ConfidenceLevel: evidence.ActiveVerification,
		Metadata: evidence.Metadata{
			Module: evidence.ModuleInfo{
				Name:    "mock.safety_test",
				Version: "0.1.0",
				Type:    "tester",
			},
			Source: evidence.SourceInfo{
				System:     "mock",
				APIVersion: "v1",
				Endpoint:   "/api/v1/auth/test",
			},
			ProcessedTime:        now,
			SafetyClassification: &safetyClass,
		},
		Observables: []evidence.Observable{
			{Type: "resource", Value: "mfa_policy_global"},
			{Type: "user", Value: "test-user@example.com"},
		},
		StatusID:       evidence.StatusEffective,
		Status:         "MFA bypass attempt was correctly blocked",
		RawData:        rawJSON,
		Findings: []evidence.Finding{
			{
				Title:       "MFA Bypass Blocked",
				Description: "Simulated MFA bypass with expired TOTP token was correctly rejected with HTTP 403",
				SeverityID:  0, // informational
			},
		},
		TestTranscript: transcript,
	}

	return []evidence.Evidence{ev}, nil
}
