// Package evidence defines the core evidence schema for OCEAN.
package evidence

// ConfidenceLevel represents the degree of confidence in an evidence record.
// Passive observation means the system read data; active verification means
// the system performed a test to confirm the control's effectiveness.
type ConfidenceLevel string

const (
	// PassiveObservation indicates evidence was gathered by reading state
	// (e.g., listing MFA policies via API).
	PassiveObservation ConfidenceLevel = "passive_observation"

	// ActiveVerification indicates evidence was gathered by performing an
	// active test (e.g., attempting login without MFA to confirm it is blocked).
	ActiveVerification ConfidenceLevel = "active_verification"
)

// Valid reports whether c is a recognized confidence level.
func (c ConfidenceLevel) Valid() bool {
	return c == PassiveObservation || c == ActiveVerification
}
