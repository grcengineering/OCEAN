package evidence

import (
	"fmt"

	"github.com/google/uuid"
)

// Validate checks that an Evidence record satisfies all invariants required
// by OCEAN's evidence schema. It returns the first validation error found,
// or nil if the record is valid.
func (e *Evidence) Validate() error {
	// Required fields: ID
	if e.ID == uuid.Nil {
		return fmt.Errorf("evidence: ID is required (must be non-zero UUID)")
	}

	// Required fields: ControlID
	if e.ControlID == "" {
		return fmt.Errorf("evidence: ControlID is required")
	}

	// Required fields: Time (must not be zero)
	if e.Time.IsZero() {
		return fmt.Errorf("evidence: Time is required (must not be zero)")
	}

	// Required fields: Status
	if e.Status == "" {
		return fmt.Errorf("evidence: Status is required")
	}

	// Required fields: RawData
	if e.RawData == nil {
		return fmt.Errorf("evidence: RawData is required")
	}

	// ConfidenceLevel must be a recognized value.
	if !e.ConfidenceLevel.Valid() {
		return fmt.Errorf("evidence: invalid ConfidenceLevel %q (must be %q or %q)",
			e.ConfidenceLevel, PassiveObservation, ActiveVerification)
	}

	// StatusID must be one of the defined constants.
	if !validStatusID(e.StatusID) {
		return fmt.Errorf("evidence: invalid StatusID %d (must be 0, 1, 2, or 99)", e.StatusID)
	}

	// Confidence/transcript consistency:
	//   active_verification  -> TestTranscript MUST be present
	//   passive_observation  -> TestTranscript MUST be nil
	if e.ConfidenceLevel == ActiveVerification && e.TestTranscript == nil {
		return fmt.Errorf("evidence: TestTranscript is required when ConfidenceLevel is %q", ActiveVerification)
	}
	if e.ConfidenceLevel == PassiveObservation && e.TestTranscript != nil {
		return fmt.Errorf("evidence: TestTranscript must be nil when ConfidenceLevel is %q", PassiveObservation)
	}

	// Metadata.Module fields must be non-empty.
	if e.Metadata.Module.Name == "" {
		return fmt.Errorf("evidence: Metadata.Module.Name is required")
	}
	if e.Metadata.Module.Version == "" {
		return fmt.Errorf("evidence: Metadata.Module.Version is required")
	}
	if e.Metadata.Module.Type == "" {
		return fmt.Errorf("evidence: Metadata.Module.Type is required")
	}

	// Metadata.Source fields must be non-empty.
	if e.Metadata.Source.System == "" {
		return fmt.Errorf("evidence: Metadata.Source.System is required")
	}
	if e.Metadata.Source.APIVersion == "" {
		return fmt.Errorf("evidence: Metadata.Source.APIVersion is required")
	}
	if e.Metadata.Source.Endpoint == "" {
		return fmt.Errorf("evidence: Metadata.Source.Endpoint is required")
	}

	// Attestation.Digest must be non-empty.
	if e.Attestation.Digest == "" {
		return fmt.Errorf("evidence: Attestation.Digest is required")
	}

	// Attestation.Type must be "collection" or "evaluation".
	if e.Attestation.Type != "collection" && e.Attestation.Type != "evaluation" {
		return fmt.Errorf("evidence: invalid Attestation.Type %q (must be %q or %q)",
			e.Attestation.Type, "collection", "evaluation")
	}

	return nil
}

// ValidateAll validates a slice of Evidence records, returning the first error
// encountered. It returns nil for empty or nil slices.
func ValidateAll(evidences []Evidence) error {
	for i := range evidences {
		if err := evidences[i].Validate(); err != nil {
			return fmt.Errorf("evidence[%d]: %w", i, err)
		}
	}
	return nil
}

// validStatusID reports whether sid is one of the defined StatusID constants.
func validStatusID(sid StatusID) bool {
	switch sid {
	case StatusUnknown, StatusEffective, StatusIneffective, StatusOther:
		return true
	default:
		return false
	}
}
