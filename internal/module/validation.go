package module

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/grcengineering/ocean/internal/evidence"
)

// ValidationError describes a single validation failure for a module or evidence record.
type ValidationError struct {
	Field   string
	Message string
}

func (v ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", v.Field, v.Message)
}

// semverPattern matches semantic version strings: major.minor.patch with optional prerelease.
var semverPattern = regexp.MustCompile(`^\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?$`)

// idPattern matches module IDs in system.name format (at least one dot separator,
// alphanumeric segments with hyphens allowed).
var idPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*(\.[a-zA-Z0-9][a-zA-Z0-9_-]*)+$`)

// --- T114: ValidateModule ---

// ValidateModule checks that a Module satisfies all base validation rules:
//   - ID is non-empty and follows system.name format (dot-separated)
//   - Name is non-empty
//   - Version is non-empty and follows semver format
//   - SourceSystem is non-empty
//   - EvidenceTypes is non-empty
//   - CredentialRequirements entries have non-empty Name fields
func ValidateModule(m Module) []ValidationError {
	var errs []ValidationError

	// ID validation
	id := strings.TrimSpace(m.ID())
	if id == "" {
		errs = append(errs, ValidationError{Field: "ID", Message: "must not be empty"})
	} else if !idPattern.MatchString(id) {
		errs = append(errs, ValidationError{Field: "ID", Message: fmt.Sprintf(
			"%q must follow system.name format (e.g., okta.mfa)", id)})
	}

	// Name validation
	if strings.TrimSpace(m.Name()) == "" {
		errs = append(errs, ValidationError{Field: "Name", Message: "must not be empty"})
	}

	// Version validation
	ver := strings.TrimSpace(m.Version())
	if ver == "" {
		errs = append(errs, ValidationError{Field: "Version", Message: "must not be empty"})
	} else if !semverPattern.MatchString(ver) {
		errs = append(errs, ValidationError{Field: "Version", Message: fmt.Sprintf(
			"%q must follow semver format (e.g., 1.0.0)", ver)})
	}

	// SourceSystem validation
	if strings.TrimSpace(m.SourceSystem()) == "" {
		errs = append(errs, ValidationError{Field: "SourceSystem", Message: "must not be empty"})
	}

	// EvidenceTypes validation
	if len(m.EvidenceTypes()) == 0 {
		errs = append(errs, ValidationError{Field: "EvidenceTypes", Message: "must contain at least one evidence type"})
	}

	// CredentialRequirements validation
	for i, cred := range m.CredentialRequirements() {
		if strings.TrimSpace(cred.Name) == "" {
			errs = append(errs, ValidationError{
				Field:   "CredentialRequirements",
				Message: fmt.Sprintf("credential at index %d has empty name", i),
			})
		}
	}

	return errs
}

// --- T115: ValidateTester ---

// ValidateTester checks all base module validation rules plus tester-specific rules:
//   - SafetyClassification is declared and valid
//   - CleanupProcedures exist for non-safe classifications
//   - EnvironmentScope is declared and valid
func ValidateTester(t Tester) []ValidationError {
	errs := ValidateModule(t)

	// SafetyClassification validation
	if !t.SafetyClass().Valid() {
		errs = append(errs, ValidationError{
			Field:   "SafetyClassification",
			Message: fmt.Sprintf("%q is not a valid safety classification (safe/observable/reversible/destructive)", t.SafetyClass()),
		})
	}

	// EnvironmentScope validation
	if !t.EnvironmentScope().Valid() {
		errs = append(errs, ValidationError{
			Field:   "EnvironmentScope",
			Message: fmt.Sprintf("%q is not a valid environment scope (production/staging/isolated)", t.EnvironmentScope()),
		})
	}

	// Cleanup procedures required for non-safe classifications
	if t.SafetyClass().Valid() && t.SafetyClass() != SafetyClassSafe {
		if len(t.CleanupProcedures()) == 0 {
			errs = append(errs, ValidationError{
				Field:   "CleanupProcedures",
				Message: fmt.Sprintf("testers with %q safety classification must declare cleanup procedures", t.SafetyClass()),
			})
		}
	}

	return errs
}

// --- T116: ValidateAndRegister ---

// ValidateAndRegister validates a module and registers it in the registry if valid.
// For Tester implementations, it runs tester-specific validation.
// Returns an error if validation fails, with all validation errors included.
func ValidateAndRegister(reg *Registry, m Module) error {
	var errs []ValidationError

	// Check if the module is a Tester -- run tester-specific validation
	if t, ok := m.(Tester); ok {
		errs = ValidateTester(t)
	} else {
		errs = ValidateModule(m)
	}

	if len(errs) > 0 {
		var msgs []string
		for _, e := range errs {
			msgs = append(msgs, e.Error())
		}
		return fmt.Errorf("module %q validation failed: %s", m.ID(), strings.Join(msgs, "; "))
	}

	// Register based on type
	if t, ok := m.(Tester); ok {
		reg.RegisterTester(t)
	} else if c, ok := m.(Collector); ok {
		reg.RegisterCollector(c)
	} else {
		return fmt.Errorf("module %q implements neither Collector nor Tester", m.ID())
	}

	return nil
}

// --- T120: ValidateEvidenceOutput ---

// ValidateEvidenceOutput checks that evidence output from a module is well-formed:
//   - ID is non-zero (UUID set)
//   - ControlID is non-empty
//   - Time is non-zero
//   - StatusID is a valid value (0, 1, 2, or 99)
//   - ConfidenceLevel is a valid value
func ValidateEvidenceOutput(ev evidence.Evidence) []ValidationError {
	var errs []ValidationError

	if ev.ID == uuid.Nil {
		errs = append(errs, ValidationError{Field: "ID", Message: "must not be zero UUID"})
	}

	if strings.TrimSpace(ev.ControlID) == "" {
		errs = append(errs, ValidationError{Field: "ControlID", Message: "must not be empty"})
	}

	if ev.Time.IsZero() || ev.Time.Equal(time.Time{}) {
		errs = append(errs, ValidationError{Field: "Time", Message: "must not be zero time"})
	}

	if !isValidStatusID(ev.StatusID) {
		errs = append(errs, ValidationError{
			Field:   "StatusID",
			Message: fmt.Sprintf("status_id %d is not valid (must be 0, 1, 2, or 99)", ev.StatusID),
		})
	}

	if !ev.ConfidenceLevel.Valid() {
		errs = append(errs, ValidationError{
			Field:   "ConfidenceLevel",
			Message: fmt.Sprintf("%q is not a valid confidence level", ev.ConfidenceLevel),
		})
	}

	return errs
}

// isValidStatusID checks if a StatusID is one of the recognized values.
func isValidStatusID(s evidence.StatusID) bool {
	switch s {
	case evidence.StatusUnknown, evidence.StatusEffective, evidence.StatusIneffective, evidence.StatusOther:
		return true
	default:
		return false
	}
}
