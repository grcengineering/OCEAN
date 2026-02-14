// Package module defines types for OCEAN's pluggable collector/tester modules.
package module

import "fmt"

// SafetyClassification categorizes a module's potential impact on the target
// system. This is a core safety concept: every module must declare what it
// does so operators can make informed decisions about automated execution.
type SafetyClassification string

const (
	// SafetyClassSafe indicates the module only reads publicly available
	// or non-sensitive configuration state.
	SafetyClassSafe SafetyClassification = "safe"

	// SafetyClassObservable indicates the module reads data in a way that
	// may be logged or visible to the target system (e.g., API calls that
	// appear in audit logs).
	SafetyClassObservable SafetyClassification = "observable"

	// SafetyClassReversible indicates the module makes changes to the target
	// system that can be automatically rolled back.
	SafetyClassReversible SafetyClassification = "reversible"

	// SafetyClassDestructive indicates the module makes changes that cannot
	// be automatically reversed.
	SafetyClassDestructive SafetyClassification = "destructive"
)

// Valid reports whether s is a recognized safety classification.
func (s SafetyClassification) Valid() bool {
	switch s {
	case SafetyClassSafe, SafetyClassObservable, SafetyClassReversible, SafetyClassDestructive:
		return true
	default:
		return false
	}
}

// RequiresExplicitAuth reports whether the safety level requires explicit
// operator authorization before execution. All levels except "safe" require
// authorization because they interact with the target system in observable ways.
func (s SafetyClassification) RequiresExplicitAuth() bool {
	return s == SafetyClassObservable || s == SafetyClassReversible || s == SafetyClassDestructive
}

// RequiresWarning reports whether the safety level requires a prominent
// warning before execution. Only destructive operations require a warning
// because their effects cannot be automatically reversed.
func (s SafetyClassification) RequiresWarning() bool {
	return s == SafetyClassDestructive
}

// EnvironmentScope indicates the environment in which a module operates.
type EnvironmentScope string

const (
	// ScopeProduction targets live production systems.
	ScopeProduction EnvironmentScope = "production"

	// ScopeStaging targets staging or pre-production systems.
	ScopeStaging EnvironmentScope = "staging"

	// ScopeIsolated targets isolated test environments with no production impact.
	ScopeIsolated EnvironmentScope = "isolated"
)

// Valid reports whether e is a recognized environment scope.
func (e EnvironmentScope) Valid() bool {
	switch e {
	case ScopeProduction, ScopeStaging, ScopeIsolated:
		return true
	default:
		return false
	}
}

// --- T068: Safety classification enforcement ---

// ValidateSafetyLevel checks whether the tester's safety classification is valid.
func ValidateSafetyLevel(t Tester) error {
	if !t.SafetyClass().Valid() {
		return fmt.Errorf("invalid safety classification %q for tester %q", t.SafetyClass(), t.ID())
	}
	return nil
}

// CanRunInEnvironment checks if a tester with the given safety classification
// can run in the target environment. Rules:
//   - "safe" testers can run in any environment
//   - "observable" testers can run in production and staging
//   - "reversible" testers can only run in staging and isolated
//   - "destructive" testers can only run in isolated
func CanRunInEnvironment(classification SafetyClassification, target EnvironmentScope) bool {
	switch classification {
	case SafetyClassSafe:
		return true
	case SafetyClassObservable:
		return target == ScopeProduction || target == ScopeStaging
	case SafetyClassReversible:
		return target == ScopeStaging || target == ScopeIsolated
	case SafetyClassDestructive:
		return target == ScopeIsolated
	default:
		return false
	}
}

// --- T108: Mixed safety classifications in composite controls ---

// safetyRank maps safety classifications to a numeric rank for comparison.
// Higher rank = more restrictive classification.
var safetyRank = map[SafetyClassification]int{
	SafetyClassSafe:        0,
	SafetyClassObservable:  1,
	SafetyClassReversible:  2,
	SafetyClassDestructive: 3,
}

// HighestSafetyClassification returns the most restrictive safety
// classification from a set of testers. When a composite control references
// multiple testers with different safety levels, the authorization
// requirement is the highest (most restrictive) classification.
//
// Returns SafetyClassSafe if the testers slice is empty.
func HighestSafetyClassification(testers []Tester) SafetyClassification {
	if len(testers) == 0 {
		return SafetyClassSafe
	}

	highest := SafetyClassSafe
	highestRank := 0

	for _, t := range testers {
		rank, ok := safetyRank[t.SafetyClass()]
		if !ok {
			// Unknown classification treated as most restrictive.
			return SafetyClassDestructive
		}
		if rank > highestRank {
			highestRank = rank
			highest = t.SafetyClass()
		}
	}

	return highest
}

// --- T069: Authorization prompt system ---

// AuthorizationLevel indicates how much authorization is required.
type AuthorizationLevel string

const (
	// AuthLevelAuto means no prompt needed (safe tests).
	AuthLevelAuto AuthorizationLevel = "auto"

	// AuthLevelPrompt means a simple confirmation is needed (observable tests).
	AuthLevelPrompt AuthorizationLevel = "prompt"

	// AuthLevelExplicit means explicit "yes" is required (reversible tests).
	AuthLevelExplicit AuthorizationLevel = "explicit"

	// AuthLevelWarning means a warning plus explicit "yes" is required (destructive tests).
	AuthLevelWarning AuthorizationLevel = "warning"
)

// RequiredAuthLevel returns the authorization level needed for a safety classification.
func RequiredAuthLevel(classification SafetyClassification) AuthorizationLevel {
	switch classification {
	case SafetyClassSafe:
		return AuthLevelAuto
	case SafetyClassObservable:
		return AuthLevelPrompt
	case SafetyClassReversible:
		return AuthLevelExplicit
	case SafetyClassDestructive:
		return AuthLevelWarning
	default:
		return AuthLevelWarning // Default to most restrictive
	}
}

// Authorizer handles test authorization. Implementations can be interactive (CLI)
// or pre-authorized (config/CI).
type Authorizer interface {
	Authorize(testName string, classification SafetyClassification, level AuthorizationLevel) (bool, error)
}

// AutoAuthorizer always authorizes safe tests and rejects everything else.
// Used for safe-only execution or CI with pre-approval for safe tests.
type AutoAuthorizer struct{}

// Authorize returns true only when the authorization level is AuthLevelAuto,
// meaning the test is classified as safe and requires no interactive prompt.
func (a *AutoAuthorizer) Authorize(_ string, _ SafetyClassification, level AuthorizationLevel) (bool, error) {
	return level == AuthLevelAuto, nil
}

// --- T070: Environment scope validation ---

// EnforceScope validates that a tester can run in the target environment.
// Returns an error with a clear explanation if scope is violated.
func EnforceScope(tester Tester, targetEnv EnvironmentScope) error {
	if !CanRunInEnvironment(tester.SafetyClass(), targetEnv) {
		return fmt.Errorf(
			"scope violation: tester %q has safety classification %q which cannot run in %q environment",
			tester.ID(), tester.SafetyClass(), targetEnv,
		)
	}
	return nil
}
