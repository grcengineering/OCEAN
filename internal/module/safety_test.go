package module

import (
	"context"
	"testing"

	"github.com/grcengineering/ocean/internal/evidence"
)

// fakeTester is a minimal Tester implementation for testing safety logic.
type fakeTester struct {
	safetyClass SafetyClassification
	envScope    EnvironmentScope
}

func (f *fakeTester) ID() string                                 { return "fake.tester" }
func (f *fakeTester) Name() string                               { return "Fake Tester" }
func (f *fakeTester) Version() string                            { return "0.0.1" }
func (f *fakeTester) SourceSystem() string                       { return "fake" }
func (f *fakeTester) EvidenceTypes() []int                       { return []int{9999} }
func (f *fakeTester) CredentialRequirements() []CredentialReq    { return nil }
func (f *fakeTester) SafetyClass() SafetyClassification          { return f.safetyClass }
func (f *fakeTester) EnvironmentScope() EnvironmentScope         { return f.envScope }
func (f *fakeTester) PreFlightChecks() []string                  { return []string{"check1"} }
func (f *fakeTester) CleanupProcedures() []string                { return []string{"cleanup1"} }
func (f *fakeTester) Test(_ context.Context, _ map[string]string) ([]evidence.Evidence, error) {
	return nil, nil
}

func TestValidateSafetyLevel_Valid(t *testing.T) {
	validClasses := []SafetyClassification{
		SafetyClassSafe,
		SafetyClassObservable,
		SafetyClassReversible,
		SafetyClassDestructive,
	}

	for _, sc := range validClasses {
		tester := &fakeTester{safetyClass: sc, envScope: ScopeProduction}
		if err := ValidateSafetyLevel(tester); err != nil {
			t.Errorf("ValidateSafetyLevel(%q) returned error: %v", sc, err)
		}
	}
}

func TestValidateSafetyLevel_Invalid(t *testing.T) {
	tester := &fakeTester{safetyClass: SafetyClassification("bogus"), envScope: ScopeProduction}
	if err := ValidateSafetyLevel(tester); err == nil {
		t.Error("ValidateSafetyLevel(\"bogus\") expected error, got nil")
	}
}

func TestCanRunInEnvironment(t *testing.T) {
	tests := []struct {
		classification SafetyClassification
		target         EnvironmentScope
		want           bool
	}{
		// safe: can run anywhere
		{SafetyClassSafe, ScopeProduction, true},
		{SafetyClassSafe, ScopeStaging, true},
		{SafetyClassSafe, ScopeIsolated, true},

		// observable: production and staging only
		{SafetyClassObservable, ScopeProduction, true},
		{SafetyClassObservable, ScopeStaging, true},
		{SafetyClassObservable, ScopeIsolated, false},

		// reversible: staging and isolated only
		{SafetyClassReversible, ScopeProduction, false},
		{SafetyClassReversible, ScopeStaging, true},
		{SafetyClassReversible, ScopeIsolated, true},

		// destructive: isolated only
		{SafetyClassDestructive, ScopeProduction, false},
		{SafetyClassDestructive, ScopeStaging, false},
		{SafetyClassDestructive, ScopeIsolated, true},
	}

	for _, tt := range tests {
		got := CanRunInEnvironment(tt.classification, tt.target)
		if got != tt.want {
			t.Errorf("CanRunInEnvironment(%q, %q) = %v, want %v",
				tt.classification, tt.target, got, tt.want)
		}
	}
}

func TestEnforceScope_Allowed(t *testing.T) {
	tester := &fakeTester{safetyClass: SafetyClassSafe, envScope: ScopeProduction}
	if err := EnforceScope(tester, ScopeProduction); err != nil {
		t.Errorf("EnforceScope(safe, production) returned error: %v", err)
	}
}

func TestEnforceScope_Denied(t *testing.T) {
	tester := &fakeTester{safetyClass: SafetyClassDestructive, envScope: ScopeIsolated}
	err := EnforceScope(tester, ScopeProduction)
	if err == nil {
		t.Error("EnforceScope(destructive, production) expected error, got nil")
	}
}

func TestRequiredAuthLevel(t *testing.T) {
	tests := []struct {
		classification SafetyClassification
		want           AuthorizationLevel
	}{
		{SafetyClassSafe, AuthLevelAuto},
		{SafetyClassObservable, AuthLevelPrompt},
		{SafetyClassReversible, AuthLevelExplicit},
		{SafetyClassDestructive, AuthLevelWarning},
	}

	for _, tt := range tests {
		got := RequiredAuthLevel(tt.classification)
		if got != tt.want {
			t.Errorf("RequiredAuthLevel(%q) = %q, want %q",
				tt.classification, got, tt.want)
		}
	}
}

func TestHighestSafetyClassification_Empty(t *testing.T) {
	result := HighestSafetyClassification(nil)
	if result != SafetyClassSafe {
		t.Errorf("HighestSafetyClassification(nil) = %q, want %q", result, SafetyClassSafe)
	}
}

func TestHighestSafetyClassification_SingleSafe(t *testing.T) {
	testers := []Tester{
		&fakeTester{safetyClass: SafetyClassSafe},
	}
	result := HighestSafetyClassification(testers)
	if result != SafetyClassSafe {
		t.Errorf("expected %q, got %q", SafetyClassSafe, result)
	}
}

func TestHighestSafetyClassification_MixedLevels(t *testing.T) {
	tests := []struct {
		name    string
		testers []Tester
		want    SafetyClassification
	}{
		{
			name: "safe and observable",
			testers: []Tester{
				&fakeTester{safetyClass: SafetyClassSafe},
				&fakeTester{safetyClass: SafetyClassObservable},
			},
			want: SafetyClassObservable,
		},
		{
			name: "observable and reversible",
			testers: []Tester{
				&fakeTester{safetyClass: SafetyClassObservable},
				&fakeTester{safetyClass: SafetyClassReversible},
			},
			want: SafetyClassReversible,
		},
		{
			name: "all levels including destructive",
			testers: []Tester{
				&fakeTester{safetyClass: SafetyClassSafe},
				&fakeTester{safetyClass: SafetyClassObservable},
				&fakeTester{safetyClass: SafetyClassReversible},
				&fakeTester{safetyClass: SafetyClassDestructive},
			},
			want: SafetyClassDestructive,
		},
		{
			name: "multiple safe",
			testers: []Tester{
				&fakeTester{safetyClass: SafetyClassSafe},
				&fakeTester{safetyClass: SafetyClassSafe},
			},
			want: SafetyClassSafe,
		},
		{
			name: "reversible takes precedence over observable",
			testers: []Tester{
				&fakeTester{safetyClass: SafetyClassReversible},
				&fakeTester{safetyClass: SafetyClassObservable},
				&fakeTester{safetyClass: SafetyClassSafe},
			},
			want: SafetyClassReversible,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HighestSafetyClassification(tt.testers)
			if got != tt.want {
				t.Errorf("HighestSafetyClassification() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAutoAuthorizer_ApprovesOnlySafe(t *testing.T) {
	auth := &AutoAuthorizer{}

	ok, err := auth.Authorize("test", SafetyClassSafe, AuthLevelAuto)
	if err != nil {
		t.Fatalf("Authorize(safe, auto) returned error: %v", err)
	}
	if !ok {
		t.Error("AutoAuthorizer should approve safe/auto tests")
	}

	ok, err = auth.Authorize("test", SafetyClassObservable, AuthLevelPrompt)
	if err != nil {
		t.Fatalf("Authorize(observable, prompt) returned error: %v", err)
	}
	if ok {
		t.Error("AutoAuthorizer should not approve non-auto levels")
	}
}
