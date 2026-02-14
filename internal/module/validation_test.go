package module

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/grcengineering/ocean/internal/evidence"
)

// --- Test Helpers ---

// stubModule is a configurable Module implementation for validation tests.
type stubModule struct {
	id           string
	name         string
	version      string
	sourceSystem string
	evidTypes    []int
	credReqs     []CredentialReq
}

func (s *stubModule) ID() string                          { return s.id }
func (s *stubModule) Name() string                        { return s.name }
func (s *stubModule) Version() string                     { return s.version }
func (s *stubModule) SourceSystem() string                { return s.sourceSystem }
func (s *stubModule) EvidenceTypes() []int                { return s.evidTypes }
func (s *stubModule) CredentialRequirements() []CredentialReq { return s.credReqs }

// stubCollector wraps stubModule as a Collector.
type stubCollector struct {
	stubModule
}

func (s *stubCollector) Collect(_ context.Context, _ map[string]string) ([]evidence.Evidence, error) {
	return nil, nil
}

// stubTester wraps stubModule as a Tester with configurable safety fields.
type stubTester struct {
	stubModule
	safetyClass  SafetyClassification
	envScope     EnvironmentScope
	preFlight    []string
	cleanup      []string
}

func (s *stubTester) SafetyClass() SafetyClassification          { return s.safetyClass }
func (s *stubTester) EnvironmentScope() EnvironmentScope          { return s.envScope }
func (s *stubTester) PreFlightChecks() []string                   { return s.preFlight }
func (s *stubTester) CleanupProcedures() []string                 { return s.cleanup }
func (s *stubTester) Test(_ context.Context, _ map[string]string) ([]evidence.Evidence, error) {
	return nil, nil
}

// validModule returns a stubModule with all valid fields populated.
func validModule() stubModule {
	return stubModule{
		id:           "okta.mfa",
		name:         "Okta MFA Collector",
		version:      "1.0.0",
		sourceSystem: "okta",
		evidTypes:    []int{6003},
		credReqs:     []CredentialReq{{Name: "api_key", Type: "string", Description: "Okta API key", Required: true}},
	}
}

// --- T112-T113: Registry ListModules / ListByType / ListBySourceSystem ---

func TestListModules_Empty(t *testing.T) {
	reg := NewRegistry()
	infos := reg.ListModules()
	if len(infos) != 0 {
		t.Errorf("ListModules() on empty registry returned %d items, want 0", len(infos))
	}
}

func TestListModules_CollectorsAndTesters(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterCollector(&stubCollector{stubModule{
		id: "okta.mfa", name: "Okta MFA", version: "1.0.0",
		sourceSystem: "okta", evidTypes: []int{6003},
	}})
	reg.RegisterTester(&stubTester{
		stubModule: stubModule{
			id: "aws.sg.test", name: "AWS SG Tester", version: "2.0.0",
			sourceSystem: "aws", evidTypes: []int{4001},
		},
		safetyClass: SafetyClassObservable,
		envScope:    ScopeProduction,
	})

	infos := reg.ListModules()
	if len(infos) != 2 {
		t.Fatalf("ListModules() returned %d items, want 2", len(infos))
	}

	// Verify collector info
	var foundCollector, foundTester bool
	for _, info := range infos {
		if info.ID == "okta.mfa" {
			foundCollector = true
			if info.Type != "collector" {
				t.Errorf("collector type = %q, want %q", info.Type, "collector")
			}
			if info.Version != "1.0.0" {
				t.Errorf("collector version = %q, want %q", info.Version, "1.0.0")
			}
			if info.SourceSystem != "okta" {
				t.Errorf("collector source = %q, want %q", info.SourceSystem, "okta")
			}
			if info.SafetyClassification != "" {
				t.Errorf("collector safety = %q, want empty", info.SafetyClassification)
			}
		}
		if info.ID == "aws.sg.test" {
			foundTester = true
			if info.Type != "tester" {
				t.Errorf("tester type = %q, want %q", info.Type, "tester")
			}
			if info.SafetyClassification != "observable" {
				t.Errorf("tester safety = %q, want %q", info.SafetyClassification, "observable")
			}
			if info.EnvironmentScope != "production" {
				t.Errorf("tester scope = %q, want %q", info.EnvironmentScope, "production")
			}
		}
	}
	if !foundCollector {
		t.Error("ListModules() did not include registered collector")
	}
	if !foundTester {
		t.Error("ListModules() did not include registered tester")
	}
}

func TestListByType_Collectors(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterCollector(&stubCollector{stubModule{
		id: "okta.mfa", name: "Okta MFA", version: "1.0.0",
		sourceSystem: "okta", evidTypes: []int{6003},
	}})
	reg.RegisterTester(&stubTester{
		stubModule: stubModule{
			id: "aws.sg.test", name: "AWS SG Tester", version: "2.0.0",
			sourceSystem: "aws", evidTypes: []int{4001},
		},
		safetyClass: SafetyClassSafe,
		envScope:    ScopeIsolated,
	})

	collectors := reg.ListByType("collector")
	if len(collectors) != 1 {
		t.Fatalf("ListByType(collector) returned %d items, want 1", len(collectors))
	}
	if collectors[0].ID != "okta.mfa" {
		t.Errorf("ListByType(collector)[0].ID = %q, want %q", collectors[0].ID, "okta.mfa")
	}
}

func TestListByType_Testers(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterCollector(&stubCollector{stubModule{
		id: "okta.mfa", name: "Okta MFA", version: "1.0.0",
		sourceSystem: "okta", evidTypes: []int{6003},
	}})
	reg.RegisterTester(&stubTester{
		stubModule: stubModule{
			id: "aws.sg.test", name: "AWS SG Tester", version: "2.0.0",
			sourceSystem: "aws", evidTypes: []int{4001},
		},
		safetyClass: SafetyClassSafe,
		envScope:    ScopeIsolated,
	})

	testers := reg.ListByType("tester")
	if len(testers) != 1 {
		t.Fatalf("ListByType(tester) returned %d items, want 1", len(testers))
	}
	if testers[0].ID != "aws.sg.test" {
		t.Errorf("ListByType(tester)[0].ID = %q, want %q", testers[0].ID, "aws.sg.test")
	}
}

func TestListByType_InvalidType(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterCollector(&stubCollector{stubModule{
		id: "okta.mfa", name: "Okta MFA", version: "1.0.0",
		sourceSystem: "okta", evidTypes: []int{6003},
	}})

	result := reg.ListByType("invalid")
	if len(result) != 0 {
		t.Errorf("ListByType(invalid) returned %d items, want 0", len(result))
	}
}

func TestListBySourceSystem(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterCollector(&stubCollector{stubModule{
		id: "okta.mfa", name: "Okta MFA", version: "1.0.0",
		sourceSystem: "okta", evidTypes: []int{6003},
	}})
	reg.RegisterCollector(&stubCollector{stubModule{
		id: "okta.users", name: "Okta Users", version: "1.1.0",
		sourceSystem: "okta", evidTypes: []int{6004},
	}})
	reg.RegisterTester(&stubTester{
		stubModule: stubModule{
			id: "aws.sg.test", name: "AWS SG Tester", version: "2.0.0",
			sourceSystem: "aws", evidTypes: []int{4001},
		},
		safetyClass: SafetyClassSafe,
		envScope:    ScopeIsolated,
	})

	okta := reg.ListBySourceSystem("okta")
	if len(okta) != 2 {
		t.Fatalf("ListBySourceSystem(okta) returned %d items, want 2", len(okta))
	}

	aws := reg.ListBySourceSystem("aws")
	if len(aws) != 1 {
		t.Fatalf("ListBySourceSystem(aws) returned %d items, want 1", len(aws))
	}

	none := reg.ListBySourceSystem("github")
	if len(none) != 0 {
		t.Errorf("ListBySourceSystem(github) returned %d items, want 0", len(none))
	}
}

// --- T114: ValidateModule ---

func TestValidateModule_Valid(t *testing.T) {
	m := validModule()
	c := &stubCollector{m}
	errs := ValidateModule(c)
	if len(errs) != 0 {
		t.Errorf("ValidateModule(valid) returned %d errors, want 0:", len(errs))
		for _, e := range errs {
			t.Errorf("  - %s: %s", e.Field, e.Message)
		}
	}
}

func TestValidateModule_EmptyID(t *testing.T) {
	m := validModule()
	m.id = ""
	c := &stubCollector{m}
	errs := ValidateModule(c)
	if !hasValidationError(errs, "ID") {
		t.Error("ValidateModule(empty ID) should have ID error")
	}
}

func TestValidateModule_IDMissingDot(t *testing.T) {
	m := validModule()
	m.id = "oktamfa" // no dot separator
	c := &stubCollector{m}
	errs := ValidateModule(c)
	if !hasValidationError(errs, "ID") {
		t.Error("ValidateModule(ID without dot) should have ID format error")
	}
}

func TestValidateModule_EmptyName(t *testing.T) {
	m := validModule()
	m.name = ""
	c := &stubCollector{m}
	errs := ValidateModule(c)
	if !hasValidationError(errs, "Name") {
		t.Error("ValidateModule(empty Name) should have Name error")
	}
}

func TestValidateModule_EmptyVersion(t *testing.T) {
	m := validModule()
	m.version = ""
	c := &stubCollector{m}
	errs := ValidateModule(c)
	if !hasValidationError(errs, "Version") {
		t.Error("ValidateModule(empty Version) should have Version error")
	}
}

func TestValidateModule_InvalidVersion(t *testing.T) {
	m := validModule()
	m.version = "not-a-version"
	c := &stubCollector{m}
	errs := ValidateModule(c)
	if !hasValidationError(errs, "Version") {
		t.Error("ValidateModule(invalid version) should have Version format error")
	}
}

func TestValidateModule_ValidVersionFormats(t *testing.T) {
	validVersions := []string{"1.0.0", "0.1.0", "10.20.30", "1.0.0-alpha", "2.0.0-rc.1"}
	for _, ver := range validVersions {
		m := validModule()
		m.version = ver
		c := &stubCollector{m}
		errs := ValidateModule(c)
		if hasValidationError(errs, "Version") {
			t.Errorf("ValidateModule(version=%q) should not have Version error", ver)
		}
	}
}

func TestValidateModule_EmptySourceSystem(t *testing.T) {
	m := validModule()
	m.sourceSystem = ""
	c := &stubCollector{m}
	errs := ValidateModule(c)
	if !hasValidationError(errs, "SourceSystem") {
		t.Error("ValidateModule(empty SourceSystem) should have SourceSystem error")
	}
}

func TestValidateModule_EmptyEvidenceTypes(t *testing.T) {
	m := validModule()
	m.evidTypes = nil
	c := &stubCollector{m}
	errs := ValidateModule(c)
	if !hasValidationError(errs, "EvidenceTypes") {
		t.Error("ValidateModule(nil EvidenceTypes) should have EvidenceTypes error")
	}
}

func TestValidateModule_EmptyCredentialName(t *testing.T) {
	m := validModule()
	m.credReqs = []CredentialReq{{Name: "", Type: "string", Description: "key", Required: true}}
	c := &stubCollector{m}
	errs := ValidateModule(c)
	if !hasValidationError(errs, "CredentialRequirements") {
		t.Error("ValidateModule(empty credential name) should have CredentialRequirements error")
	}
}

func TestValidateModule_MultipleErrors(t *testing.T) {
	m := stubModule{} // all empty
	c := &stubCollector{m}
	errs := ValidateModule(c)
	if len(errs) < 4 {
		t.Errorf("ValidateModule(all empty) returned %d errors, want at least 4", len(errs))
	}
}

// --- T115: ValidateTester ---

func TestValidateTester_Valid(t *testing.T) {
	st := &stubTester{
		stubModule:  validModule(),
		safetyClass: SafetyClassObservable,
		envScope:    ScopeProduction,
		cleanup:     []string{"remove test artifacts"},
	}
	errs := ValidateTester(st)
	if len(errs) != 0 {
		t.Errorf("ValidateTester(valid) returned %d errors:", len(errs))
		for _, e := range errs {
			t.Errorf("  - %s: %s", e.Field, e.Message)
		}
	}
}

func TestValidateTester_InvalidSafetyClassification(t *testing.T) {
	st := &stubTester{
		stubModule:  validModule(),
		safetyClass: SafetyClassification("bogus"),
		envScope:    ScopeProduction,
		cleanup:     []string{"cleanup"},
	}
	errs := ValidateTester(st)
	if !hasValidationError(errs, "SafetyClassification") {
		t.Error("ValidateTester(invalid safety) should have SafetyClassification error")
	}
}

func TestValidateTester_InvalidEnvironmentScope(t *testing.T) {
	st := &stubTester{
		stubModule:  validModule(),
		safetyClass: SafetyClassSafe,
		envScope:    EnvironmentScope("bogus"),
	}
	errs := ValidateTester(st)
	if !hasValidationError(errs, "EnvironmentScope") {
		t.Error("ValidateTester(invalid scope) should have EnvironmentScope error")
	}
}

func TestValidateTester_SafeWithNoCleanup(t *testing.T) {
	st := &stubTester{
		stubModule:  validModule(),
		safetyClass: SafetyClassSafe,
		envScope:    ScopeIsolated,
		cleanup:     nil, // safe modules don't need cleanup
	}
	errs := ValidateTester(st)
	if hasValidationError(errs, "CleanupProcedures") {
		t.Error("ValidateTester(safe, no cleanup) should NOT have CleanupProcedures error")
	}
}

func TestValidateTester_ObservableWithNoCleanup(t *testing.T) {
	st := &stubTester{
		stubModule:  validModule(),
		safetyClass: SafetyClassObservable,
		envScope:    ScopeProduction,
		cleanup:     nil, // observable requires cleanup
	}
	errs := ValidateTester(st)
	if !hasValidationError(errs, "CleanupProcedures") {
		t.Error("ValidateTester(observable, no cleanup) should have CleanupProcedures error")
	}
}

func TestValidateTester_ReversibleWithNoCleanup(t *testing.T) {
	st := &stubTester{
		stubModule:  validModule(),
		safetyClass: SafetyClassReversible,
		envScope:    ScopeStaging,
		cleanup:     nil, // reversible requires cleanup
	}
	errs := ValidateTester(st)
	if !hasValidationError(errs, "CleanupProcedures") {
		t.Error("ValidateTester(reversible, no cleanup) should have CleanupProcedures error")
	}
}

func TestValidateTester_DestructiveWithNoCleanup(t *testing.T) {
	st := &stubTester{
		stubModule:  validModule(),
		safetyClass: SafetyClassDestructive,
		envScope:    ScopeIsolated,
		cleanup:     nil, // destructive requires cleanup
	}
	errs := ValidateTester(st)
	if !hasValidationError(errs, "CleanupProcedures") {
		t.Error("ValidateTester(destructive, no cleanup) should have CleanupProcedures error")
	}
}

func TestValidateTester_IncludesBaseModuleErrors(t *testing.T) {
	st := &stubTester{
		stubModule:  stubModule{}, // all empty
		safetyClass: SafetyClassification(""),
		envScope:    EnvironmentScope(""),
	}
	errs := ValidateTester(st)
	// Should include both base module errors AND tester-specific errors
	if !hasValidationError(errs, "ID") {
		t.Error("ValidateTester should include base module ID error")
	}
	if !hasValidationError(errs, "SafetyClassification") {
		t.Error("ValidateTester should include SafetyClassification error")
	}
}

// --- T116: ValidateAndRegister ---

func TestValidateAndRegister_ValidCollector(t *testing.T) {
	reg := NewRegistry()
	c := &stubCollector{validModule()}
	err := ValidateAndRegister(reg, c)
	if err != nil {
		t.Fatalf("ValidateAndRegister(valid collector) returned error: %v", err)
	}

	// Verify it was registered
	got, getErr := reg.GetCollector("okta.mfa")
	if getErr != nil {
		t.Fatalf("GetCollector after register returned error: %v", getErr)
	}
	if got.ID() != "okta.mfa" {
		t.Errorf("registered collector ID = %q, want %q", got.ID(), "okta.mfa")
	}
}

func TestValidateAndRegister_ValidTester(t *testing.T) {
	reg := NewRegistry()
	st := &stubTester{
		stubModule:  validModule(),
		safetyClass: SafetyClassObservable,
		envScope:    ScopeProduction,
		cleanup:     []string{"remove artifacts"},
	}
	err := ValidateAndRegister(reg, st)
	if err != nil {
		t.Fatalf("ValidateAndRegister(valid tester) returned error: %v", err)
	}

	got, getErr := reg.GetTester("okta.mfa")
	if getErr != nil {
		t.Fatalf("GetTester after register returned error: %v", getErr)
	}
	if got.ID() != "okta.mfa" {
		t.Errorf("registered tester ID = %q, want %q", got.ID(), "okta.mfa")
	}
}

func TestValidateAndRegister_InvalidModule(t *testing.T) {
	reg := NewRegistry()
	c := &stubCollector{stubModule{}} // all empty
	err := ValidateAndRegister(reg, c)
	if err == nil {
		t.Fatal("ValidateAndRegister(invalid module) should return error")
	}
}

func TestValidateAndRegister_TesterMissingSafety(t *testing.T) {
	reg := NewRegistry()
	st := &stubTester{
		stubModule:  validModule(),
		safetyClass: SafetyClassification(""), // missing
		envScope:    ScopeProduction,
	}
	err := ValidateAndRegister(reg, st)
	if err == nil {
		t.Fatal("ValidateAndRegister(tester missing safety) should return error")
	}
}

// --- T120: ValidateEvidenceOutput ---

func TestValidateEvidenceOutput_Valid(t *testing.T) {
	ev := evidence.Evidence{
		ID:              uuid.New(),
		ControlID:       "AC-2",
		Time:            time.Now(),
		StatusID:        evidence.StatusEffective,
		ConfidenceLevel: evidence.PassiveObservation,
	}
	errs := ValidateEvidenceOutput(ev)
	if len(errs) != 0 {
		t.Errorf("ValidateEvidenceOutput(valid) returned %d errors:", len(errs))
		for _, e := range errs {
			t.Errorf("  - %s: %s", e.Field, e.Message)
		}
	}
}

func TestValidateEvidenceOutput_ZeroID(t *testing.T) {
	ev := evidence.Evidence{
		ControlID:       "AC-2",
		Time:            time.Now(),
		StatusID:        evidence.StatusEffective,
		ConfidenceLevel: evidence.PassiveObservation,
	}
	errs := ValidateEvidenceOutput(ev)
	if !hasValidationError(errs, "ID") {
		t.Error("ValidateEvidenceOutput(zero ID) should have ID error")
	}
}

func TestValidateEvidenceOutput_EmptyControlID(t *testing.T) {
	ev := evidence.Evidence{
		ID:              uuid.New(),
		ControlID:       "",
		Time:            time.Now(),
		StatusID:        evidence.StatusEffective,
		ConfidenceLevel: evidence.PassiveObservation,
	}
	errs := ValidateEvidenceOutput(ev)
	if !hasValidationError(errs, "ControlID") {
		t.Error("ValidateEvidenceOutput(empty ControlID) should have ControlID error")
	}
}

func TestValidateEvidenceOutput_ZeroTime(t *testing.T) {
	ev := evidence.Evidence{
		ID:              uuid.New(),
		ControlID:       "AC-2",
		StatusID:        evidence.StatusEffective,
		ConfidenceLevel: evidence.PassiveObservation,
	}
	errs := ValidateEvidenceOutput(ev)
	if !hasValidationError(errs, "Time") {
		t.Error("ValidateEvidenceOutput(zero Time) should have Time error")
	}
}

func TestValidateEvidenceOutput_InvalidStatusID(t *testing.T) {
	ev := evidence.Evidence{
		ID:              uuid.New(),
		ControlID:       "AC-2",
		Time:            time.Now(),
		StatusID:        evidence.StatusID(42), // invalid
		ConfidenceLevel: evidence.PassiveObservation,
	}
	errs := ValidateEvidenceOutput(ev)
	if !hasValidationError(errs, "StatusID") {
		t.Error("ValidateEvidenceOutput(invalid StatusID) should have StatusID error")
	}
}

func TestValidateEvidenceOutput_InvalidConfidenceLevel(t *testing.T) {
	ev := evidence.Evidence{
		ID:              uuid.New(),
		ControlID:       "AC-2",
		Time:            time.Now(),
		StatusID:        evidence.StatusEffective,
		ConfidenceLevel: evidence.ConfidenceLevel("invalid"),
	}
	errs := ValidateEvidenceOutput(ev)
	if !hasValidationError(errs, "ConfidenceLevel") {
		t.Error("ValidateEvidenceOutput(invalid ConfidenceLevel) should have ConfidenceLevel error")
	}
}

func TestValidateEvidenceOutput_MultipleErrors(t *testing.T) {
	ev := evidence.Evidence{} // all zero values
	errs := ValidateEvidenceOutput(ev)
	if len(errs) < 3 {
		t.Errorf("ValidateEvidenceOutput(all zero) returned %d errors, want at least 3", len(errs))
	}
}

// --- Test Helpers ---

func hasValidationError(errs []ValidationError, field string) bool {
	for _, e := range errs {
		if e.Field == field {
			return true
		}
	}
	return false
}
