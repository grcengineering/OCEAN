package eval

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/grcengineering/ocean/internal/evidence"
)

// --- T095: Preset registry tests ---

func TestPresetRegistry_AllEffective(t *testing.T) {
	expr, ok := presets["all_effective"]
	if !ok {
		t.Fatal("preset 'all_effective' not found in registry")
	}
	if expr == "" {
		t.Fatal("preset 'all_effective' has empty expression")
	}
}

func TestPresetRegistry_AnyEffective(t *testing.T) {
	expr, ok := presets["any_effective"]
	if !ok {
		t.Fatal("preset 'any_effective' not found in registry")
	}
	if expr == "" {
		t.Fatal("preset 'any_effective' has empty expression")
	}
}

func TestPresetRegistry_ActiveVerified(t *testing.T) {
	expr, ok := presets["active_verified"]
	if !ok {
		t.Fatal("preset 'active_verified' not found in registry")
	}
	if expr == "" {
		t.Fatal("preset 'active_verified' has empty expression")
	}
}

// --- T096: ExpandPreset tests ---

func TestExpandPreset_KnownPreset(t *testing.T) {
	expr, err := ExpandPreset("all_effective")
	if err != nil {
		t.Fatalf("ExpandPreset('all_effective') error = %v", err)
	}
	if expr == "" {
		t.Fatal("ExpandPreset('all_effective') returned empty string")
	}
}

func TestExpandPreset_UnknownPreset(t *testing.T) {
	_, err := ExpandPreset("nonexistent_preset")
	if err == nil {
		t.Fatal("ExpandPreset('nonexistent_preset') expected error, got nil")
	}
}

func TestExpandPreset_AllPresetsCompile(t *testing.T) {
	// Every preset expression must be a valid CEL expression.
	for name := range presets {
		expr, err := ExpandPreset(name)
		if err != nil {
			t.Fatalf("ExpandPreset(%q) error = %v", name, err)
		}

		compiled, err := CompileExpression(expr)
		if err != nil {
			t.Errorf("preset %q expression %q failed to compile: %v", name, expr, err)
		}
		if compiled == nil {
			t.Errorf("preset %q compiled to nil", name)
		}
	}
}

// --- T097: Presets evaluate correctly end-to-end ---

func makePresetTestEvidence(statusID evidence.StatusID, conf evidence.ConfidenceLevel) evidence.Evidence {
	return evidence.Evidence{
		ID:              uuid.New(),
		ControlID:       "test.control",
		ClassUID:        1001,
		CategoryUID:     1,
		ActivityID:      1,
		Time:            time.Now().UTC(),
		ConfidenceLevel: conf,
		StatusID:        statusID,
		Status: func() string {
			switch statusID {
			case evidence.StatusEffective:
				return "effective"
			case evidence.StatusIneffective:
				return "ineffective"
			default:
				return "unknown"
			}
		}(),
		RawData: json.RawMessage(`{"test": true}`),
	}
}

func TestPreset_AllEffective_EvaluatesCorrectly(t *testing.T) {
	expr, err := ExpandPreset("all_effective")
	if err != nil {
		t.Fatalf("ExpandPreset error: %v", err)
	}

	compiled, err := CompileExpression(expr)
	if err != nil {
		t.Fatalf("CompileExpression error: %v", err)
	}

	// All effective => true.
	allEffective := []evidence.Evidence{
		makePresetTestEvidence(evidence.StatusEffective, evidence.PassiveObservation),
		makePresetTestEvidence(evidence.StatusEffective, evidence.ActiveVerification),
	}

	result, err := Evaluate(compiled, allEffective)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if !result {
		t.Error("all_effective preset should return true when all evidence is effective")
	}

	// Has ineffective => false.
	mixed := []evidence.Evidence{
		makePresetTestEvidence(evidence.StatusEffective, evidence.PassiveObservation),
		makePresetTestEvidence(evidence.StatusIneffective, evidence.PassiveObservation),
	}

	result, err = Evaluate(compiled, mixed)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if result {
		t.Error("all_effective preset should return false when some evidence is ineffective")
	}
}

func TestPreset_AnyEffective_EvaluatesCorrectly(t *testing.T) {
	expr, err := ExpandPreset("any_effective")
	if err != nil {
		t.Fatalf("ExpandPreset error: %v", err)
	}

	compiled, err := CompileExpression(expr)
	if err != nil {
		t.Fatalf("CompileExpression error: %v", err)
	}

	// Mix of effective and ineffective => true.
	mixed := []evidence.Evidence{
		makePresetTestEvidence(evidence.StatusEffective, evidence.PassiveObservation),
		makePresetTestEvidence(evidence.StatusIneffective, evidence.PassiveObservation),
	}

	result, err := Evaluate(compiled, mixed)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if !result {
		t.Error("any_effective preset should return true when any evidence is effective")
	}

	// No effective evidence => false.
	allIneffective := []evidence.Evidence{
		makePresetTestEvidence(evidence.StatusIneffective, evidence.PassiveObservation),
	}

	result, err = Evaluate(compiled, allIneffective)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if result {
		t.Error("any_effective preset should return false when no evidence is effective")
	}
}

func TestPreset_ActiveVerified_EvaluatesCorrectly(t *testing.T) {
	expr, err := ExpandPreset("active_verified")
	if err != nil {
		t.Fatalf("ExpandPreset error: %v", err)
	}

	compiled, err := CompileExpression(expr)
	if err != nil {
		t.Fatalf("CompileExpression error: %v", err)
	}

	// Passive only => false (no active).
	passiveOnly := []evidence.Evidence{
		makePresetTestEvidence(evidence.StatusEffective, evidence.PassiveObservation),
	}

	result, err := Evaluate(compiled, passiveOnly)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if result {
		t.Error("active_verified preset should return false with only passive evidence")
	}

	// Active + effective => true.
	activeEffective := []evidence.Evidence{
		makePresetTestEvidence(evidence.StatusEffective, evidence.PassiveObservation),
		makePresetTestEvidence(evidence.StatusEffective, evidence.ActiveVerification),
	}

	result, err = Evaluate(compiled, activeEffective)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if !result {
		t.Error("active_verified preset should return true with active + all effective evidence")
	}
}

// --- T097: ResolveExpression tests ---

func TestResolveExpression_DirectCEL(t *testing.T) {
	expr, err := ResolveExpression("status_counts.effective > 0", "")
	if err != nil {
		t.Fatalf("ResolveExpression error: %v", err)
	}
	if expr != "status_counts.effective > 0" {
		t.Errorf("ResolveExpression returned %q, want %q", expr, "status_counts.effective > 0")
	}
}

func TestResolveExpression_PresetExpansion(t *testing.T) {
	expr, err := ResolveExpression("", "all_effective")
	if err != nil {
		t.Fatalf("ResolveExpression error: %v", err)
	}
	if expr == "" {
		t.Fatal("ResolveExpression returned empty string for preset expansion")
	}
}

func TestResolveExpression_CELTakesPrecedence(t *testing.T) {
	customExpr := "status_counts.total > 0"
	expr, err := ResolveExpression(customExpr, "all_effective")
	if err != nil {
		t.Fatalf("ResolveExpression error: %v", err)
	}
	if expr != customExpr {
		t.Errorf("CEL expression should take precedence, got %q want %q", expr, customExpr)
	}
}

func TestResolveExpression_NeitherProvided(t *testing.T) {
	_, err := ResolveExpression("", "")
	if err == nil {
		t.Fatal("ResolveExpression should error when neither CEL nor preset is provided")
	}
}

// --- ListPresets test ---

func TestListPresets_ReturnsAll(t *testing.T) {
	list := ListPresets()
	if len(list) < 3 {
		t.Errorf("ListPresets() returned %d presets, want at least 3", len(list))
	}

	// Verify specific presets exist.
	found := make(map[string]bool)
	for _, name := range list {
		found[name] = true
	}

	for _, name := range []string{"all_effective", "any_effective", "active_verified"} {
		if !found[name] {
			t.Errorf("ListPresets() missing preset %q", name)
		}
	}
}
