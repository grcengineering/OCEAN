package eval

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/grcengineering/ocean/internal/evidence"
)

// --- T090: NewCELEnvironment tests ---

func TestNewCELEnvironment_ReturnsNonNil(t *testing.T) {
	env, err := NewCELEnvironment()
	if err != nil {
		t.Fatalf("NewCELEnvironment() error = %v", err)
	}
	if env == nil {
		t.Fatal("NewCELEnvironment() returned nil")
	}
}

// --- T092: CompileExpression tests ---

func TestCompileExpression_ValidExpression(t *testing.T) {
	compiled, err := CompileExpression("status_counts.ineffective == 0 && status_counts.effective > 0")
	if err != nil {
		t.Fatalf("CompileExpression() error = %v", err)
	}
	if compiled == nil {
		t.Fatal("CompileExpression() returned nil")
	}
}

func TestCompileExpression_HasActiveExpression(t *testing.T) {
	compiled, err := CompileExpression("has_active && status_counts.effective > 0")
	if err != nil {
		t.Fatalf("CompileExpression() error = %v", err)
	}
	if compiled == nil {
		t.Fatal("CompileExpression() returned nil")
	}
}

func TestCompileExpression_EvidenceFieldAccess(t *testing.T) {
	compiled, err := CompileExpression("evidence.size() > 0")
	if err != nil {
		t.Fatalf("CompileExpression() error = %v", err)
	}
	if compiled == nil {
		t.Fatal("CompileExpression() returned nil")
	}
}

// T103: compilation errors with line/column info
func TestCompileExpression_SyntaxError(t *testing.T) {
	_, err := CompileExpression("status_counts.ineffective ==")
	if err == nil {
		t.Fatal("CompileExpression() expected error for syntax error, got nil")
	}
	// Error message should exist and be descriptive.
	if len(err.Error()) == 0 {
		t.Error("CompileExpression() error message should not be empty")
	}
}

func TestCompileExpression_TypeCheckError(t *testing.T) {
	// Comparing a bool to an int should be a type error.
	_, err := CompileExpression("has_active + 5")
	if err == nil {
		t.Fatal("CompileExpression() expected error for type mismatch, got nil")
	}
}

func TestCompileExpression_EmptyExpression(t *testing.T) {
	_, err := CompileExpression("")
	if err == nil {
		t.Fatal("CompileExpression() expected error for empty expression, got nil")
	}
}

// --- T093: Evaluate tests ---

func statusString(s evidence.StatusID) string {
	switch s {
	case evidence.StatusEffective:
		return "effective"
	case evidence.StatusIneffective:
		return "ineffective"
	default:
		return "unknown"
	}
}

func makeTestEvidence(statusID evidence.StatusID, conf evidence.ConfidenceLevel) evidence.Evidence {
	return evidence.Evidence{
		ID:              uuid.New(),
		ControlID:       "test.control",
		ClassUID:        1001,
		CategoryUID:     1,
		ActivityID:      1,
		Time:            time.Now().UTC(),
		ConfidenceLevel: conf,
		StatusID:        statusID,
		Status:          statusString(statusID),
		RawData:         json.RawMessage(`{"test": true}`),
	}
}

func TestEvaluate_AllEffective(t *testing.T) {
	compiled, err := CompileExpression("status_counts.ineffective == 0 && status_counts.effective > 0")
	if err != nil {
		t.Fatalf("CompileExpression() error = %v", err)
	}

	evidences := []evidence.Evidence{
		makeTestEvidence(evidence.StatusEffective, evidence.PassiveObservation),
		makeTestEvidence(evidence.StatusEffective, evidence.ActiveVerification),
	}

	result, err := Evaluate(compiled, evidences)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if !result {
		t.Error("Evaluate() = false, want true (all effective)")
	}
}

func TestEvaluate_HasIneffective(t *testing.T) {
	compiled, err := CompileExpression("status_counts.ineffective == 0 && status_counts.effective > 0")
	if err != nil {
		t.Fatalf("CompileExpression() error = %v", err)
	}

	evidences := []evidence.Evidence{
		makeTestEvidence(evidence.StatusEffective, evidence.PassiveObservation),
		makeTestEvidence(evidence.StatusIneffective, evidence.PassiveObservation),
	}

	result, err := Evaluate(compiled, evidences)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if result {
		t.Error("Evaluate() = true, want false (has ineffective)")
	}
}

func TestEvaluate_AnyEffective(t *testing.T) {
	compiled, err := CompileExpression("status_counts.effective > 0")
	if err != nil {
		t.Fatalf("CompileExpression() error = %v", err)
	}

	evidences := []evidence.Evidence{
		makeTestEvidence(evidence.StatusEffective, evidence.PassiveObservation),
		makeTestEvidence(evidence.StatusIneffective, evidence.PassiveObservation),
	}

	result, err := Evaluate(compiled, evidences)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if !result {
		t.Error("Evaluate() = false, want true (any effective)")
	}
}

func TestEvaluate_ActiveVerified(t *testing.T) {
	compiled, err := CompileExpression("has_active && status_counts.ineffective == 0 && status_counts.effective > 0")
	if err != nil {
		t.Fatalf("CompileExpression() error = %v", err)
	}

	// Only passive evidence -- should fail because has_active is false.
	passiveOnly := []evidence.Evidence{
		makeTestEvidence(evidence.StatusEffective, evidence.PassiveObservation),
	}

	result, err := Evaluate(compiled, passiveOnly)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if result {
		t.Error("Evaluate() = true, want false (no active evidence)")
	}

	// With active evidence -- should pass.
	withActive := []evidence.Evidence{
		makeTestEvidence(evidence.StatusEffective, evidence.PassiveObservation),
		makeTestEvidence(evidence.StatusEffective, evidence.ActiveVerification),
	}

	result, err = Evaluate(compiled, withActive)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if !result {
		t.Error("Evaluate() = false, want true (has active + all effective)")
	}
}

func TestEvaluate_EmptyEvidence(t *testing.T) {
	compiled, err := CompileExpression("status_counts.effective > 0")
	if err != nil {
		t.Fatalf("CompileExpression() error = %v", err)
	}

	result, err := Evaluate(compiled, nil)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if result {
		t.Error("Evaluate() = true, want false (no evidence)")
	}
}

func TestEvaluate_StatusCounts(t *testing.T) {
	compiled, err := CompileExpression("status_counts.total == 3 && status_counts.effective == 2 && status_counts.ineffective == 1 && status_counts.unknown == 0")
	if err != nil {
		t.Fatalf("CompileExpression() error = %v", err)
	}

	evidences := []evidence.Evidence{
		makeTestEvidence(evidence.StatusEffective, evidence.PassiveObservation),
		makeTestEvidence(evidence.StatusEffective, evidence.ActiveVerification),
		makeTestEvidence(evidence.StatusIneffective, evidence.PassiveObservation),
	}

	result, err := Evaluate(compiled, evidences)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if !result {
		t.Error("Evaluate() = false, want true (counts should match)")
	}
}

func TestEvaluate_EvidenceListSize(t *testing.T) {
	compiled, err := CompileExpression("evidence.size() == 2")
	if err != nil {
		t.Fatalf("CompileExpression() error = %v", err)
	}

	evidences := []evidence.Evidence{
		makeTestEvidence(evidence.StatusEffective, evidence.PassiveObservation),
		makeTestEvidence(evidence.StatusEffective, evidence.ActiveVerification),
	}

	result, err := Evaluate(compiled, evidences)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if !result {
		t.Error("Evaluate() = false, want true (evidence size == 2)")
	}
}

// --- T192: CEL complexity limits ---

func TestCompileExpression_AcceptsSimpleExpression(t *testing.T) {
	// A simple expression should compile fine within limits.
	compiled, err := CompileExpression("status_counts.effective > 0 && has_active")
	if err != nil {
		t.Fatalf("CompileExpression() error = %v", err)
	}
	if compiled == nil {
		t.Fatal("CompileExpression() returned nil for simple expression")
	}
}

func TestCompileExpression_RejectsExcessiveDepth(t *testing.T) {
	// Build a deeply nested expression that exceeds the depth limit.
	// depth > MaxExpressionDepth should be rejected.
	expr := "true"
	for i := 0; i < 15; i++ {
		expr = "(" + expr + " && true)"
	}

	_, err := CompileExpression(expr)
	if err == nil {
		t.Fatal("CompileExpression() expected error for excessively deep expression, got nil")
	}
	if !containsDepthError(err) {
		t.Errorf("expected depth-related error, got: %v", err)
	}
}

func TestCheckExpressionDepth_SimpleExpr(t *testing.T) {
	// A simple expression should have depth well under the limit.
	depth, err := CheckExpressionDepth("status_counts.effective > 0")
	if err != nil {
		t.Fatalf("CheckExpressionDepth() error = %v", err)
	}
	if depth > MaxExpressionDepth {
		t.Errorf("depth = %d, expected <= %d", depth, MaxExpressionDepth)
	}
}

func TestCheckExpressionDepth_NestedExpr(t *testing.T) {
	// Build a moderately nested expression.
	expr := "true"
	for i := 0; i < 5; i++ {
		expr = "(" + expr + " && true)"
	}

	depth, err := CheckExpressionDepth(expr)
	if err != nil {
		t.Fatalf("CheckExpressionDepth() error = %v", err)
	}
	if depth <= 0 {
		t.Errorf("depth = %d, expected > 0", depth)
	}
}

func containsDepthError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return len(s) > 0 && (contains(s, "depth") || contains(s, "complex"))
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// --- T192: ValidateExpressionComplexity tests ---

func TestValidateExpressionComplexity_ValidShortExpression(t *testing.T) {
	err := ValidateExpressionComplexity("status_counts.effective > 0 && has_active")
	if err != nil {
		t.Fatalf("ValidateExpressionComplexity() error = %v for valid expression", err)
	}
}

func TestValidateExpressionComplexity_ExceedsMaxLength(t *testing.T) {
	// Build an expression that exceeds MaxCELExpressionLength.
	long := ""
	for len(long) <= MaxCELExpressionLength {
		long += "status_counts.effective > 0 && "
	}
	long += "true"

	err := ValidateExpressionComplexity(long)
	if err == nil {
		t.Fatal("expected error for expression exceeding max length, got nil")
	}
	if !contains(err.Error(), "too long") {
		t.Errorf("expected 'too long' in error, got: %v", err)
	}
}

func TestValidateExpressionComplexity_ExceedsMaxNestingDepth(t *testing.T) {
	// Build an expression with nesting depth exceeding MaxCELASTDepth.
	expr := "true"
	for i := 0; i < MaxCELASTDepth+5; i++ {
		expr = "(" + expr + ")"
	}

	err := ValidateExpressionComplexity(expr)
	if err == nil {
		t.Fatal("expected error for expression exceeding max nesting depth, got nil")
	}
	if !contains(err.Error(), "deeply nested") {
		t.Errorf("expected 'deeply nested' in error, got: %v", err)
	}
}

func TestValidateExpressionComplexity_ExactlyAtLengthLimit(t *testing.T) {
	// Build an expression exactly at MaxCELExpressionLength.
	base := "a"
	for len(base) < MaxCELExpressionLength {
		base += "a"
	}
	// Exactly at limit should pass.
	err := ValidateExpressionComplexity(base)
	if err != nil {
		t.Fatalf("ValidateExpressionComplexity() error = %v for expression at exact length limit", err)
	}
}

func TestValidateExpressionComplexity_ExactlyAtDepthLimit(t *testing.T) {
	// Build an expression with nesting depth exactly at MaxCELASTDepth.
	expr := "true"
	for i := 0; i < MaxCELASTDepth; i++ {
		expr = "(" + expr + ")"
	}

	err := ValidateExpressionComplexity(expr)
	if err != nil {
		t.Fatalf("ValidateExpressionComplexity() error = %v for expression at exact depth limit", err)
	}
}

func TestValidateExpressionComplexity_EmptyExpression(t *testing.T) {
	// Empty string should pass complexity check (compilation catches empty separately).
	err := ValidateExpressionComplexity("")
	if err != nil {
		t.Fatalf("ValidateExpressionComplexity() should not error on empty expression, got: %v", err)
	}
}

func TestValidateExpressionComplexity_MixedBrackets(t *testing.T) {
	// Test that parentheses, brackets, and braces all count toward nesting.
	expr := "([{true}])"
	err := ValidateExpressionComplexity(expr)
	if err != nil {
		t.Fatalf("ValidateExpressionComplexity() error = %v for mixed bracket expression", err)
	}
}

func TestCompileExpression_RejectsLongExpression(t *testing.T) {
	// Ensure CompileExpression calls ValidateExpressionComplexity.
	long := ""
	for len(long) <= MaxCELExpressionLength {
		long += "status_counts.effective > 0 && "
	}
	long += "true"

	_, err := CompileExpression(long)
	if err == nil {
		t.Fatal("CompileExpression() expected error for expression exceeding max length, got nil")
	}
	if !contains(err.Error(), "too long") {
		t.Errorf("expected 'too long' in error, got: %v", err)
	}
}

func TestCompileExpression_RejectsDeeplyNestedBrackets(t *testing.T) {
	// Ensure CompileExpression calls ValidateExpressionComplexity for bracket nesting.
	expr := "true"
	for i := 0; i < MaxCELASTDepth+5; i++ {
		expr = "(" + expr + ")"
	}

	_, err := CompileExpression(expr)
	if err == nil {
		t.Fatal("CompileExpression() expected error for deeply nested brackets, got nil")
	}
	if !contains(err.Error(), "deeply nested") {
		t.Errorf("expected 'deeply nested' in error, got: %v", err)
	}
}

// T104: handle missing evidence fields gracefully
func TestEvaluate_MissingFieldsGraceful(t *testing.T) {
	// Accessing evidence fields that exist on the map should work,
	// even with minimal evidence records.
	compiled, err := CompileExpression("status_counts.effective >= 0")
	if err != nil {
		t.Fatalf("CompileExpression() error = %v", err)
	}

	minimal := []evidence.Evidence{{
		ID:        uuid.New(),
		ControlID: "test.minimal",
		StatusID:  evidence.StatusUnknown,
	}}

	result, err := Evaluate(compiled, minimal)
	if err != nil {
		t.Fatalf("Evaluate() should not error on minimal evidence, got: %v", err)
	}
	// effective >= 0 is always true.
	if !result {
		t.Error("Evaluate() = false, want true")
	}
}
