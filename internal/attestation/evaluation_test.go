package attestation

import (
	"testing"
	"time"
)

func TestEvaluationPredicateType(t *testing.T) {
	if EvaluationPredicateType == "" {
		t.Fatal("EvaluationPredicateType should not be empty")
	}
	want := "https://ocean.grc.engineering/attestation/v1/evaluation"
	if EvaluationPredicateType != want {
		t.Errorf("EvaluationPredicateType = %q, want %q", EvaluationPredicateType, want)
	}
}

func TestNewEvaluationAttestation_CreatesValidStatement(t *testing.T) {
	controlID := "test.mfa_enforcement"
	evidenceDigests := []string{"sha256:abc123", "sha256:def456"}
	expressionDigest := "sha256:expr789"
	expressionText := "status_counts.ineffective == 0"
	verdict := "effective"
	confidence := "high"

	stmt, err := NewEvaluationAttestation(controlID, evidenceDigests, expressionDigest, expressionText, verdict, confidence)
	if err != nil {
		t.Fatalf("NewEvaluationAttestation() error = %v", err)
	}

	if stmt == nil {
		t.Fatal("NewEvaluationAttestation() returned nil")
	}

	// Verify in-toto statement structure.
	if stmt.Type != InTotoStatementType {
		t.Errorf("Type = %q, want %q", stmt.Type, InTotoStatementType)
	}

	if stmt.PredicateType != EvaluationPredicateType {
		t.Errorf("PredicateType = %q, want %q", stmt.PredicateType, EvaluationPredicateType)
	}

	// Verify subject.
	if len(stmt.Subject) != 1 {
		t.Fatalf("Subject count = %d, want 1", len(stmt.Subject))
	}

	subject := stmt.Subject[0]
	if subject.Name == "" {
		t.Error("Subject.Name should not be empty")
	}

	// Verify predicate fields.
	predicate, ok := stmt.Predicate.(*EvaluationPredicate)
	if !ok {
		t.Fatalf("Predicate is not *EvaluationPredicate, got %T", stmt.Predicate)
	}

	if predicate.ControlID != controlID {
		t.Errorf("Predicate.ControlID = %q, want %q", predicate.ControlID, controlID)
	}

	if len(predicate.EvidenceDigests) != 2 {
		t.Errorf("Predicate.EvidenceDigests count = %d, want 2", len(predicate.EvidenceDigests))
	}

	if predicate.ExpressionDigest != expressionDigest {
		t.Errorf("Predicate.ExpressionDigest = %q, want %q", predicate.ExpressionDigest, expressionDigest)
	}

	if predicate.ExpressionText != expressionText {
		t.Errorf("Predicate.ExpressionText = %q, want %q", predicate.ExpressionText, expressionText)
	}

	if predicate.Verdict != verdict {
		t.Errorf("Predicate.Verdict = %q, want %q", predicate.Verdict, verdict)
	}

	if predicate.Confidence != confidence {
		t.Errorf("Predicate.Confidence = %q, want %q", predicate.Confidence, confidence)
	}

	if predicate.Timestamp.IsZero() {
		t.Error("Predicate.Timestamp should not be zero")
	}
}

func TestNewEvaluationAttestation_EmptyEvidenceDigests(t *testing.T) {
	stmt, err := NewEvaluationAttestation("test.ctrl", nil, "sha256:expr", "true", "unknown", "low")
	if err != nil {
		t.Fatalf("NewEvaluationAttestation() error = %v", err)
	}
	if stmt == nil {
		t.Fatal("NewEvaluationAttestation() returned nil")
	}

	predicate, ok := stmt.Predicate.(*EvaluationPredicate)
	if !ok {
		t.Fatalf("Predicate is not *EvaluationPredicate, got %T", stmt.Predicate)
	}

	if predicate.EvidenceDigests == nil {
		// nil is acceptable, but empty slice is also fine.
	}
}

func TestNewEvaluationAttestation_TimestampIsRecent(t *testing.T) {
	before := time.Now().UTC().Add(-time.Second)

	stmt, err := NewEvaluationAttestation("test.ctrl", nil, "sha256:e", "true", "effective", "high")
	if err != nil {
		t.Fatalf("NewEvaluationAttestation() error = %v", err)
	}

	after := time.Now().UTC().Add(time.Second)

	predicate := stmt.Predicate.(*EvaluationPredicate)
	if predicate.Timestamp.Before(before) || predicate.Timestamp.After(after) {
		t.Errorf("Timestamp %v is not within expected range [%v, %v]", predicate.Timestamp, before, after)
	}
}

func TestSignEvaluation_CreatesSignedEnvelope(t *testing.T) {
	controlID := "test.mfa"
	evidenceDigests := []string{"sha256:abc123"}
	expressionDigest := "sha256:expr789"
	expressionText := "status_counts.ineffective == 0"
	verdict := "effective"
	confidence := "high"

	stmt, err := NewEvaluationAttestation(controlID, evidenceDigests, expressionDigest, expressionText, verdict, confidence)
	if err != nil {
		t.Fatalf("NewEvaluationAttestation() error = %v", err)
	}

	// Generate a test keypair for signing.
	signer := generateTestSigner(t)

	envelope, ref, err := SignEvaluation(stmt, signer)
	if err != nil {
		t.Fatalf("SignEvaluation() error = %v", err)
	}

	if envelope == nil {
		t.Fatal("SignEvaluation() returned nil envelope")
	}

	if ref == "" {
		t.Fatal("SignEvaluation() returned empty ref")
	}

	// Verify the envelope can be validated.
	if err := VerifyDSSEEnvelope(envelope, signer.PublicKey()); err != nil {
		t.Errorf("envelope verification failed: %v", err)
	}
}

// generateTestSigner creates a deterministic test signer.
func generateTestSigner(t *testing.T) *Ed25519Signer {
	t.Helper()

	dir := t.TempDir()
	_, privPath, err := GenerateKeyPair(dir)
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	signer, err := LoadSigner(privPath)
	if err != nil {
		t.Fatalf("LoadSigner() error = %v", err)
	}

	return signer
}
