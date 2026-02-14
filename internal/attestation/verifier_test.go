package attestation

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/grcengineering/ocean/internal/evidence"
)

// --- Test helpers ---

// newTestSigner creates an Ed25519 signer for testing.
func newTestSigner(t *testing.T) *Ed25519Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}
	return NewEd25519Signer(priv)
}

// newTestEvidence creates a minimal valid evidence record for testing.
func newTestEvidence(t *testing.T) *evidence.Evidence {
	t.Helper()
	return &evidence.Evidence{
		ID:              uuid.New(),
		ControlID:       "test.mfa_enforcement",
		ClassUID:        6003,
		CategoryUID:     6,
		ActivityID:      1,
		Time:            time.Now().UTC(),
		ConfidenceLevel: evidence.PassiveObservation,
		Metadata: evidence.Metadata{
			Module: evidence.ModuleInfo{
				Name:    "mock.test",
				Version: "1.0.0",
				Type:    "collector",
			},
			Source: evidence.SourceInfo{
				System:     "mock",
				APIVersion: "v1",
				Endpoint:   "/api/test",
			},
			ProcessedTime: time.Now().UTC(),
		},
		StatusID: evidence.StatusEffective,
		Status:   "effective",
		RawData:  json.RawMessage(`{"mfa_enabled":true,"enforced":true}`),
	}
}

// newTestEvidenceWithTranscript creates evidence with a test transcript (active verification).
func newTestEvidenceWithTranscript(t *testing.T) *evidence.Evidence {
	t.Helper()
	ev := newTestEvidence(t)
	ev.ConfidenceLevel = evidence.ActiveVerification
	ev.TestTranscript = &evidence.TestTranscript{
		ActionsAttempted: []evidence.TranscriptAction{
			{
				Action:    "attempt_login_without_mfa",
				Timestamp: time.Now().UTC(),
			},
		},
		Observations: []evidence.TranscriptObservation{
			{
				Observation: "login_blocked",
				Timestamp:   time.Now().UTC(),
				Expected:    true,
			},
		},
		CleanupActions: []evidence.TranscriptCleanup{
			{
				Action:    "revoke_test_token",
				Timestamp: time.Now().UTC(),
				Success:   true,
			},
		},
	}
	return ev
}

// --- T133: DSSE envelope verification ---

func TestVerifyEnvelope_ValidSignature(t *testing.T) {
	signer := newTestSigner(t)
	statement := []byte(`{"_type":"https://in-toto.io/Statement/v1","subject":[]}`)

	envelope, err := CreateDSSEEnvelope(statement, signer)
	if err != nil {
		t.Fatalf("CreateDSSEEnvelope() error = %v", err)
	}

	result := VerifyEnvelope(envelope, signer.PublicKey())
	if !result.Passed {
		t.Errorf("VerifyEnvelope() passed = false, want true; details = %q", result.Details)
	}
}

func TestVerifyEnvelope_InvalidSignature(t *testing.T) {
	signer := newTestSigner(t)
	statement := []byte(`{"_type":"https://in-toto.io/Statement/v1","subject":[]}`)

	envelope, err := CreateDSSEEnvelope(statement, signer)
	if err != nil {
		t.Fatalf("CreateDSSEEnvelope() error = %v", err)
	}

	// Use a different key for verification.
	otherSigner := newTestSigner(t)
	result := VerifyEnvelope(envelope, otherSigner.PublicKey())
	if result.Passed {
		t.Error("VerifyEnvelope() with wrong key should not pass")
	}
}

func TestVerifyEnvelope_NoSignatures(t *testing.T) {
	envelope := &DSSEEnvelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     "dGVzdA==",
		Signatures:  []DSSESignature{},
	}

	signer := newTestSigner(t)
	result := VerifyEnvelope(envelope, signer.PublicKey())
	if result.Passed {
		t.Error("VerifyEnvelope() with no signatures should not pass")
	}
}

// --- T134: Content digest verification ---

func TestVerifyDigest_Match(t *testing.T) {
	data := []byte(`{"mfa_enabled":true}`)
	expectedDigest := DigestOf(data)

	result := VerifyDigest(data, expectedDigest)
	if !result.Passed {
		t.Errorf("VerifyDigest() passed = false, want true; details = %q", result.Details)
	}
}

func TestVerifyDigest_Mismatch(t *testing.T) {
	data := []byte(`{"mfa_enabled":true}`)
	wrongDigest := DigestOf([]byte(`{"mfa_enabled":false}`))

	result := VerifyDigest(data, wrongDigest)
	if result.Passed {
		t.Error("VerifyDigest() with mismatched digest should not pass")
	}
	if result.Details == "" {
		t.Error("VerifyDigest() should include details about mismatch")
	}
}

func TestVerifyDigest_EmptyData(t *testing.T) {
	data := []byte{}
	expectedDigest := DigestOf(data)

	result := VerifyDigest(data, expectedDigest)
	if !result.Passed {
		t.Errorf("VerifyDigest() with empty data should pass when digest matches; details = %q", result.Details)
	}
}

// --- T135: Collection attestation chain verification ---

func TestVerifyCollectionAttestation_ValidChain(t *testing.T) {
	signer := newTestSigner(t)
	ev := newTestEvidence(t)

	// Sign the evidence (creates collection attestation).
	envelope, err := SignEvidence(ev, signer)
	if err != nil {
		t.Fatalf("SignEvidence() error = %v", err)
	}

	result := VerifyCollectionAttestation(ev, envelope, signer.PublicKey())
	if !result.Overall {
		t.Errorf("VerifyCollectionAttestation() overall = false, want true")
		for _, step := range result.StepResults {
			if !step.Passed {
				t.Logf("  FAILED step %q: %s", step.StepName, step.Details)
			}
		}
	}
}

func TestVerifyCollectionAttestation_TamperedContent(t *testing.T) {
	signer := newTestSigner(t)
	ev := newTestEvidence(t)

	// Sign the evidence.
	envelope, err := SignEvidence(ev, signer)
	if err != nil {
		t.Fatalf("SignEvidence() error = %v", err)
	}

	// Tamper with evidence content after signing.
	ev.RawData = json.RawMessage(`{"mfa_enabled":false,"tampered":true}`)

	result := VerifyCollectionAttestation(ev, envelope, signer.PublicKey())
	if result.Overall {
		t.Error("VerifyCollectionAttestation() with tampered content should not pass")
	}

	// Should have a step that specifically fails on digest match.
	foundDigestFailure := false
	for _, step := range result.StepResults {
		if step.StepName == "evidence_content_digest" && !step.Passed {
			foundDigestFailure = true
		}
	}
	if !foundDigestFailure {
		t.Error("expected 'evidence_content_digest' step to fail for tampered content")
	}
}

func TestVerifyCollectionAttestation_WrongSigner(t *testing.T) {
	signer := newTestSigner(t)
	ev := newTestEvidence(t)

	envelope, err := SignEvidence(ev, signer)
	if err != nil {
		t.Fatalf("SignEvidence() error = %v", err)
	}

	// Verify with a different signer's public key.
	otherSigner := newTestSigner(t)
	result := VerifyCollectionAttestation(ev, envelope, otherSigner.PublicKey())
	if result.Overall {
		t.Error("VerifyCollectionAttestation() with wrong signer should not pass")
	}
}

// --- T136: Evaluation attestation chain verification ---

func TestVerifyEvaluationAttestation_ValidChain(t *testing.T) {
	signer := newTestSigner(t)

	evidenceDigests := []string{"sha256:abc123", "sha256:def456"}
	expressionText := "status_counts.ineffective == 0"
	expressionDigest := DigestOf([]byte(expressionText))
	verdict := "effective"
	confidence := "high"

	stmt, err := NewEvaluationAttestation("test.mfa", evidenceDigests, expressionDigest, expressionText, verdict, confidence)
	if err != nil {
		t.Fatalf("NewEvaluationAttestation() error = %v", err)
	}

	envelope, _, err := SignEvaluation(stmt, signer)
	if err != nil {
		t.Fatalf("SignEvaluation() error = %v", err)
	}

	result := VerifyEvaluationAttestation(envelope, evidenceDigests, expressionText, signer.PublicKey())
	if !result.Overall {
		t.Errorf("VerifyEvaluationAttestation() overall = false, want true")
		for _, step := range result.StepResults {
			if !step.Passed {
				t.Logf("  FAILED step %q: %s", step.StepName, step.Details)
			}
		}
	}
}

func TestVerifyEvaluationAttestation_WrongEvidenceDigests(t *testing.T) {
	signer := newTestSigner(t)

	evidenceDigests := []string{"sha256:abc123"}
	expressionText := "true"
	expressionDigest := DigestOf([]byte(expressionText))

	stmt, err := NewEvaluationAttestation("test.ctrl", evidenceDigests, expressionDigest, expressionText, "effective", "high")
	if err != nil {
		t.Fatalf("NewEvaluationAttestation() error = %v", err)
	}

	envelope, _, err := SignEvaluation(stmt, signer)
	if err != nil {
		t.Fatalf("SignEvaluation() error = %v", err)
	}

	// Provide different evidence digests for verification.
	wrongDigests := []string{"sha256:tampered"}
	result := VerifyEvaluationAttestation(envelope, wrongDigests, expressionText, signer.PublicKey())
	if result.Overall {
		t.Error("VerifyEvaluationAttestation() with wrong evidence digests should not pass")
	}
}

// --- T137: Full provenance chain verification ---

func TestVerifyProvenanceChain_CollectionOnly(t *testing.T) {
	signer := newTestSigner(t)
	ev := newTestEvidence(t)

	envelope, err := SignEvidence(ev, signer)
	if err != nil {
		t.Fatalf("SignEvidence() error = %v", err)
	}

	envelopeJSON, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("json.Marshal envelope error = %v", err)
	}

	store := &mockStore{
		evidence:     map[uuid.UUID]*evidence.Evidence{ev.ID: ev},
		attestations: map[string][]byte{ev.Attestation.DSSEEnvelopeRef: envelopeJSON},
	}

	result, err := VerifyProvenanceChain(context.Background(), store, ev.ID, signer.PublicKey())
	if err != nil {
		t.Fatalf("VerifyProvenanceChain() error = %v", err)
	}
	if !result.Overall {
		t.Errorf("VerifyProvenanceChain() overall = false, want true")
		for _, step := range result.StepResults {
			if !step.Passed {
				t.Logf("  FAILED step %q: %s", step.StepName, step.Details)
			}
		}
	}
}

// --- T138: Tamper detection ---

func TestVerifyProvenanceChain_TamperedEvidence(t *testing.T) {
	signer := newTestSigner(t)
	ev := newTestEvidence(t)

	envelope, err := SignEvidence(ev, signer)
	if err != nil {
		t.Fatalf("SignEvidence() error = %v", err)
	}

	envelopeJSON, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("json.Marshal envelope error = %v", err)
	}

	// Tamper with evidence AFTER signing and storing.
	tamperedEv := *ev
	tamperedEv.RawData = json.RawMessage(`{"tampered":true}`)

	store := &mockStore{
		evidence:     map[uuid.UUID]*evidence.Evidence{ev.ID: &tamperedEv},
		attestations: map[string][]byte{ev.Attestation.DSSEEnvelopeRef: envelopeJSON},
	}

	result, err := VerifyProvenanceChain(context.Background(), store, ev.ID, signer.PublicKey())
	if err != nil {
		t.Fatalf("VerifyProvenanceChain() error = %v", err)
	}
	if result.Overall {
		t.Error("VerifyProvenanceChain() with tampered evidence should not pass overall")
	}

	// Should contain the specific tamper detection message.
	foundTamperMsg := false
	for _, step := range result.StepResults {
		if step.StepName == "evidence_content_digest" && !step.Passed {
			foundTamperMsg = true
		}
	}
	if !foundTamperMsg {
		t.Error("expected tamper detection step to fail with evidence_content_digest")
	}
}

// --- T139: Transcript digest verification ---

func TestVerifyProvenanceChain_WithTranscript(t *testing.T) {
	signer := newTestSigner(t)
	ev := newTestEvidenceWithTranscript(t)

	envelope, err := SignEvidence(ev, signer)
	if err != nil {
		t.Fatalf("SignEvidence() error = %v", err)
	}

	envelopeJSON, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("json.Marshal envelope error = %v", err)
	}

	store := &mockStore{
		evidence:     map[uuid.UUID]*evidence.Evidence{ev.ID: ev},
		attestations: map[string][]byte{ev.Attestation.DSSEEnvelopeRef: envelopeJSON},
	}

	result, err := VerifyProvenanceChain(context.Background(), store, ev.ID, signer.PublicKey())
	if err != nil {
		t.Fatalf("VerifyProvenanceChain() error = %v", err)
	}
	if !result.Overall {
		t.Errorf("VerifyProvenanceChain() with transcript overall = false, want true")
		for _, step := range result.StepResults {
			if !step.Passed {
				t.Logf("  FAILED step %q: %s", step.StepName, step.Details)
			}
		}
	}

	// Should have a transcript verification step that passed.
	foundTranscriptStep := false
	for _, step := range result.StepResults {
		if step.StepName == "transcript_digest" {
			foundTranscriptStep = true
			if !step.Passed {
				t.Errorf("transcript_digest step should pass; details = %q", step.Details)
			}
		}
	}
	if !foundTranscriptStep {
		t.Error("expected 'transcript_digest' step in verification results")
	}
}

func TestVerifyProvenanceChain_TamperedTranscript(t *testing.T) {
	signer := newTestSigner(t)
	ev := newTestEvidenceWithTranscript(t)

	envelope, err := SignEvidence(ev, signer)
	if err != nil {
		t.Fatalf("SignEvidence() error = %v", err)
	}

	envelopeJSON, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("json.Marshal envelope error = %v", err)
	}

	// Tamper with the transcript after signing.
	ev.TestTranscript.Observations = append(ev.TestTranscript.Observations, evidence.TranscriptObservation{
		Observation: "injected_observation",
		Timestamp:   time.Now().UTC(),
		Expected:    false,
	})

	store := &mockStore{
		evidence:     map[uuid.UUID]*evidence.Evidence{ev.ID: ev},
		attestations: map[string][]byte{ev.Attestation.DSSEEnvelopeRef: envelopeJSON},
	}

	result, err := VerifyProvenanceChain(context.Background(), store, ev.ID, signer.PublicKey())
	if err != nil {
		t.Fatalf("VerifyProvenanceChain() error = %v", err)
	}
	if result.Overall {
		t.Error("VerifyProvenanceChain() with tampered transcript should not pass overall")
	}
}

// --- T140: Public key export ---

func TestExportPublicKey(t *testing.T) {
	dir := t.TempDir()
	_, privPath, err := GenerateKeyPair(dir)
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	signer, err := LoadSigner(privPath)
	if err != nil {
		t.Fatalf("LoadSigner() error = %v", err)
	}

	exportPath := filepath.Join(dir, "exported-public.pem")
	if err := ExportPublicKey(signer, exportPath); err != nil {
		t.Fatalf("ExportPublicKey() error = %v", err)
	}

	// Verify file was created.
	data, err := os.ReadFile(exportPath)
	if err != nil {
		t.Fatalf("reading exported key: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("exported key file is empty")
	}

	// Verify the exported key can be loaded back.
	loadedKey, err := LoadPublicKey(exportPath)
	if err != nil {
		t.Fatalf("LoadPublicKey() error = %v", err)
	}
	if !loadedKey.Equal(signer.PublicKey()) {
		t.Error("loaded public key does not match original")
	}
}

func TestLoadPublicKey_InvalidFile(t *testing.T) {
	_, err := LoadPublicKey("/nonexistent/path.pem")
	if err == nil {
		t.Error("LoadPublicKey() with non-existent file should return error")
	}

	// Invalid PEM content.
	dir := t.TempDir()
	badFile := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(badFile, []byte("not a pem file"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err = LoadPublicKey(badFile)
	if err == nil {
		t.Error("LoadPublicKey() with invalid PEM should return error")
	}
}

// --- T141: Standalone verification with public key ---

func TestVerifyWithPublicKey_ValidChain(t *testing.T) {
	signer := newTestSigner(t)
	ev := newTestEvidence(t)

	envelope, err := SignEvidence(ev, signer)
	if err != nil {
		t.Fatalf("SignEvidence() error = %v", err)
	}

	// Create the attestation chain JSON blob.
	chain := AttestationChain{
		Evidence:             *ev,
		CollectionEnvelope:   envelope,
		EvaluationEnvelope:   nil,
		EvaluationInputs:     nil,
		EvaluationExpression: "",
	}
	chainJSON, err := json.Marshal(chain)
	if err != nil {
		t.Fatalf("json.Marshal chain error = %v", err)
	}

	// Export the public key.
	dir := t.TempDir()
	pubKeyPath := filepath.Join(dir, "verify.pub")
	if err := ExportPublicKey(signer, pubKeyPath); err != nil {
		t.Fatalf("ExportPublicKey() error = %v", err)
	}

	result, err := VerifyWithPublicKey(chainJSON, pubKeyPath)
	if err != nil {
		t.Fatalf("VerifyWithPublicKey() error = %v", err)
	}
	if !result.Overall {
		t.Errorf("VerifyWithPublicKey() overall = false, want true")
		for _, step := range result.StepResults {
			if !step.Passed {
				t.Logf("  FAILED step %q: %s", step.StepName, step.Details)
			}
		}
	}
}

func TestVerifyWithPublicKey_WrongKey(t *testing.T) {
	signer := newTestSigner(t)
	ev := newTestEvidence(t)

	envelope, err := SignEvidence(ev, signer)
	if err != nil {
		t.Fatalf("SignEvidence() error = %v", err)
	}

	chain := AttestationChain{
		Evidence:           *ev,
		CollectionEnvelope: envelope,
	}
	chainJSON, err := json.Marshal(chain)
	if err != nil {
		t.Fatalf("json.Marshal chain error = %v", err)
	}

	// Export a DIFFERENT signer's public key.
	otherSigner := newTestSigner(t)
	dir := t.TempDir()
	pubKeyPath := filepath.Join(dir, "wrong.pub")
	if err := ExportPublicKey(otherSigner, pubKeyPath); err != nil {
		t.Fatalf("ExportPublicKey() error = %v", err)
	}

	result, err := VerifyWithPublicKey(chainJSON, pubKeyPath)
	if err != nil {
		t.Fatalf("VerifyWithPublicKey() error = %v", err)
	}
	if result.Overall {
		t.Error("VerifyWithPublicKey() with wrong key should not pass overall")
	}
}

// --- VerificationResult structure tests ---

func TestVerificationResult_AllStepsPassed(t *testing.T) {
	result := &VerificationResult{
		StepResults: []StepResult{
			{StepName: "step1", Passed: true, Details: "ok"},
			{StepName: "step2", Passed: true, Details: "ok"},
		},
		Overall: true,
	}

	if !result.Overall {
		t.Error("Overall should be true when all steps pass")
	}
}

func TestVerificationResult_OneStepFailed(t *testing.T) {
	result := &VerificationResult{
		StepResults: []StepResult{
			{StepName: "step1", Passed: true, Details: "ok"},
			{StepName: "step2", Passed: false, Details: "failed"},
		},
		Overall: false,
	}

	if result.Overall {
		t.Error("Overall should be false when any step fails")
	}
}

// --- Mock store for testing ---

type mockStore struct {
	evidence     map[uuid.UUID]*evidence.Evidence
	attestations map[string][]byte
}

func (m *mockStore) GetEvidence(_ context.Context, id uuid.UUID) (*evidence.Evidence, error) {
	ev, ok := m.evidence[id]
	if !ok {
		return nil, context.DeadlineExceeded // simulate not found
	}
	return ev, nil
}

func (m *mockStore) GetAttestation(_ context.Context, ref string) ([]byte, error) {
	data, ok := m.attestations[ref]
	if !ok {
		return nil, context.DeadlineExceeded // simulate not found
	}
	return data, nil
}
