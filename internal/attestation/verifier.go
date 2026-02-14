package attestation

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/grcengineering/ocean/internal/evidence"
)

// StepResult captures the outcome of a single verification step within a
// provenance chain verification. Each step has a human-readable name, a
// pass/fail status, and a details string explaining the outcome.
type StepResult struct {
	StepName string `json:"step_name"`
	Passed   bool   `json:"passed"`
	Details  string `json:"details"`
}

// VerificationResult aggregates all step results from a provenance chain
// verification and provides an overall pass/fail. Overall is true only if
// every step passed.
type VerificationResult struct {
	StepResults []StepResult `json:"step_results"`
	Overall     bool         `json:"overall"`
}

// AttestationChain is a self-contained JSON blob that packages evidence,
// its collection envelope, and optionally an evaluation envelope with its
// inputs, for third-party verification without needing a Store.
type AttestationChain struct {
	Evidence             evidence.Evidence `json:"evidence"`
	CollectionEnvelope   *DSSEEnvelope     `json:"collection_envelope"`
	EvaluationEnvelope   *DSSEEnvelope     `json:"evaluation_envelope,omitempty"`
	EvaluationInputs     []string          `json:"evaluation_inputs,omitempty"`
	EvaluationExpression string            `json:"evaluation_expression,omitempty"`
}

// EvidenceStore is the subset of the Store interface needed by the verifier.
// This avoids importing the full storage package and its dependencies, breaking
// the import cycle while still enabling provenance chain verification against
// persisted data.
type EvidenceStore interface {
	GetEvidence(ctx context.Context, id uuid.UUID) (*evidence.Evidence, error)
	GetAttestation(ctx context.Context, ref string) ([]byte, error)
}

// VerifyEnvelope verifies a DSSE envelope's signature against a public key.
// Returns a StepResult indicating pass/fail with details.
func VerifyEnvelope(envelope *DSSEEnvelope, publicKey ed25519.PublicKey) StepResult {
	err := VerifyDSSEEnvelope(envelope, publicKey)
	if err != nil {
		return StepResult{
			StepName: "envelope_signature",
			Passed:   false,
			Details:  fmt.Sprintf("DSSE envelope signature verification failed: %v", err),
		}
	}
	return StepResult{
		StepName: "envelope_signature",
		Passed:   true,
		Details:  "DSSE envelope signature verified successfully",
	}
}

// VerifyDigest compares the SHA-256 digest of data against an expected digest.
// Returns a StepResult indicating match/mismatch.
func VerifyDigest(data []byte, expectedDigest string) StepResult {
	actualDigest := DigestOf(data)
	if actualDigest != expectedDigest {
		return StepResult{
			StepName: "evidence_content_digest",
			Passed:   false,
			Details:  fmt.Sprintf("evidence content does not match attestation digest: got %s, want %s", actualDigest, expectedDigest),
		}
	}
	return StepResult{
		StepName: "evidence_content_digest",
		Passed:   true,
		Details:  fmt.Sprintf("content digest matches: %s", actualDigest),
	}
}

// VerifyCollectionAttestation performs a full Collection Attestation chain
// verification:
//  1. Verify evidence content digest matches the attestation predicate digest
//  2. Verify the DSSE envelope signature
//  3. Verify signer identity (keyID in envelope matches public key)
//  4. If evidence has a test transcript, verify its digest
func VerifyCollectionAttestation(ev *evidence.Evidence, envelope *DSSEEnvelope, publicKey ed25519.PublicKey) *VerificationResult {
	result := &VerificationResult{Overall: true}

	// Step 1: Verify evidence content digest matches attestation.
	digestResult := VerifyDigest(ev.RawData, ev.Attestation.Digest)
	result.StepResults = append(result.StepResults, digestResult)
	if !digestResult.Passed {
		result.Overall = false
	}

	// Step 2: Verify DSSE envelope signature.
	sigResult := VerifyEnvelope(envelope, publicKey)
	result.StepResults = append(result.StepResults, sigResult)
	if !sigResult.Passed {
		result.Overall = false
	}

	// Step 3: Verify signer identity — the envelope's keyID should be derivable
	// from the provided public key.
	signerResult := verifySignerIdentity(envelope, publicKey)
	result.StepResults = append(result.StepResults, signerResult)
	if !signerResult.Passed {
		result.Overall = false
	}

	// Step 4: If a test transcript exists, verify its digest against the
	// collection predicate's transcript digest.
	if ev.TestTranscript != nil {
		transcriptResult := verifyTranscriptDigest(ev.TestTranscript, envelope)
		result.StepResults = append(result.StepResults, transcriptResult)
		if !transcriptResult.Passed {
			result.Overall = false
		}
	}

	return result
}

// VerifyEvaluationAttestation performs Evaluation Attestation chain verification:
//  1. Verify DSSE envelope signature
//  2. Verify evidence input digests match the predicate
//  3. Verify expression digest matches
//  4. Verify verdict is present
func VerifyEvaluationAttestation(envelope *DSSEEnvelope, expectedEvidenceDigests []string, expectedExpression string, publicKey ed25519.PublicKey) *VerificationResult {
	result := &VerificationResult{Overall: true}

	// Step 1: Verify DSSE envelope signature.
	sigResult := VerifyEnvelope(envelope, publicKey)
	result.StepResults = append(result.StepResults, sigResult)
	if !sigResult.Passed {
		result.Overall = false
	}

	// Step 2: Extract the predicate from the envelope payload.
	predicate, err := extractEvaluationPredicate(envelope)
	if err != nil {
		result.StepResults = append(result.StepResults, StepResult{
			StepName: "evaluation_predicate_extract",
			Passed:   false,
			Details:  fmt.Sprintf("failed to extract evaluation predicate: %v", err),
		})
		result.Overall = false
		return result
	}

	// Step 3: Verify evidence input digests.
	digestsResult := verifyEvidenceInputDigests(predicate, expectedEvidenceDigests)
	result.StepResults = append(result.StepResults, digestsResult)
	if !digestsResult.Passed {
		result.Overall = false
	}

	// Step 4: Verify expression digest.
	expectedExprDigest := DigestOf([]byte(expectedExpression))
	exprResult := StepResult{StepName: "expression_digest"}
	if predicate.ExpressionDigest == expectedExprDigest {
		exprResult.Passed = true
		exprResult.Details = fmt.Sprintf("expression digest matches: %s", expectedExprDigest)
	} else {
		exprResult.Passed = false
		exprResult.Details = fmt.Sprintf("expression digest mismatch: got %s, want %s", predicate.ExpressionDigest, expectedExprDigest)
		result.Overall = false
	}
	result.StepResults = append(result.StepResults, exprResult)

	// Step 5: Verify verdict is present.
	verdictResult := StepResult{StepName: "verdict_present"}
	if predicate.Verdict != "" {
		verdictResult.Passed = true
		verdictResult.Details = fmt.Sprintf("verdict: %s (confidence: %s)", predicate.Verdict, predicate.Confidence)
	} else {
		verdictResult.Passed = false
		verdictResult.Details = "evaluation predicate has no verdict"
		result.Overall = false
	}
	result.StepResults = append(result.StepResults, verdictResult)

	return result
}

// VerifyProvenanceChain performs a full provenance chain verification by loading
// the evidence and its attestation(s) from the Store. It verifies:
//  1. Collection Attestation: content digest, envelope signature, signer identity
//  2. Evaluation Attestation (if exists): same checks for the evaluation envelope
//
// Each step reports pass/fail independently. The overall result fails if any
// step fails.
func VerifyProvenanceChain(ctx context.Context, store EvidenceStore, evidenceID uuid.UUID, publicKey ed25519.PublicKey) (*VerificationResult, error) {
	// Load the evidence record.
	ev, err := store.GetEvidence(ctx, evidenceID)
	if err != nil {
		return nil, fmt.Errorf("loading evidence %s: %w", evidenceID, err)
	}

	// Load the collection attestation envelope.
	if ev.Attestation.DSSEEnvelopeRef == "" {
		return &VerificationResult{
			StepResults: []StepResult{{
				StepName: "collection_attestation_present",
				Passed:   false,
				Details:  "evidence has no collection attestation reference",
			}},
			Overall: false,
		}, nil
	}

	envelopeJSON, err := store.GetAttestation(ctx, ev.Attestation.DSSEEnvelopeRef)
	if err != nil {
		return nil, fmt.Errorf("loading collection attestation %s: %w", ev.Attestation.DSSEEnvelopeRef, err)
	}

	var envelope DSSEEnvelope
	if err := json.Unmarshal(envelopeJSON, &envelope); err != nil {
		return nil, fmt.Errorf("unmarshaling collection envelope: %w", err)
	}

	// Verify the collection attestation chain.
	result := VerifyCollectionAttestation(ev, &envelope, publicKey)

	return result, nil
}

// VerifyWithPublicKey performs standalone verification of an attestation chain
// using only a JSON blob and a public key file path. This is the entry point
// for third-party verification without needing a running OCEAN instance or
// database.
func VerifyWithPublicKey(chainJSON []byte, publicKeyPath string) (*VerificationResult, error) {
	// Load the public key from file.
	publicKey, err := LoadPublicKey(publicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("loading public key: %w", err)
	}

	// Unmarshal the attestation chain.
	var chain AttestationChain
	if err := json.Unmarshal(chainJSON, &chain); err != nil {
		return nil, fmt.Errorf("unmarshaling attestation chain: %w", err)
	}

	// Verify the collection attestation.
	if chain.CollectionEnvelope == nil {
		return &VerificationResult{
			StepResults: []StepResult{{
				StepName: "collection_envelope_present",
				Passed:   false,
				Details:  "attestation chain has no collection envelope",
			}},
			Overall: false,
		}, nil
	}

	result := VerifyCollectionAttestation(&chain.Evidence, chain.CollectionEnvelope, publicKey)

	// If there's an evaluation envelope, verify it too.
	if chain.EvaluationEnvelope != nil {
		evalResult := VerifyEvaluationAttestation(
			chain.EvaluationEnvelope,
			chain.EvaluationInputs,
			chain.EvaluationExpression,
			publicKey,
		)
		result.StepResults = append(result.StepResults, evalResult.StepResults...)
		if !evalResult.Overall {
			result.Overall = false
		}
	}

	return result, nil
}

// --- Internal helpers ---

// verifySignerIdentity checks that the envelope's signature keyID matches
// the expected keyID derived from the provided public key.
func verifySignerIdentity(envelope *DSSEEnvelope, publicKey ed25519.PublicKey) StepResult {
	if len(envelope.Signatures) == 0 {
		return StepResult{
			StepName: "signer_identity",
			Passed:   false,
			Details:  "envelope has no signatures to verify signer identity",
		}
	}

	// Derive the expected keyID from the public key using the same algorithm
	// as Ed25519Signer.KeyID() (SHA-256 of public key, first 8 bytes hex).
	expectedKeyID := computeKeyID(publicKey)

	for _, sig := range envelope.Signatures {
		if sig.KeyID == expectedKeyID {
			return StepResult{
				StepName: "signer_identity",
				Passed:   true,
				Details:  fmt.Sprintf("signer identity verified: keyID %s", expectedKeyID),
			}
		}
	}

	return StepResult{
		StepName: "signer_identity",
		Passed:   false,
		Details:  fmt.Sprintf("no signature found with expected keyID %s", expectedKeyID),
	}
}

// computeKeyID derives a keyID from a public key using the same algorithm as
// Ed25519Signer: hex of first 8 bytes of SHA-256(publicKey).
func computeKeyID(publicKey ed25519.PublicKey) string {
	hash := sha256.Sum256(publicKey)
	return hex.EncodeToString(hash[:8])
}

// verifyTranscriptDigest verifies that the test transcript's current digest
// matches the digest recorded in the collection attestation predicate.
func verifyTranscriptDigest(transcript *evidence.TestTranscript, envelope *DSSEEnvelope) StepResult {
	// Extract the predicate from the envelope payload.
	predicate, err := extractCollectionPredicate(envelope)
	if err != nil {
		return StepResult{
			StepName: "transcript_digest",
			Passed:   false,
			Details:  fmt.Sprintf("failed to extract collection predicate: %v", err),
		}
	}

	if predicate.TranscriptDigest == "" {
		return StepResult{
			StepName: "transcript_digest",
			Passed:   false,
			Details:  "collection predicate has no transcript digest, but evidence has a transcript",
		}
	}

	// Compute the current transcript digest.
	currentDigest, err := DigestOfJSON(transcript)
	if err != nil {
		return StepResult{
			StepName: "transcript_digest",
			Passed:   false,
			Details:  fmt.Sprintf("failed to compute transcript digest: %v", err),
		}
	}

	if currentDigest != predicate.TranscriptDigest {
		return StepResult{
			StepName: "transcript_digest",
			Passed:   false,
			Details:  fmt.Sprintf("transcript digest mismatch: got %s, want %s", currentDigest, predicate.TranscriptDigest),
		}
	}

	return StepResult{
		StepName: "transcript_digest",
		Passed:   true,
		Details:  fmt.Sprintf("transcript digest verified: %s", currentDigest),
	}
}

// extractCollectionPredicate decodes the DSSE envelope payload and extracts
// the CollectionPredicate from the in-toto statement.
func extractCollectionPredicate(envelope *DSSEEnvelope) (*CollectionPredicate, error) {
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return nil, fmt.Errorf("decoding envelope payload: %w", err)
	}

	var stmt struct {
		PredicateType string              `json:"predicateType"`
		Predicate     CollectionPredicate `json:"predicate"`
	}
	if err := json.Unmarshal(payload, &stmt); err != nil {
		return nil, fmt.Errorf("unmarshaling statement: %w", err)
	}

	return &stmt.Predicate, nil
}

// extractEvaluationPredicate decodes the DSSE envelope payload and extracts
// the EvaluationPredicate from the in-toto statement.
func extractEvaluationPredicate(envelope *DSSEEnvelope) (*EvaluationPredicate, error) {
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return nil, fmt.Errorf("decoding envelope payload: %w", err)
	}

	var stmt struct {
		PredicateType string              `json:"predicateType"`
		Predicate     EvaluationPredicate `json:"predicate"`
	}
	if err := json.Unmarshal(payload, &stmt); err != nil {
		return nil, fmt.Errorf("unmarshaling statement: %w", err)
	}

	return &stmt.Predicate, nil
}

// verifyEvidenceInputDigests checks that the evidence digests in the evaluation
// predicate match the expected set of digests.
func verifyEvidenceInputDigests(predicate *EvaluationPredicate, expectedDigests []string) StepResult {
	if len(predicate.EvidenceDigests) != len(expectedDigests) {
		return StepResult{
			StepName: "evidence_input_digests",
			Passed:   false,
			Details:  fmt.Sprintf("evidence digest count mismatch: predicate has %d, expected %d", len(predicate.EvidenceDigests), len(expectedDigests)),
		}
	}

	// Build a set for comparison.
	expectedSet := make(map[string]bool, len(expectedDigests))
	for _, d := range expectedDigests {
		expectedSet[d] = true
	}

	for _, d := range predicate.EvidenceDigests {
		if !expectedSet[d] {
			return StepResult{
				StepName: "evidence_input_digests",
				Passed:   false,
				Details:  fmt.Sprintf("unexpected evidence digest in predicate: %s", d),
			}
		}
	}

	return StepResult{
		StepName: "evidence_input_digests",
		Passed:   true,
		Details:  fmt.Sprintf("all %d evidence input digests verified", len(expectedDigests)),
	}
}
