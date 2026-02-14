package attestation

import (
	"encoding/json"
	"fmt"
	"time"
)

const (
	// EvaluationPredicateType identifies the OCEAN evaluation predicate,
	// which captures the CEL expression, evidence inputs, and verdict for
	// a control evaluation event.
	EvaluationPredicateType = "https://ocean.grc.engineering/attestation/v1/evaluation"
)

// EvaluationPredicate captures the inputs and output of a CEL-based control
// evaluation. It records which evidence was evaluated, what expression was
// used, and what verdict was reached, providing full auditability of the
// evaluation decision.
type EvaluationPredicate struct {
	ControlID        string    `json:"controlId"`
	EvidenceDigests  []string  `json:"evidenceDigests"`
	ExpressionDigest string    `json:"expressionDigest"`
	ExpressionText   string    `json:"expressionText"`
	Verdict          string    `json:"verdict"`
	Confidence       string    `json:"confidence"`
	Timestamp        time.Time `json:"timestamp"`
}

// NewEvaluationAttestation creates an in-toto statement for a control
// evaluation event. The statement binds the control ID as the subject and
// attaches an EvaluationPredicate with full evaluation metadata.
func NewEvaluationAttestation(
	controlID string,
	evidenceDigests []string,
	expressionDigest, expressionText, verdict, confidence string,
) (*InTotoStatement, error) {
	now := time.Now().UTC()

	predicate := &EvaluationPredicate{
		ControlID:        controlID,
		EvidenceDigests:  evidenceDigests,
		ExpressionDigest: expressionDigest,
		ExpressionText:   expressionText,
		Verdict:          verdict,
		Confidence:       confidence,
		Timestamp:        now,
	}

	// The subject is the control evaluation, identified by the expression digest.
	digestHex := expressionDigest
	if len(digestHex) > 7 && digestHex[:7] == "sha256:" {
		digestHex = digestHex[7:]
	}

	return &InTotoStatement{
		Type: InTotoStatementType,
		Subject: []Subject{{
			Name:   fmt.Sprintf("control/%s", controlID),
			Digest: map[string]string{"sha256": digestHex},
		}},
		PredicateType: EvaluationPredicateType,
		Predicate:     predicate,
	}, nil
}

// SignEvaluation creates a signed DSSE envelope for an evaluation attestation
// statement. Returns the envelope and a content-addressable reference string
// (sha256:hex of the envelope JSON).
func SignEvaluation(stmt *InTotoStatement, signer Signer) (*DSSEEnvelope, string, error) {
	stmtJSON, err := json.Marshal(stmt)
	if err != nil {
		return nil, "", fmt.Errorf("marshaling evaluation statement: %w", err)
	}

	envelope, err := CreateDSSEEnvelope(stmtJSON, signer)
	if err != nil {
		return nil, "", fmt.Errorf("creating evaluation DSSE envelope: %w", err)
	}

	envelopeJSON, err := json.Marshal(envelope)
	if err != nil {
		return nil, "", fmt.Errorf("marshaling evaluation envelope: %w", err)
	}

	ref := DigestOf(envelopeJSON)
	return envelope, ref, nil
}
