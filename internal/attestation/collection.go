package attestation

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/grcengineering/ocean/internal/evidence"
)

const (
	// InTotoStatementType is the _type value for in-toto v1 statements.
	InTotoStatementType = "https://in-toto.io/Statement/v1"

	// CollectionPredicateType identifies the OCEAN collection predicate,
	// which captures what was collected/tested, by what module, from where.
	CollectionPredicateType = "https://ocean.grc.engineering/attestation/v1/collection"
)

// InTotoStatement is an in-toto v1 statement that binds a subject (the evidence)
// to a predicate (the collection metadata) under a cryptographic signature.
type InTotoStatement struct {
	Type          string      `json:"_type"`
	Subject       []Subject   `json:"subject"`
	PredicateType string      `json:"predicateType"`
	Predicate     interface{} `json:"predicate"`
}

// Subject identifies a software artifact by name and one or more digests.
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// CollectionPredicate captures what was collected or tested, by what module,
// from which source system. This is the OCEAN-specific predicate that provides
// full provenance for every evidence record.
type CollectionPredicate struct {
	ModuleID         string       `json:"moduleId"`
	ModuleVersion    string       `json:"moduleVersion"`
	ModuleType       string       `json:"moduleType"`
	Timestamp        time.Time    `json:"timestamp"`
	Source           SourceDetail `json:"source"`
	EvidenceDigest   string       `json:"evidenceDigest"`
	RawDataDigest    string       `json:"rawDataDigest"`
	TranscriptDigest string       `json:"transcriptDigest,omitempty"`
}

// SourceDetail identifies where evidence came from, including the external
// system, API version, and specific endpoint queried.
type SourceDetail struct {
	System     string `json:"system"`
	APIVersion string `json:"apiVersion"`
	Endpoint   string `json:"endpoint"`
}

// NewCollectionAttestation creates an in-toto statement for an evidence
// collection event. The statement binds the evidence ID as the subject and
// attaches a CollectionPredicate with full provenance metadata.
func NewCollectionAttestation(ev *evidence.Evidence) (*InTotoStatement, error) {
	// Compute digest of the raw data (the API response payload).
	rawDataDigest := DigestOf(ev.RawData)

	// Compute digest of the evidence raw data for the subject binding.
	evidenceDigest := rawDataDigest

	predicate := CollectionPredicate{
		ModuleID:       ev.Metadata.Module.Name,
		ModuleVersion:  ev.Metadata.Module.Version,
		ModuleType:     ev.Metadata.Module.Type,
		Timestamp:      ev.Time,
		Source: SourceDetail{
			System:     ev.Metadata.Source.System,
			APIVersion: ev.Metadata.Source.APIVersion,
			Endpoint:   ev.Metadata.Source.Endpoint,
		},
		EvidenceDigest: evidenceDigest,
		RawDataDigest:  rawDataDigest,
	}

	// If a test transcript exists, compute its digest for auditability.
	if ev.TestTranscript != nil {
		transcriptDigest, err := DigestOfJSON(ev.TestTranscript)
		if err != nil {
			return nil, fmt.Errorf("computing transcript digest: %w", err)
		}
		predicate.TranscriptDigest = transcriptDigest
	}

	// Strip "sha256:" prefix for the subject digest map.
	digestHex := evidenceDigest
	if len(digestHex) > 7 && digestHex[:7] == "sha256:" {
		digestHex = digestHex[7:]
	}

	return &InTotoStatement{
		Type: InTotoStatementType,
		Subject: []Subject{{
			Name:   fmt.Sprintf("evidence/%s", ev.ID),
			Digest: map[string]string{"sha256": digestHex},
		}},
		PredicateType: CollectionPredicateType,
		Predicate:     predicate,
	}, nil
}

// SignEvidence creates a Collection Attestation for the given evidence record,
// wraps it in a signed DSSE envelope, and attaches the attestation reference
// to the evidence in place. Returns the signed DSSE envelope for storage.
func SignEvidence(ev *evidence.Evidence, signer Signer) (*DSSEEnvelope, error) {
	// Create in-toto statement from evidence.
	stmt, err := NewCollectionAttestation(ev)
	if err != nil {
		return nil, fmt.Errorf("creating collection attestation: %w", err)
	}

	// Marshal statement to JSON for signing.
	stmtJSON, err := json.Marshal(stmt)
	if err != nil {
		return nil, fmt.Errorf("marshaling attestation statement: %w", err)
	}

	// Create DSSE envelope (signs the PAE of the statement).
	envelope, err := CreateDSSEEnvelope(stmtJSON, signer)
	if err != nil {
		return nil, fmt.Errorf("creating DSSE envelope: %w", err)
	}

	// Compute envelope digest for storage reference.
	envelopeJSON, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("marshaling envelope: %w", err)
	}
	envelopeRef := DigestOf(envelopeJSON)

	// Compute evidence digest (of the raw data).
	evidenceDigest := DigestOf(ev.RawData)

	// Attach attestation reference to the evidence record.
	ev.Attestation = evidence.AttestationRef{
		Type:            "collection",
		DSSEEnvelopeRef: envelopeRef,
		Digest:          evidenceDigest,
		Signer:          signer.KeyID(),
	}

	return envelope, nil
}
