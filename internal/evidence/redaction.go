package evidence

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
)

// RedactionConfig specifies which fields and values to redact from evidence.
type RedactionConfig struct {
	// RemoveRawData removes the entire raw_data field.
	RemoveRawData bool

	// MaskObservableTypes replaces observable values of these types with "***REDACTED***".
	MaskObservableTypes []string

	// HashObservableTypes replaces observable values of these types with a SHA-256 hash.
	// This preserves referential integrity (same value -> same hash) while hiding the original.
	HashObservableTypes []string

	// RemoveFields removes the specified top-level fields by name.
	// Supported: "findings", "attestation", "enrichments", "test_transcript".
	RemoveFields []string
}

const redactedPlaceholder = "***REDACTED***"

// RedactEvidence returns a new Evidence record with sensitive fields redacted
// according to the provided configuration. The original evidence is never
// modified -- the returned value is a deep copy with redactions applied.
func RedactEvidence(ev *Evidence, config RedactionConfig) *Evidence {
	// Start with a shallow copy.
	redacted := *ev

	// Deep copy slices to avoid mutating the original.
	if len(ev.Observables) > 0 {
		redacted.Observables = make([]Observable, len(ev.Observables))
		copy(redacted.Observables, ev.Observables)
	}
	if len(ev.Findings) > 0 {
		redacted.Findings = make([]Finding, len(ev.Findings))
		copy(redacted.Findings, ev.Findings)
	}
	if len(ev.Enrichments) > 0 {
		redacted.Enrichments = make([]Enrichment, len(ev.Enrichments))
		copy(redacted.Enrichments, ev.Enrichments)
	}
	if ev.RawData != nil {
		rawCopy := make(json.RawMessage, len(ev.RawData))
		copy(rawCopy, ev.RawData)
		redacted.RawData = rawCopy
	}

	// Remove raw data if configured.
	if config.RemoveRawData {
		redacted.RawData = nil
	}

	// Build lookup sets for observable redaction.
	maskSet := toSet(config.MaskObservableTypes)
	hashSet := toSet(config.HashObservableTypes)

	// Redact observables.
	for i := range redacted.Observables {
		obs := &redacted.Observables[i]
		if _, ok := maskSet[obs.Type]; ok {
			obs.Value = redactedPlaceholder
		} else if _, ok := hashSet[obs.Type]; ok {
			obs.Value = hashValue(obs.Value)
		}
	}

	// Remove specified fields.
	removeSet := toSet(config.RemoveFields)
	if _, ok := removeSet["findings"]; ok {
		redacted.Findings = nil
	}
	if _, ok := removeSet["attestation"]; ok {
		redacted.Attestation = AttestationRef{}
	}
	if _, ok := removeSet["enrichments"]; ok {
		redacted.Enrichments = nil
	}
	if _, ok := removeSet["test_transcript"]; ok {
		redacted.TestTranscript = nil
	}

	return &redacted
}

// toSet converts a string slice into a set (map) for O(1) lookups.
func toSet(items []string) map[string]struct{} {
	s := make(map[string]struct{}, len(items))
	for _, item := range items {
		s[item] = struct{}{}
	}
	return s
}

// hashValue returns a SHA-256 hash of the value with a "sha256:" prefix.
func hashValue(value string) string {
	h := sha256.Sum256([]byte(value))
	return fmt.Sprintf("sha256:%x", h)
}
