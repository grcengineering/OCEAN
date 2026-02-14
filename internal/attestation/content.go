// Package attestation provides cryptographic signing and DSSE attestation
// for OCEAN evidence records. It implements Ed25519 key management,
// content-addressable digests, DSSE envelope creation/verification, and
// in-toto collection attestations.
package attestation

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
)

// DigestOf computes the SHA-256 digest of raw bytes.
// Returns the digest in the format "sha256:<hex>".
func DigestOf(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", h)
}

// DigestOfJSON computes the SHA-256 digest of a JSON-serializable value.
// The value is marshaled to JSON first, then the digest is computed over the
// resulting bytes. Returns the digest in the format "sha256:<hex>".
func DigestOfJSON(v interface{}) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("marshaling for digest: %w", err)
	}
	return DigestOf(data), nil
}
