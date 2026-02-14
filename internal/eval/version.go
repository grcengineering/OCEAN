// Package eval implements OCEAN's CEL-based evaluation engine for determining
// control effectiveness from evidence records.
package eval

import (
	"crypto/sha256"
	"fmt"
)

// ContentAddress computes the SHA-256 content address of a CEL expression
// string. This provides a stable, deterministic identifier for an expression
// that can be stored alongside evaluation results for auditability.
// Returns the digest in "sha256:<hex>" format.
func ContentAddress(expression string) string {
	h := sha256.Sum256([]byte(expression))
	return fmt.Sprintf("sha256:%x", h)
}
