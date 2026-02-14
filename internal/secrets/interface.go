// Package secrets provides pluggable secret retrieval for OCEAN modules.
// Secrets are never stored in evidence; this package exists to supply
// credentials to modules at runtime.
package secrets

// Provider retrieves secrets without exposing them in evidence.
type Provider interface {
	Get(name string) (string, error)
}
