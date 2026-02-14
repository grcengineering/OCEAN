package module

// Module is the base interface for all pluggable integrations in OCEAN.
// Every collector and tester must implement this interface to provide
// identification, versioning, and credential discovery.
type Module interface {
	// ID returns the unique identifier for this module (e.g., "okta-mfa-collector").
	ID() string

	// Name returns a human-readable name for this module.
	Name() string

	// Version returns the semantic version of this module.
	Version() string

	// SourceSystem returns the name of the external system this module interacts with.
	SourceSystem() string

	// EvidenceTypes returns the OCSF class UIDs that this module can produce.
	EvidenceTypes() []int

	// CredentialRequirements returns the credentials this module needs to operate.
	CredentialRequirements() []CredentialReq
}

// CredentialReq describes a single credential that a module requires.
type CredentialReq struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description"`
	Required    bool   `json:"required"`
}
