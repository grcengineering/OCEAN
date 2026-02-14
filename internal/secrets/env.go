package secrets

import (
	"fmt"
	"os"
)

// EnvProvider reads secrets from environment variables.
type EnvProvider struct{}

// NewEnvProvider creates an EnvProvider.
func NewEnvProvider() *EnvProvider { return &EnvProvider{} }

// Get retrieves the secret named by the given environment variable.
func (p *EnvProvider) Get(name string) (string, error) {
	val := os.Getenv(name)
	if val == "" {
		return "", fmt.Errorf("secret %q not found in environment", name)
	}
	return val, nil
}
