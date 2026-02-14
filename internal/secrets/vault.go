package secrets

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// VaultProvider retrieves secrets from a HashiCorp Vault KV v2 engine
// using the Vault HTTP API.
type VaultProvider struct {
	addr      string
	token     string
	mountPath string
	client    *http.Client
}

// NewVaultProvider creates a VaultProvider that reads secrets from the
// given Vault server. If mountPath is empty it defaults to "secret".
func NewVaultProvider(addr, token, mountPath string) *VaultProvider {
	if mountPath == "" {
		mountPath = "secret"
	}
	return &VaultProvider{
		addr:      strings.TrimRight(addr, "/"),
		token:     token,
		mountPath: mountPath,
		client:    &http.Client{},
	}
}

// Get retrieves a secret by name from Vault's KV v2 engine.
// It expects the secret to contain a "value" key within the KV data.
func (p *VaultProvider) Get(name string) (string, error) {
	url := fmt.Sprintf("%s/v1/%s/data/%s", p.addr, p.mountPath, name)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("vault: failed to create request: %w", err)
	}
	req.Header.Set("X-Vault-Token", p.token)

	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("vault: connection failed for secret %q: %w", name, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("vault: failed to read response body: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		// continue below
	case http.StatusForbidden, http.StatusUnauthorized:
		return "", fmt.Errorf("vault: authentication failed for secret %q (HTTP %d): %s",
			name, resp.StatusCode, string(body))
	case http.StatusNotFound:
		return "", fmt.Errorf("vault: secret %q not found", name)
	default:
		return "", fmt.Errorf("vault: unexpected status %d for secret %q: %s",
			resp.StatusCode, name, string(body))
	}

	// Vault KV v2 response structure:
	//   {"data": {"data": {"value": "..."}, "metadata": {...}}}
	var result struct {
		Data struct {
			Data map[string]interface{} `json:"data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("vault: failed to parse response for secret %q: %w", name, err)
	}

	val, ok := result.Data.Data["value"]
	if !ok {
		return "", fmt.Errorf("vault: secret %q has no \"value\" key", name)
	}

	strVal, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("vault: secret %q value is not a string", name)
	}

	return strVal, nil
}
