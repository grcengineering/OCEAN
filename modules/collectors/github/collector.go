// Package github provides OCEAN collectors for GitHub's REST API v3.
// It queries branch protection rules, repository settings, and other
// security-relevant configuration via standard library net/http calls
// with proper rate-limit handling and authentication.
package github

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/grcengineering/ocean/internal/module"
)

const (
	// defaultBaseURL is the GitHub REST API v3 base URL.
	defaultBaseURL = "https://api.github.com"

	// defaultAPIVersion is the GitHub API version used in Accept headers.
	defaultAPIVersion = "2022-11-28"
)

// client wraps net/http for GitHub API calls with authentication,
// rate-limit handling, and proper headers.
type client struct {
	httpClient *http.Client
	baseURL    string
	token      string
}

// newClient creates a GitHub API client from a module config map.
// Requires GITHUB_TOKEN. Returns an error if the token is missing.
func newClient(config map[string]string) (*client, error) {
	token := config["GITHUB_TOKEN"]
	if token == "" {
		return nil, fmt.Errorf("GITHUB_TOKEN is required")
	}

	baseURL := config["GITHUB_API_URL"]
	if baseURL == "" {
		baseURL = defaultBaseURL
	}

	return &client{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		baseURL:    baseURL,
		token:      token,
	}, nil
}

// get performs an authenticated GET request to the GitHub API.
// It handles rate limiting by checking X-RateLimit headers and
// waiting if the limit has been exceeded.
func (c *client) get(path string) (json.RawMessage, int, error) {
	url := c.baseURL + path

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("X-GitHub-Api-Version", defaultAPIVersion)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("executing request to %s: %w", path, err)
	}
	defer resp.Body.Close()

	// Check rate limiting before reading the body.
	if err := c.checkRateLimit(resp); err != nil {
		return nil, resp.StatusCode, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("reading response body: %w", err)
	}

	return json.RawMessage(body), resp.StatusCode, nil
}

// put performs an authenticated PUT request to the GitHub API with a JSON body.
func (c *client) put(path string, body io.Reader) (json.RawMessage, int, error) {
	url := c.baseURL + path

	req, err := http.NewRequest(http.MethodPut, url, body)
	if err != nil {
		return nil, 0, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("X-GitHub-Api-Version", defaultAPIVersion)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("executing request to %s: %w", path, err)
	}
	defer resp.Body.Close()

	if err := c.checkRateLimit(resp); err != nil {
		return nil, resp.StatusCode, err
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("reading response body: %w", err)
	}

	return json.RawMessage(respBody), resp.StatusCode, nil
}

// delete performs an authenticated DELETE request to the GitHub API with a JSON body.
func (c *client) delete(path string, body io.Reader) (int, error) {
	url := c.baseURL + path

	req, err := http.NewRequest(http.MethodDelete, url, body)
	if err != nil {
		return 0, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("X-GitHub-Api-Version", defaultAPIVersion)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("executing request to %s: %w", path, err)
	}
	defer resp.Body.Close()

	if err := c.checkRateLimit(resp); err != nil {
		return resp.StatusCode, err
	}

	// Drain body to allow connection reuse.
	io.Copy(io.Discard, resp.Body)

	return resp.StatusCode, nil
}

// checkRateLimit inspects GitHub's X-RateLimit headers. If the remaining
// request count has reached zero, it returns an error indicating when the
// limit resets. This is a non-blocking check -- the caller decides whether
// to retry.
func (c *client) checkRateLimit(resp *http.Response) error {
	remaining := resp.Header.Get("X-RateLimit-Remaining")
	if remaining == "" {
		return nil
	}

	rem, err := strconv.Atoi(remaining)
	if err != nil {
		return nil // Non-numeric header; ignore.
	}

	if rem == 0 {
		resetStr := resp.Header.Get("X-RateLimit-Reset")
		resetTime := "unknown"
		if resetStr != "" {
			if ts, err := strconv.ParseInt(resetStr, 10, 64); err == nil {
				resetTime = time.Unix(ts, 0).UTC().Format(time.RFC3339)
			}
		}
		return fmt.Errorf("GitHub API rate limit exceeded, resets at %s", resetTime)
	}

	return nil
}

// RegisterAll registers all GitHub collectors with the given registry.
func RegisterAll(reg *module.Registry) {
	reg.RegisterCollector(&BranchProtectionCollector{})
}
