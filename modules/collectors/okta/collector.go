// Package okta provides OCEAN collector modules for Okta identity management.
// It implements real-world evidence collection by querying the Okta Management API
// for MFA policies, user configurations, and security posture data.
package okta

import (
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// Client is a rate-limited HTTP client for the Okta Management API.
// It handles authentication, rate limiting, and common request headers.
type Client struct {
	domain     string
	token      string
	httpClient *http.Client
	insecure   bool // use http:// instead of https:// (for testing only)

	// Simple token-bucket rate limiter: one request per interval.
	rateMu       sync.Mutex
	lastRequest  time.Time
	rateInterval time.Duration
}

// NewClient creates a new Okta API client from the provided configuration.
// Required config keys: OKTA_API_TOKEN, OKTA_DOMAIN.
// Optional config key: OKTA_INSECURE ("true" to use http:// for testing).
func NewClient(config map[string]string) (*Client, error) {
	token := config["OKTA_API_TOKEN"]
	if token == "" {
		return nil, fmt.Errorf("OKTA_API_TOKEN is required")
	}

	domain := config["OKTA_DOMAIN"]
	if domain == "" {
		return nil, fmt.Errorf("OKTA_DOMAIN is required")
	}

	insecure := config["OKTA_INSECURE"] == "true"

	return &Client{
		domain:   domain,
		token:    token,
		insecure: insecure,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		rateInterval: 100 * time.Millisecond, // 10 requests per second max
	}, nil
}

// BaseURL returns the base URL for the Okta API.
func (c *Client) BaseURL() string {
	scheme := "https"
	if c.insecure {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s", scheme, c.domain)
}

// setHeaders sets the standard Okta API request headers.
func (c *Client) setHeaders(req *http.Request) {
	req.Header.Set("Authorization", "SSWS "+c.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "OCEAN/0.1.0")
}

// Do executes an HTTP request with rate limiting and standard headers.
// It returns the response body bytes and any error encountered.
func (c *Client) Do(req *http.Request) ([]byte, int, error) {
	c.setHeaders(req)

	// Simple rate limiting: wait if we've made a request too recently.
	c.rateMu.Lock()
	elapsed := time.Since(c.lastRequest)
	if elapsed < c.rateInterval {
		time.Sleep(c.rateInterval - elapsed)
	}
	c.lastRequest = time.Now()
	c.rateMu.Unlock()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("okta API request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to read okta API response: %w", err)
	}

	return body, resp.StatusCode, nil
}
