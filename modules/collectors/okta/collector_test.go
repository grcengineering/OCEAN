package okta

import (
	"net/http"
	"testing"
)

func TestNewClient_MissingToken(t *testing.T) {
	config := map[string]string{
		"OKTA_DOMAIN": "example.okta.com",
	}
	_, err := NewClient(config)
	if err == nil {
		t.Fatal("NewClient() should return error when OKTA_API_TOKEN is missing")
	}
}

func TestNewClient_MissingDomain(t *testing.T) {
	config := map[string]string{
		"OKTA_API_TOKEN": "test-token",
	}
	_, err := NewClient(config)
	if err == nil {
		t.Fatal("NewClient() should return error when OKTA_DOMAIN is missing")
	}
}

func TestNewClient_EmptyToken(t *testing.T) {
	config := map[string]string{
		"OKTA_API_TOKEN": "",
		"OKTA_DOMAIN":    "example.okta.com",
	}
	_, err := NewClient(config)
	if err == nil {
		t.Fatal("NewClient() should return error when OKTA_API_TOKEN is empty")
	}
}

func TestNewClient_EmptyDomain(t *testing.T) {
	config := map[string]string{
		"OKTA_API_TOKEN": "test-token",
		"OKTA_DOMAIN":    "",
	}
	_, err := NewClient(config)
	if err == nil {
		t.Fatal("NewClient() should return error when OKTA_DOMAIN is empty")
	}
}

func TestNewClient_Success(t *testing.T) {
	config := map[string]string{
		"OKTA_API_TOKEN": "test-token-00abc",
		"OKTA_DOMAIN":    "example.okta.com",
	}
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() returned error: %v", err)
	}
	if client == nil {
		t.Fatal("NewClient() returned nil client")
	}
	if client.domain != "example.okta.com" {
		t.Errorf("client.domain = %q, want %q", client.domain, "example.okta.com")
	}
	if client.token != "test-token-00abc" {
		t.Errorf("client.token = %q, want %q", client.token, "test-token-00abc")
	}
}

func TestNewClient_SetsUserAgent(t *testing.T) {
	config := map[string]string{
		"OKTA_API_TOKEN": "test-token",
		"OKTA_DOMAIN":    "example.okta.com",
	}
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() returned error: %v", err)
	}

	req, _ := http.NewRequest("GET", "https://example.okta.com/api/v1/test", nil)
	client.setHeaders(req)

	ua := req.Header.Get("User-Agent")
	if ua == "" {
		t.Error("User-Agent header should not be empty")
	}
	if ua != "OCEAN/0.1.0" {
		t.Errorf("User-Agent = %q, want %q", ua, "OCEAN/0.1.0")
	}

	auth := req.Header.Get("Authorization")
	if auth != "SSWS test-token" {
		t.Errorf("Authorization = %q, want %q", auth, "SSWS test-token")
	}

	ct := req.Header.Get("Accept")
	if ct != "application/json" {
		t.Errorf("Accept = %q, want %q", ct, "application/json")
	}
}

func TestClient_BaseURL(t *testing.T) {
	config := map[string]string{
		"OKTA_API_TOKEN": "test-token",
		"OKTA_DOMAIN":    "example.okta.com",
	}
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() returned error: %v", err)
	}

	expected := "https://example.okta.com"
	if client.BaseURL() != expected {
		t.Errorf("BaseURL() = %q, want %q", client.BaseURL(), expected)
	}
}
