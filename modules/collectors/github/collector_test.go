package github

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/grcengineering/ocean/internal/evidence"
)

func TestNewClient_MissingToken(t *testing.T) {
	config := map[string]string{}

	_, err := newClient(config)
	if err == nil {
		t.Fatal("expected error when GITHUB_TOKEN is missing, got nil")
	}
}

func TestNewClient_DefaultBaseURL(t *testing.T) {
	config := map[string]string{
		"GITHUB_TOKEN": "ghp_testtoken123",
	}

	c, err := newClient(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if c.baseURL != "https://api.github.com" {
		t.Fatalf("expected default base URL %q, got %q", "https://api.github.com", c.baseURL)
	}
}

func TestNewClient_CustomBaseURL(t *testing.T) {
	config := map[string]string{
		"GITHUB_TOKEN":   "ghp_testtoken123",
		"GITHUB_API_URL": "https://github.example.com/api/v3",
	}

	c, err := newClient(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if c.baseURL != "https://github.example.com/api/v3" {
		t.Fatalf("expected base URL %q, got %q", "https://github.example.com/api/v3", c.baseURL)
	}
}

func TestBranchProtection_ID(t *testing.T) {
	c := &BranchProtectionCollector{}
	if c.ID() != "github.branch_protection" {
		t.Fatalf("expected ID %q, got %q", "github.branch_protection", c.ID())
	}
}

func TestBranchProtection_CredentialRequirements(t *testing.T) {
	c := &BranchProtectionCollector{}
	reqs := c.CredentialRequirements()

	if len(reqs) != 4 {
		t.Fatalf("expected 4 credential requirements, got %d", len(reqs))
	}

	expectedNames := map[string]bool{
		"GITHUB_TOKEN":  false,
		"GITHUB_OWNER":  false,
		"GITHUB_REPO":   false,
		"GITHUB_BRANCH": false,
	}

	for _, req := range reqs {
		if _, ok := expectedNames[req.Name]; !ok {
			t.Fatalf("unexpected credential requirement name: %q", req.Name)
		}
		expectedNames[req.Name] = true
	}

	for name, found := range expectedNames {
		if !found {
			t.Fatalf("missing credential requirement: %q", name)
		}
	}
}

func TestBranchProtection_Collect_MissingOwner(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := map[string]string{
		"GITHUB_TOKEN":   "ghp_testtoken123",
		"GITHUB_API_URL": server.URL,
		"GITHUB_OWNER":   "",
		"GITHUB_REPO":    "test-repo",
	}

	c := &BranchProtectionCollector{}
	_, err := c.Collect(context.Background(), config)
	if err == nil {
		t.Fatal("expected error when GITHUB_OWNER is missing, got nil")
	}
}

func TestBranchProtection_Collect_Protected(t *testing.T) {
	protectionJSON := `{
		"required_status_checks": {
			"strict": true,
			"contexts": ["ci"]
		},
		"enforce_admins": {
			"enabled": true
		},
		"required_pull_request_reviews": {
			"dismiss_stale_reviews": true,
			"require_code_owner_reviews": true,
			"required_approving_review_count": 1
		},
		"allow_force_pushes": {
			"enabled": false
		},
		"allow_deletions": {
			"enabled": false
		}
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expectedPath := "/repos/testowner/testrepo/branches/main/protection"
		if r.URL.Path != expectedPath {
			t.Errorf("unexpected request path: got %q, want %q", r.URL.Path, expectedPath)
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer ghp_testtoken123" {
			t.Errorf("unexpected auth header: got %q", authHeader)
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-RateLimit-Remaining", "100")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, protectionJSON)
	}))
	defer server.Close()

	config := map[string]string{
		"GITHUB_TOKEN":   "ghp_testtoken123",
		"GITHUB_API_URL": server.URL,
		"GITHUB_OWNER":   "testowner",
		"GITHUB_REPO":    "testrepo",
		"GITHUB_BRANCH":  "main",
	}

	c := &BranchProtectionCollector{}
	results, err := c.Collect(context.Background(), config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 evidence record, got %d", len(results))
	}

	ev := results[0]
	if ev.StatusID != evidence.StatusEffective {
		t.Fatalf("expected StatusEffective (%d), got %d", evidence.StatusEffective, ev.StatusID)
	}

	if ev.ControlID != "scm.branch_protection" {
		t.Fatalf("expected control ID %q, got %q", "scm.branch_protection", ev.ControlID)
	}
}

func TestBranchProtection_Collect_NotProtected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "100")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"message":"Branch not protected"}`)
	}))
	defer server.Close()

	config := map[string]string{
		"GITHUB_TOKEN":   "ghp_testtoken123",
		"GITHUB_API_URL": server.URL,
		"GITHUB_OWNER":   "testowner",
		"GITHUB_REPO":    "testrepo",
		"GITHUB_BRANCH":  "main",
	}

	c := &BranchProtectionCollector{}
	results, err := c.Collect(context.Background(), config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 evidence record, got %d", len(results))
	}

	ev := results[0]
	if ev.StatusID != evidence.StatusIneffective {
		t.Fatalf("expected StatusIneffective (%d), got %d", evidence.StatusIneffective, ev.StatusID)
	}
}
