package github

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/grcengineering/ocean/internal/evidence"
	"github.com/grcengineering/ocean/internal/module"
)

func TestSecretPushTester_ID(t *testing.T) {
	tester := &SecretPushTester{}
	if tester.ID() != "github.secret_push" {
		t.Fatalf("expected ID %q, got %q", "github.secret_push", tester.ID())
	}
}

func TestSecretPushTester_SafetyClass(t *testing.T) {
	tester := &SecretPushTester{}
	if tester.SafetyClass() != module.SafetyClassObservable {
		t.Fatalf("expected SafetyClassObservable (%q), got %q", module.SafetyClassObservable, tester.SafetyClass())
	}
}

func TestSecretPushTester_EnvironmentScope(t *testing.T) {
	tester := &SecretPushTester{}
	if tester.EnvironmentScope() != module.ScopeStaging {
		t.Fatalf("expected ScopeStaging (%q), got %q", module.ScopeStaging, tester.EnvironmentScope())
	}
}

func TestNewGHClient_MissingToken(t *testing.T) {
	config := map[string]string{}

	_, err := newGHClient(config)
	if err == nil {
		t.Fatal("expected error when GITHUB_TOKEN is missing, got nil")
	}
}

func TestSecretPush_Test_MissingOwner(t *testing.T) {
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

	tester := &SecretPushTester{}
	_, err := tester.Test(context.Background(), config)
	if err == nil {
		t.Fatal("expected error when GITHUB_OWNER is missing, got nil")
	}
}

func TestSecretPush_Test_Blocked409(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "100")
		w.WriteHeader(http.StatusConflict)
		fmt.Fprint(w, `{"message":"Push protection blocked this push"}`)
	}))
	defer server.Close()

	config := map[string]string{
		"GITHUB_TOKEN":   "ghp_testtoken123",
		"GITHUB_API_URL": server.URL,
		"GITHUB_OWNER":   "testowner",
		"GITHUB_REPO":    "testrepo",
	}

	tester := &SecretPushTester{}
	results, err := tester.Test(context.Background(), config)
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
}

func TestSecretPush_Test_Blocked422(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "100")
		w.WriteHeader(http.StatusUnprocessableEntity)
		fmt.Fprint(w, `{"message":"Validation failed"}`)
	}))
	defer server.Close()

	config := map[string]string{
		"GITHUB_TOKEN":   "ghp_testtoken123",
		"GITHUB_API_URL": server.URL,
		"GITHUB_OWNER":   "testowner",
		"GITHUB_REPO":    "testrepo",
	}

	tester := &SecretPushTester{}
	results, err := tester.Test(context.Background(), config)
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
}

func TestSecretPush_Test_Allowed201(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "100")

		switch r.Method {
		case http.MethodPut:
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"content":{"sha":"abc123"}}`)
		case http.MethodDelete:
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{}`)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	config := map[string]string{
		"GITHUB_TOKEN":   "ghp_testtoken123",
		"GITHUB_API_URL": server.URL,
		"GITHUB_OWNER":   "testowner",
		"GITHUB_REPO":    "testrepo",
	}

	tester := &SecretPushTester{}
	results, err := tester.Test(context.Background(), config)
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

	if ev.TestTranscript == nil {
		t.Fatal("expected TestTranscript to be non-nil")
	}
}
