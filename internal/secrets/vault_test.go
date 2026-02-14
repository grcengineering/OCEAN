package secrets

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVaultProvider_Get_Success(t *testing.T) {
	// Simulate Vault KV v2 response.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if got := r.Header.Get("X-Vault-Token"); got != "test-token" {
			t.Errorf("expected X-Vault-Token=test-token, got %q", got)
		}
		if r.URL.Path != "/v1/secret/data/my-secret" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"data": map[string]interface{}{
					"value": "s3cret-value",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	p := NewVaultProvider(server.URL, "test-token", "secret")
	val, err := p.Get("my-secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != "s3cret-value" {
		t.Errorf("expected %q, got %q", "s3cret-value", val)
	}
}

func TestVaultProvider_Get_CustomMountPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/kv/data/db-pass" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"data": map[string]interface{}{
					"value": "db-password",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	p := NewVaultProvider(server.URL, "tok", "kv")
	val, err := p.Get("db-pass")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != "db-password" {
		t.Errorf("expected %q, got %q", "db-password", val)
	}
}

func TestVaultProvider_Get_DefaultMountPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/secret/data/foo" {
			t.Errorf("expected /v1/secret/data/foo, got %s", r.URL.Path)
		}
		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"data": map[string]interface{}{
					"value": "bar",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	p := NewVaultProvider(server.URL, "tok", "")
	val, err := p.Get("foo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != "bar" {
		t.Errorf("expected %q, got %q", "bar", val)
	}
}

func TestVaultProvider_Get_AuthFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"errors":["permission denied"]}`))
	}))
	defer server.Close()

	p := NewVaultProvider(server.URL, "bad-token", "secret")
	_, err := p.Get("my-secret")
	if err == nil {
		t.Fatal("expected error for auth failure")
	}
}

func TestVaultProvider_Get_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	p := NewVaultProvider(server.URL, "tok", "secret")
	_, err := p.Get("nonexistent")
	if err == nil {
		t.Fatal("expected error for missing secret")
	}
}

func TestVaultProvider_Get_ConnectionFailure(t *testing.T) {
	p := NewVaultProvider("http://127.0.0.1:1", "tok", "secret")
	_, err := p.Get("anything")
	if err == nil {
		t.Fatal("expected error for connection failure")
	}
}

func TestVaultProvider_Get_MissingValueKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Valid KV v2 structure but no "value" key inside data.data.
		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"data": map[string]interface{}{
					"other_key": "something",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	p := NewVaultProvider(server.URL, "tok", "secret")
	_, err := p.Get("no-value")
	if err == nil {
		t.Fatal("expected error when value key is missing")
	}
}

func TestVaultProvider_Get_MalformedJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{not valid json`))
	}))
	defer server.Close()

	p := NewVaultProvider(server.URL, "tok", "secret")
	_, err := p.Get("bad-json")
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}
