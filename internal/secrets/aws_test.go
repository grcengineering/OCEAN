package secrets

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAWSProvider_Get_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if got := r.Header.Get("X-Amz-Target"); got != "secretsmanager.GetSecretValue" {
			t.Errorf("expected X-Amz-Target=secretsmanager.GetSecretValue, got %q", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/x-amz-json-1.1" {
			t.Errorf("expected Content-Type=application/x-amz-json-1.1, got %q", got)
		}
		// Verify Authorization header is present and uses AWS4-HMAC-SHA256.
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256") {
			t.Errorf("expected AWS4-HMAC-SHA256 Authorization, got %q", auth)
		}
		// Verify X-Amz-Date is present.
		if r.Header.Get("X-Amz-Date") == "" {
			t.Error("expected X-Amz-Date header to be set")
		}
		// Parse request body.
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}
		if body["SecretId"] != "prod/db-password" {
			t.Errorf("expected SecretId=prod/db-password, got %q", body["SecretId"])
		}

		resp := map[string]interface{}{
			"SecretString": "super-secret-value",
			"Name":         "prod/db-password",
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	p := NewAWSProvider("us-east-1", "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	// Override endpoint for test.
	p.endpoint = server.URL
	val, err := p.Get("prod/db-password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != "super-secret-value" {
		t.Errorf("expected %q, got %q", "super-secret-value", val)
	}
}

func TestAWSProvider_Get_SecretNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		resp := map[string]interface{}{
			"__type":  "ResourceNotFoundException",
			"Message": "Secrets Manager can't find the specified secret.",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	p := NewAWSProvider("us-east-1", "AKID", "SECRET")
	p.endpoint = server.URL
	_, err := p.Get("nonexistent")
	if err == nil {
		t.Fatal("expected error for missing secret")
	}
}

func TestAWSProvider_Get_AuthFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		resp := map[string]interface{}{
			"__type":  "UnrecognizedClientException",
			"Message": "The security token included in the request is invalid.",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	p := NewAWSProvider("us-east-1", "BAD", "CREDS")
	p.endpoint = server.URL
	_, err := p.Get("my-secret")
	if err == nil {
		t.Fatal("expected error for auth failure")
	}
}

func TestAWSProvider_Get_ConnectionFailure(t *testing.T) {
	p := NewAWSProvider("us-east-1", "AKID", "SECRET")
	p.endpoint = "http://127.0.0.1:1"
	_, err := p.Get("anything")
	if err == nil {
		t.Fatal("expected error for connection failure")
	}
}

func TestAWSProvider_Get_MalformedJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		w.Write([]byte(`{not valid`))
	}))
	defer server.Close()

	p := NewAWSProvider("us-east-1", "AKID", "SECRET")
	p.endpoint = server.URL
	_, err := p.Get("bad-json")
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestAWSProvider_Get_MissingSecretString(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Valid response but without SecretString field.
		resp := map[string]interface{}{
			"Name": "binary-secret",
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	p := NewAWSProvider("us-east-1", "AKID", "SECRET")
	p.endpoint = server.URL
	_, err := p.Get("binary-secret")
	if err == nil {
		t.Fatal("expected error when SecretString is missing")
	}
}

func TestAWSProvider_SignatureComponents(t *testing.T) {
	// Verify the signing produces correct header structure.
	var capturedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		resp := map[string]interface{}{
			"SecretString": "val",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	p := NewAWSProvider("us-west-2", "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	p.endpoint = server.URL
	_, _ = p.Get("test")

	if !strings.Contains(capturedAuth, "AWS4-HMAC-SHA256") {
		t.Error("Authorization header missing AWS4-HMAC-SHA256")
	}
	if !strings.Contains(capturedAuth, "Credential=AKIAIOSFODNN7EXAMPLE") {
		t.Error("Authorization header missing Credential with access key")
	}
	if !strings.Contains(capturedAuth, "SignedHeaders=") {
		t.Error("Authorization header missing SignedHeaders")
	}
	if !strings.Contains(capturedAuth, "Signature=") {
		t.Error("Authorization header missing Signature")
	}
}
