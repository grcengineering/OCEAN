package evidence

import (
	"encoding/json"
	"testing"
)

func TestExtractObservables_NilData(t *testing.T) {
	result := ExtractObservables(nil)
	if result != nil {
		t.Fatalf("expected nil for nil input, got %v", result)
	}
}

func TestExtractObservables_InvalidJSON(t *testing.T) {
	result := ExtractObservables(json.RawMessage(`{not valid json`))
	if result != nil {
		t.Fatalf("expected nil for invalid JSON, got %v", result)
	}
}

func TestExtractObservables_UserFields(t *testing.T) {
	raw := json.RawMessage(`{"username":"alice"}`)
	result := ExtractObservables(raw)
	if len(result) != 1 {
		t.Fatalf("expected 1 observable, got %d: %v", len(result), result)
	}
	if result[0].Type != "user" {
		t.Errorf("expected type %q, got %q", "user", result[0].Type)
	}
	if result[0].Value != "alice" {
		t.Errorf("expected value %q, got %q", "alice", result[0].Value)
	}
}

func TestExtractObservables_IPFields(t *testing.T) {
	raw := json.RawMessage(`{"ip_address":"10.0.0.1"}`)
	result := ExtractObservables(raw)
	if len(result) != 1 {
		t.Fatalf("expected 1 observable, got %d: %v", len(result), result)
	}
	if result[0].Type != "ip" {
		t.Errorf("expected type %q, got %q", "ip", result[0].Type)
	}
	if result[0].Value != "10.0.0.1" {
		t.Errorf("expected value %q, got %q", "10.0.0.1", result[0].Value)
	}
}

func TestExtractObservables_ResourceFields(t *testing.T) {
	raw := json.RawMessage(`{"resource_arn":"arn:aws:iam::123"}`)
	result := ExtractObservables(raw)
	if len(result) != 1 {
		t.Fatalf("expected 1 observable, got %d: %v", len(result), result)
	}
	if result[0].Type != "resource" {
		t.Errorf("expected type %q, got %q", "resource", result[0].Type)
	}
	if result[0].Value != "arn:aws:iam::123" {
		t.Errorf("expected value %q, got %q", "arn:aws:iam::123", result[0].Value)
	}
}

func TestExtractObservables_DomainFields(t *testing.T) {
	raw := json.RawMessage(`{"hostname":"example.com"}`)
	result := ExtractObservables(raw)
	if len(result) != 1 {
		t.Fatalf("expected 1 observable, got %d: %v", len(result), result)
	}
	if result[0].Type != "domain" {
		t.Errorf("expected type %q, got %q", "domain", result[0].Type)
	}
	if result[0].Value != "example.com" {
		t.Errorf("expected value %q, got %q", "example.com", result[0].Value)
	}
}

func TestExtractObservables_NestedJSON(t *testing.T) {
	raw := json.RawMessage(`{"user":{"email":"bob@example.com"}}`)
	result := ExtractObservables(raw)
	if len(result) == 0 {
		t.Fatal("expected at least 1 observable from nested JSON, got 0")
	}
	found := false
	for _, obs := range result {
		if obs.Type == "user" && obs.Value == "bob@example.com" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected observable {type:user, value:bob@example.com} in %v", result)
	}
}

func TestExtractObservables_ArrayJSON(t *testing.T) {
	raw := json.RawMessage(`{"users":[{"username":"alice"},{"username":"bob"}]}`)
	result := ExtractObservables(raw)

	want := map[string]bool{"alice": false, "bob": false}
	for _, obs := range result {
		if obs.Type == "user" {
			want[obs.Value] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("expected user observable %q not found in %v", name, result)
		}
	}
}

func TestExtractObservables_Deduplication(t *testing.T) {
	raw := json.RawMessage(`{"username":"alice","user_email":"alice"}`)
	result := ExtractObservables(raw)

	count := 0
	for _, obs := range result {
		if obs.Type == "user" && obs.Value == "alice" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 deduplicated observable for alice, got %d in %v", count, result)
	}
}

func TestExtractObservables_EmptyStringsSkipped(t *testing.T) {
	raw := json.RawMessage(`{"username":"","email":"","ip_address":""}`)
	result := ExtractObservables(raw)
	if len(result) != 0 {
		t.Errorf("expected 0 observables for empty string values, got %d: %v", len(result), result)
	}
}
