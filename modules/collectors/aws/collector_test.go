package aws

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

func TestNewAWSClient_MissingAccessKey(t *testing.T) {
	config := map[string]string{
		"AWS_ACCESS_KEY_ID":     "",
		"AWS_SECRET_ACCESS_KEY": "secret",
	}

	_, err := newAWSClient(config)
	if err == nil {
		t.Fatal("expected error when AWS_ACCESS_KEY_ID is empty, got nil")
	}
}

func TestNewAWSClient_MissingSecretKey(t *testing.T) {
	config := map[string]string{
		"AWS_ACCESS_KEY_ID":     "AKIAIOSFODNN7EXAMPLE",
		"AWS_SECRET_ACCESS_KEY": "",
	}

	_, err := newAWSClient(config)
	if err == nil {
		t.Fatal("expected error when AWS_SECRET_ACCESS_KEY is empty, got nil")
	}
}

func TestNewAWSClient_DefaultRegion(t *testing.T) {
	config := map[string]string{
		"AWS_ACCESS_KEY_ID":     "AKIAIOSFODNN7EXAMPLE",
		"AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	client, err := newAWSClient(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if client.region != "us-east-1" {
		t.Fatalf("expected default region %q, got %q", "us-east-1", client.region)
	}
}

func TestNewAWSClient_CustomRegion(t *testing.T) {
	config := map[string]string{
		"AWS_ACCESS_KEY_ID":     "AKIAIOSFODNN7EXAMPLE",
		"AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"AWS_REGION":            "eu-west-1",
	}

	client, err := newAWSClient(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if client.region != "eu-west-1" {
		t.Fatalf("expected region %q, got %q", "eu-west-1", client.region)
	}
}

func TestSha256Hex(t *testing.T) {
	input := "hello"
	h := sha256.Sum256([]byte(input))
	want := hex.EncodeToString(h[:])

	got := sha256Hex(input)
	if got != want {
		t.Fatalf("sha256Hex(%q) = %q, want %q", input, got, want)
	}

	// Also verify against the known SHA-256 of "hello".
	knownHash := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if got != knownHash {
		t.Fatalf("sha256Hex(%q) = %q, want known hash %q", input, got, knownHash)
	}
}

func TestIsThrottleError(t *testing.T) {
	te := &throttleError{msg: "throttled: HTTP 429"}
	if !isThrottleError(te) {
		t.Fatal("expected isThrottleError to return true for *throttleError")
	}

	otherErr := errors.New("some other error")
	if isThrottleError(otherErr) {
		t.Fatal("expected isThrottleError to return false for non-throttle error")
	}

	if isThrottleError(nil) {
		t.Fatal("expected isThrottleError to return false for nil")
	}
}

func TestIAMCollector_ID(t *testing.T) {
	c := &IAMCollector{}
	if c.ID() != "aws.iam" {
		t.Fatalf("expected ID %q, got %q", "aws.iam", c.ID())
	}
}

func TestIAMCollector_CredentialRequirements(t *testing.T) {
	c := &IAMCollector{}
	reqs := c.CredentialRequirements()

	if len(reqs) != 4 {
		t.Fatalf("expected 4 credential requirements, got %d", len(reqs))
	}

	expectedNames := map[string]bool{
		"AWS_ACCESS_KEY_ID":     false,
		"AWS_SECRET_ACCESS_KEY": false,
		"AWS_SESSION_TOKEN":     false,
		"AWS_REGION":            false,
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
