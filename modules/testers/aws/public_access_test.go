package aws

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/grcengineering/ocean/internal/evidence"
	"github.com/grcengineering/ocean/internal/module"
)

func TestPublicAccessTester_ID(t *testing.T) {
	tester := &PublicAccessTester{}
	if tester.ID() != "aws.s3_public_access" {
		t.Fatalf("expected ID %q, got %q", "aws.s3_public_access", tester.ID())
	}
}

func TestPublicAccessTester_SafetyClass(t *testing.T) {
	tester := &PublicAccessTester{}
	if tester.SafetyClass() != module.SafetyClassSafe {
		t.Fatalf("expected SafetyClassSafe (%q), got %q", module.SafetyClassSafe, tester.SafetyClass())
	}
}

func TestPublicAccessTester_Test_MissingBucket(t *testing.T) {
	config := map[string]string{}

	tester := &PublicAccessTester{}
	_, err := tester.Test(context.Background(), config)
	if err == nil {
		t.Fatal("expected error when AWS_TEST_BUCKET is missing, got nil")
	}
}

func TestPublicAccessTester_Test_AccessBlocked(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	config := map[string]string{
		"AWS_TEST_BUCKET": server.URL,
	}

	tester := &PublicAccessTester{}
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

func TestPublicAccessTester_Test_PublicAccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<ListBucketResult><Contents></Contents></ListBucketResult>"))
	}))
	defer server.Close()

	config := map[string]string{
		"AWS_TEST_BUCKET": server.URL,
	}

	tester := &PublicAccessTester{}
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
}

func TestPublicAccessTester_Test_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	config := map[string]string{
		"AWS_TEST_BUCKET": server.URL,
	}

	tester := &PublicAccessTester{}
	results, err := tester.Test(context.Background(), config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 evidence record, got %d", len(results))
	}

	ev := results[0]
	if ev.StatusID != evidence.StatusEffective {
		t.Fatalf("expected StatusEffective (%d) for 404 response, got %d", evidence.StatusEffective, ev.StatusID)
	}
}

func TestPublicAccessTester_Test_HasTranscript(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	config := map[string]string{
		"AWS_TEST_BUCKET": server.URL,
	}

	tester := &PublicAccessTester{}
	results, err := tester.Test(context.Background(), config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 evidence record, got %d", len(results))
	}

	ev := results[0]
	if ev.TestTranscript == nil {
		t.Fatal("expected TestTranscript to be non-nil")
	}

	if len(ev.TestTranscript.ActionsAttempted) == 0 {
		t.Fatal("expected at least one action in the transcript")
	}

	if len(ev.TestTranscript.Observations) == 0 {
		t.Fatal("expected at least one observation in the transcript")
	}
}
