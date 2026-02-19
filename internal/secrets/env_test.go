package secrets

import (
	"testing"
)

func TestEnvProvider_Get_Success(t *testing.T) {
	t.Setenv("TEST_SECRET", "my-secret-value")

	p := NewEnvProvider()
	val, err := p.Get("TEST_SECRET")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != "my-secret-value" {
		t.Errorf("expected %q, got %q", "my-secret-value", val)
	}
}

func TestEnvProvider_Get_Missing(t *testing.T) {
	p := NewEnvProvider()
	_, err := p.Get("OCEAN_TEST_DEFINITELY_NOT_SET_12345")
	if err == nil {
		t.Fatal("expected error for unset env var, got nil")
	}
}

func TestEnvProvider_Get_Empty(t *testing.T) {
	t.Setenv("EMPTY_SECRET", "")

	p := NewEnvProvider()
	_, err := p.Get("EMPTY_SECRET")
	if err == nil {
		t.Fatal("expected error for empty env var, got nil")
	}
}
