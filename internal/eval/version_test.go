package eval

import (
	"strings"
	"testing"
)

func TestContentAddress_ReturnsShaPrefixed(t *testing.T) {
	result := ContentAddress("status_counts.ineffective == 0")
	if !strings.HasPrefix(result, "sha256:") {
		t.Errorf("ContentAddress() = %q, want sha256: prefix", result)
	}
}

func TestContentAddress_Deterministic(t *testing.T) {
	expr := "status_counts.ineffective == 0 && status_counts.effective > 0"
	a := ContentAddress(expr)
	b := ContentAddress(expr)
	if a != b {
		t.Errorf("ContentAddress() not deterministic: %q != %q", a, b)
	}
}

func TestContentAddress_DifferentExpressionsGiveDifferentDigests(t *testing.T) {
	a := ContentAddress("status_counts.effective > 0")
	b := ContentAddress("status_counts.effective > 1")
	if a == b {
		t.Error("ContentAddress() should give different digests for different expressions")
	}
}

func TestContentAddress_EmptyString(t *testing.T) {
	result := ContentAddress("")
	if !strings.HasPrefix(result, "sha256:") {
		t.Errorf("ContentAddress('') = %q, want sha256: prefix", result)
	}
	// SHA-256 of empty string is well-known.
	want := "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if result != want {
		t.Errorf("ContentAddress('') = %q, want %q", result, want)
	}
}
