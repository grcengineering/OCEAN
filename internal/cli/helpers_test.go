package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- expandPath tests ---

func TestExpandPath_TildePrefix(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("cannot determine home directory: %v", err)
	}

	got := expandPath("~/documents/ocean.db")
	want := filepath.Join(home, "documents/ocean.db")
	if got != want {
		t.Errorf("expandPath(\"~/documents/ocean.db\") = %q, want %q", got, want)
	}
}

func TestExpandPath_TildeOnly(t *testing.T) {
	// "~/" alone should return just the home dir
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("cannot determine home directory: %v", err)
	}

	got := expandPath("~/")
	want := home
	if got != want {
		t.Errorf("expandPath(\"~/\") = %q, want %q", got, want)
	}
}

func TestExpandPath_NoTilde(t *testing.T) {
	got := expandPath("/var/data/ocean.db")
	if got != "/var/data/ocean.db" {
		t.Errorf("expandPath(\"/var/data/ocean.db\") = %q, want %q", got, "/var/data/ocean.db")
	}
}

func TestExpandPath_RelativePath(t *testing.T) {
	got := expandPath("relative/path")
	if got != "relative/path" {
		t.Errorf("expandPath(\"relative/path\") = %q, want %q", got, "relative/path")
	}
}

func TestExpandPath_EmptyString(t *testing.T) {
	got := expandPath("")
	if got != "" {
		t.Errorf("expandPath(\"\") = %q, want %q", got, "")
	}
}

func TestExpandPath_TildeWithoutSlash(t *testing.T) {
	// "~user" should NOT be expanded (only "~/" prefix triggers expansion)
	got := expandPath("~user/path")
	if strings.HasPrefix(got, "/") {
		t.Errorf("expandPath(\"~user/path\") should not expand, got %q", got)
	}
}

// --- buildDefaultRegistry tests ---

func TestBuildDefaultRegistry_ReturnsNonNil(t *testing.T) {
	reg := buildDefaultRegistry()
	if reg == nil {
		t.Fatal("buildDefaultRegistry() returned nil")
	}
}

func TestBuildDefaultRegistry_HasModules(t *testing.T) {
	reg := buildDefaultRegistry()
	modules := reg.ListModules()
	if len(modules) == 0 {
		t.Fatal("buildDefaultRegistry() returned registry with 0 modules")
	}
}

func TestBuildDefaultRegistry_ContainsExpectedModules(t *testing.T) {
	reg := buildDefaultRegistry()
	modules := reg.ListModules()

	// Build a set of module IDs for lookup.
	ids := make(map[string]bool)
	for _, m := range modules {
		ids[m.ID] = true
	}

	// Verify a selection of expected module IDs exist.
	expectedIDs := []string{
		"mock.test",
		"mock.network",
		"mock.safety_test",
		"okta.mfa_policy",
		"aws.iam",
		"github.branch_protection",
	}
	for _, id := range expectedIDs {
		if !ids[id] {
			t.Errorf("expected module %q not found in registry", id)
		}
	}
}

func TestBuildDefaultRegistry_HasCollectorsAndTesters(t *testing.T) {
	reg := buildDefaultRegistry()

	collectors := reg.ListByType("collector")
	testers := reg.ListByType("tester")

	if len(collectors) == 0 {
		t.Error("registry has no collectors")
	}
	if len(testers) == 0 {
		t.Error("registry has no testers")
	}
}
