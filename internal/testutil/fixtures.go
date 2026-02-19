package testutil

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// LoadFixture reads a fixture file from tests/fixtures/ relative to the
// project root. It fails the test if the file cannot be read.
func LoadFixture(t *testing.T, name string) []byte {
	t.Helper()
	root := projectRoot()
	path := filepath.Join(root, "tests", "fixtures", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("loading fixture %q: %v", name, err)
	}
	return data
}

// projectRoot walks up from this source file to find the project root
// (the directory containing go.mod).
func projectRoot() string {
	_, thisFile, _, _ := runtime.Caller(0)
	dir := filepath.Dir(thisFile)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached filesystem root without finding go.mod.
			return "."
		}
		dir = parent
	}
}
