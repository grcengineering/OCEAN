package testutil

import (
	"testing"

	"github.com/google/uuid"
	"github.com/grcengineering/ocean/internal/evidence"
	"github.com/grcengineering/ocean/internal/module"
)

// AssertValidEvidence checks that an evidence record has all required fields
// populated correctly.
func AssertValidEvidence(t *testing.T, ev evidence.Evidence) {
	t.Helper()
	if ev.ID == uuid.Nil {
		t.Error("evidence ID is nil")
	}
	if ev.ControlID == "" {
		t.Error("evidence ControlID is empty")
	}
	if ev.Time.IsZero() {
		t.Error("evidence Time is zero")
	}
	if ev.Metadata.Module.Name == "" {
		t.Error("evidence Metadata.Module.Name is empty")
	}
	if ev.Metadata.Source.System == "" {
		t.Error("evidence Metadata.Source.System is empty")
	}
}

// AssertEvidenceCount checks the number of evidence records returned.
func AssertEvidenceCount(t *testing.T, evs []evidence.Evidence, expected int) {
	t.Helper()
	if len(evs) != expected {
		t.Errorf("got %d evidence records, want %d", len(evs), expected)
	}
}

// AssertModuleRegistered checks that a module with the given ID is in the registry.
func AssertModuleRegistered(t *testing.T, reg *module.Registry, moduleID string) {
	t.Helper()
	_, err := reg.GetModule(moduleID)
	if err != nil {
		t.Errorf("module %q not registered: %v", moduleID, err)
	}
}
