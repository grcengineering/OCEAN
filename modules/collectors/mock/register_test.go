package mock

import (
	"testing"

	"github.com/grcengineering/ocean/internal/module"
)

func TestRegisterAll_RegistersMockCollector(t *testing.T) {
	reg := module.NewRegistry()
	RegisterAll(reg)

	c, err := reg.GetCollector("mock.test")
	if err != nil {
		t.Fatalf("GetCollector(\"mock.test\") returned error: %v", err)
	}
	if c == nil {
		t.Fatal("GetCollector(\"mock.test\") returned nil")
	}
	if c.ID() != "mock.test" {
		t.Errorf("registered collector ID = %q, want %q", c.ID(), "mock.test")
	}
}

func TestRegisterAll_CollectorAppearsInList(t *testing.T) {
	reg := module.NewRegistry()
	RegisterAll(reg)

	collectors := reg.ListCollectors()
	if len(collectors) == 0 {
		t.Fatal("ListCollectors() returned empty after RegisterAll")
	}

	found := false
	for _, c := range collectors {
		if c.ID() == "mock.test" {
			found = true
			break
		}
	}
	if !found {
		t.Error("mock.test collector not found in ListCollectors()")
	}
}
