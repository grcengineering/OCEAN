package module

import (
	"context"
	"fmt"
	"testing"

	"github.com/grcengineering/ocean/internal/evidence"
)

// fakeCollector is a minimal Collector for testing the executor.
type fakeCollector struct {
	id      string
	results []evidence.Evidence
	err     error
}

func (f *fakeCollector) ID() string                             { return f.id }
func (f *fakeCollector) Name() string                           { return "Fake" }
func (f *fakeCollector) Version() string                        { return "0.0.1" }
func (f *fakeCollector) SourceSystem() string                   { return "fake" }
func (f *fakeCollector) EvidenceTypes() []int                   { return []int{9999} }
func (f *fakeCollector) CredentialRequirements() []CredentialReq { return nil }

func (f *fakeCollector) Collect(_ context.Context, _ map[string]string) ([]evidence.Evidence, error) {
	return f.results, f.err
}

func TestExecuteCollector_Success(t *testing.T) {
	reg := NewRegistry()
	fc := &fakeCollector{id: "fake.test", results: []evidence.Evidence{{}}}
	reg.RegisterCollector(fc)

	executor := NewExecutor(reg)
	results, err := executor.ExecuteCollector(context.Background(), "fake.test", nil)
	if err != nil {
		t.Fatalf("ExecuteCollector returned error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("ExecuteCollector returned %d results, want 1", len(results))
	}
}

func TestExecuteCollector_NotFound(t *testing.T) {
	reg := NewRegistry()
	executor := NewExecutor(reg)

	_, err := executor.ExecuteCollector(context.Background(), "nonexistent", nil)
	if err == nil {
		t.Fatal("expected error for nonexistent module, got nil")
	}
}

func TestExecuteCollector_CollectorError(t *testing.T) {
	reg := NewRegistry()
	fc := &fakeCollector{id: "failing.test", err: fmt.Errorf("api error")}
	reg.RegisterCollector(fc)

	executor := NewExecutor(reg)
	_, err := executor.ExecuteCollector(context.Background(), "failing.test", nil)
	if err == nil {
		t.Fatal("expected error from failing collector, got nil")
	}
}

func TestExecuteCollector_PassesConfig(t *testing.T) {
	reg := NewRegistry()
	var receivedConfig map[string]string
	fc := &fakeCollector{id: "config.test"}
	// Override Collect to capture config
	origCollect := fc.Collect
	_ = origCollect // suppress unused warning

	// We'll use a configCapture collector instead
	cc := &configCaptureCollector{id: "config.test", capturedConfig: &receivedConfig}
	reg.RegisterCollector(cc)

	executor := NewExecutor(reg)
	config := map[string]string{"api_key": "test123"}
	_, err := executor.ExecuteCollector(context.Background(), "config.test", config)
	if err != nil {
		t.Fatalf("ExecuteCollector returned error: %v", err)
	}
	if receivedConfig == nil {
		t.Fatal("config was not passed to collector")
	}
	if receivedConfig["api_key"] != "test123" {
		t.Errorf("config[\"api_key\"] = %q, want %q", receivedConfig["api_key"], "test123")
	}
}

// configCaptureCollector captures the config passed to Collect.
type configCaptureCollector struct {
	id             string
	capturedConfig *map[string]string
}

func (c *configCaptureCollector) ID() string                             { return c.id }
func (c *configCaptureCollector) Name() string                           { return "ConfigCapture" }
func (c *configCaptureCollector) Version() string                        { return "0.0.1" }
func (c *configCaptureCollector) SourceSystem() string                   { return "fake" }
func (c *configCaptureCollector) EvidenceTypes() []int                   { return []int{9999} }
func (c *configCaptureCollector) CredentialRequirements() []CredentialReq { return nil }

func (c *configCaptureCollector) Collect(_ context.Context, config map[string]string) ([]evidence.Evidence, error) {
	*c.capturedConfig = config
	return nil, nil
}
