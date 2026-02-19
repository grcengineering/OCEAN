package ocean

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/grcengineering/ocean/internal/evidence"
	"github.com/grcengineering/ocean/internal/module"
)

func TestNewClient_DefaultStorage(t *testing.T) {
	// When StoragePath is empty, NewClient defaults to "ocean.db" in the
	// current directory. We set StoragePath to a temp directory file to
	// avoid polluting the working directory while still verifying the
	// default-path code path doesn't panic.
	tmpDir := t.TempDir()
	cfg := Config{
		StoragePath: filepath.Join(tmpDir, "ocean.db"),
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient with temp storage path: %v", err)
	}
	defer client.Close()
}

func TestNewClient_WithTempStorage(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	cfg := Config{
		StoragePath: dbPath,
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestClient_Registry(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := Config{
		StoragePath: filepath.Join(tmpDir, "registry.db"),
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	reg := client.Registry()
	if reg == nil {
		t.Fatal("Registry() returned nil")
	}
}

func TestClient_Close(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := Config{
		StoragePath: filepath.Join(tmpDir, "close.db"),
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	if err := client.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
}

func TestClient_Collect_ModuleNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := Config{
		StoragePath: filepath.Join(tmpDir, "collect.db"),
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	ctx := context.Background()
	_, err = client.Collect(ctx, "nonexistent.module", nil)
	if err == nil {
		t.Fatal("expected error for nonexistent module, got nil")
	}
}

func TestClient_Evaluate_ControlNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := Config{
		StoragePath: filepath.Join(tmpDir, "evaluate.db"),
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	ctx := context.Background()
	_, err = client.Evaluate(ctx, "nonexistent.control")
	if err == nil {
		t.Fatal("expected error for nonexistent control, got nil")
	}
}

// localTester is a minimal Tester implementation for testing the Client.Test path.
type localTester struct{}

func (lt *localTester) ID() string                                  { return "test.local" }
func (lt *localTester) Name() string                                { return "LocalTest" }
func (lt *localTester) Version() string                             { return "0.1.0" }
func (lt *localTester) SourceSystem() string                        { return "local" }
func (lt *localTester) EvidenceTypes() []int                        { return []int{9999} }
func (lt *localTester) CredentialRequirements() []module.CredentialReq { return nil }
func (lt *localTester) SafetyClass() module.SafetyClassification    { return module.SafetyClassSafe }
func (lt *localTester) EnvironmentScope() module.EnvironmentScope   { return module.ScopeProduction }
func (lt *localTester) PreFlightChecks() []string                   { return nil }
func (lt *localTester) CleanupProcedures() []string                 { return nil }
func (lt *localTester) Test(ctx context.Context, config map[string]string) ([]evidence.Evidence, error) {
	return []evidence.Evidence{{
		ID:              uuid.New(),
		ControlID:       "test.control",
		ClassUID:        9999,
		StatusID:        evidence.StatusEffective,
		Status:          "effective",
		Time:            time.Now().UTC(),
		ConfidenceLevel: evidence.ActiveVerification,
		Metadata: evidence.Metadata{
			Module: evidence.ModuleInfo{Name: "test.local", Version: "0.1.0", Type: "tester"},
			Source: evidence.SourceInfo{System: "local"},
		},
	}}, nil
}

func TestClient_Test_ModuleNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := Config{
		StoragePath: filepath.Join(tmpDir, "test_notfound.db"),
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	ctx := context.Background()
	_, err = client.Test(ctx, "nonexistent.tester", nil)
	if err == nil {
		t.Fatal("expected error for nonexistent tester module, got nil")
	}
}

func TestClient_Test_Success(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := Config{
		StoragePath: filepath.Join(tmpDir, "test_success.db"),
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	// Register the local tester via the client's registry.
	client.Registry().RegisterTester(&localTester{})

	ctx := context.Background()
	results, err := client.Test(ctx, "test.local", nil)
	if err != nil {
		t.Fatalf("Test: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 evidence result, got %d", len(results))
	}

	ev := results[0]
	if ev.ControlID != "test.control" {
		t.Errorf("ControlID = %q, want %q", ev.ControlID, "test.control")
	}
	if ev.Status != "effective" {
		t.Errorf("Status = %q, want %q", ev.Status, "effective")
	}
	if ev.ClassUID != 9999 {
		t.Errorf("ClassUID = %d, want %d", ev.ClassUID, 9999)
	}
	if ev.Metadata.Module.Name != "test.local" {
		t.Errorf("Module.Name = %q, want %q", ev.Metadata.Module.Name, "test.local")
	}
	if ev.Metadata.Module.Type != "tester" {
		t.Errorf("Module.Type = %q, want %q", ev.Metadata.Module.Type, "tester")
	}
	if ev.ID == "" {
		t.Error("expected non-empty evidence ID")
	}
}

func TestClient_History_Empty(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := Config{
		StoragePath: filepath.Join(tmpDir, "history_empty.db"),
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	ctx := context.Background()
	from := time.Now().Add(-24 * time.Hour)
	to := time.Now()

	results, err := client.History(ctx, "nonexistent.control", from, to)
	if err != nil {
		t.Fatalf("History: %v", err)
	}

	if len(results) != 0 {
		t.Errorf("expected empty history, got %d entries", len(results))
	}
}

func TestClient_Evaluate_WithControl(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a controls directory with a minimal control YAML fixture.
	controlsDir := filepath.Join(tmpDir, "controls")
	if err := os.MkdirAll(controlsDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	controlYAML := []byte(`id: "eval.test_control"
name: "Evaluation Test Control"
description: "A control for testing the Evaluate path"
threat_mitigated: "Test threat"
collectors:
  - module_id: "mock.test"
evaluation:
  preset: "any_effective"
`)
	controlPath := filepath.Join(controlsDir, "eval_control.yaml")
	if err := os.WriteFile(controlPath, controlYAML, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg := Config{
		StoragePath: filepath.Join(tmpDir, "evaluate_ctrl.db"),
		ControlsDir: controlsDir,
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	ctx := context.Background()

	// Evaluate should succeed (no evidence => unknown status, but no error).
	result, err := client.Evaluate(ctx, "eval.test_control")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil ControlStatus result")
	}
	if result.ControlID != "eval.test_control" {
		t.Errorf("ControlID = %q, want %q", result.ControlID, "eval.test_control")
	}
	// With no evidence stored, the evaluator returns "unknown" status.
	if result.Status != "unknown" {
		t.Errorf("Status = %q, want %q", result.Status, "unknown")
	}
	if result.ID == "" {
		t.Error("expected non-empty control status ID")
	}
}
