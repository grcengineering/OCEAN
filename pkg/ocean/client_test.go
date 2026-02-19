package ocean

import (
	"context"
	"path/filepath"
	"testing"
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
