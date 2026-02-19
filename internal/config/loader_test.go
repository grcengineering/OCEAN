package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_NoFile_ReturnsDefaults(t *testing.T) {
	nonExistent := filepath.Join(t.TempDir(), "does-not-exist.yaml")

	cfg, err := Load(nonExistent)
	if err != nil {
		t.Fatalf("Load returned unexpected error: %v", err)
	}

	want := DefaultConfig()
	if cfg.StoragePath != want.StoragePath {
		t.Errorf("StoragePath = %q, want %q", cfg.StoragePath, want.StoragePath)
	}
	if cfg.LogLevel != want.LogLevel {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, want.LogLevel)
	}
	if cfg.KeyPath != want.KeyPath {
		t.Errorf("KeyPath = %q, want %q", cfg.KeyPath, want.KeyPath)
	}
	if cfg.ControlsDir != want.ControlsDir {
		t.Errorf("ControlsDir = %q, want %q", cfg.ControlsDir, want.ControlsDir)
	}
	if cfg.OutputFormat != want.OutputFormat {
		t.Errorf("OutputFormat = %q, want %q", cfg.OutputFormat, want.OutputFormat)
	}
	if cfg.Server.Port != want.Server.Port {
		t.Errorf("Server.Port = %d, want %d", cfg.Server.Port, want.Server.Port)
	}
}

func TestLoad_ValidYAML(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	yamlContent := []byte(`storage_path: /tmp/custom.db
log_level: debug
key_path: /tmp/keys
controls_dir: my-controls
output_format: table
server:
  port: 9090
  auth_token: secret
`)
	if err := os.WriteFile(cfgPath, yamlContent, 0644); err != nil {
		t.Fatalf("writing temp config: %v", err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load returned unexpected error: %v", err)
	}

	if cfg.StoragePath != "/tmp/custom.db" {
		t.Errorf("StoragePath = %q, want %q", cfg.StoragePath, "/tmp/custom.db")
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, "debug")
	}
	if cfg.KeyPath != "/tmp/keys" {
		t.Errorf("KeyPath = %q, want %q", cfg.KeyPath, "/tmp/keys")
	}
	if cfg.ControlsDir != "my-controls" {
		t.Errorf("ControlsDir = %q, want %q", cfg.ControlsDir, "my-controls")
	}
	if cfg.OutputFormat != "table" {
		t.Errorf("OutputFormat = %q, want %q", cfg.OutputFormat, "table")
	}
	if cfg.Server.Port != 9090 {
		t.Errorf("Server.Port = %d, want %d", cfg.Server.Port, 9090)
	}
	if cfg.Server.AuthToken != "secret" {
		t.Errorf("Server.AuthToken = %q, want %q", cfg.Server.AuthToken, "secret")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bad.yaml")

	badContent := []byte("storage_path: [invalid\n  broken: yaml: content")
	if err := os.WriteFile(cfgPath, badContent, 0644); err != nil {
		t.Fatalf("writing temp config: %v", err)
	}

	_, err := Load(cfgPath)
	if err == nil {
		t.Fatal("Load should return an error for invalid YAML, got nil")
	}
}

func TestLoad_EnvOverrides(t *testing.T) {
	// Create a valid YAML file so we can verify the env var takes precedence.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	yamlContent := []byte("storage_path: /from/file\n")
	if err := os.WriteFile(cfgPath, yamlContent, 0644); err != nil {
		t.Fatalf("writing temp config: %v", err)
	}

	t.Setenv("OCEAN_STORAGE_PATH", "/from/env")

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load returned unexpected error: %v", err)
	}

	if cfg.StoragePath != "/from/env" {
		t.Errorf("StoragePath = %q, want %q (env override)", cfg.StoragePath, "/from/env")
	}
}
