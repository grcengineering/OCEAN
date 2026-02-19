package config

import (
	"testing"

	"github.com/rs/zerolog"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.StoragePath != "~/.ocean/ocean.db" {
		t.Errorf("StoragePath = %q, want %q", cfg.StoragePath, "~/.ocean/ocean.db")
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, "info")
	}
	if cfg.KeyPath != "~/.ocean/keys" {
		t.Errorf("KeyPath = %q, want %q", cfg.KeyPath, "~/.ocean/keys")
	}
	if cfg.ControlsDir != "controls" {
		t.Errorf("ControlsDir = %q, want %q", cfg.ControlsDir, "controls")
	}
	if cfg.OutputFormat != "json" {
		t.Errorf("OutputFormat = %q, want %q", cfg.OutputFormat, "json")
	}
	if cfg.Server.Port != 8080 {
		t.Errorf("Server.Port = %d, want %d", cfg.Server.Port, 8080)
	}
}

func TestDefaultConfig_StoragePath(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.StoragePath != "~/.ocean/ocean.db" {
		t.Fatalf("StoragePath = %q, want %q", cfg.StoragePath, "~/.ocean/ocean.db")
	}
}

func TestDefaultConfig_ServerPort(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Server.Port != 8080 {
		t.Fatalf("Server.Port = %d, want %d", cfg.Server.Port, 8080)
	}
}

func TestSetupLogging_ValidLevel(t *testing.T) {
	cfg := &Config{LogLevel: "debug"}
	SetupLogging(cfg)

	if zerolog.GlobalLevel() != zerolog.DebugLevel {
		t.Errorf("global level = %v, want %v", zerolog.GlobalLevel(), zerolog.DebugLevel)
	}

	// Restore to info so other tests are not affected.
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
}

func TestSetupLogging_InvalidLevel(t *testing.T) {
	cfg := &Config{LogLevel: "bogus"}
	SetupLogging(cfg)

	if zerolog.GlobalLevel() != zerolog.InfoLevel {
		t.Errorf("global level = %v, want %v (info fallback)", zerolog.GlobalLevel(), zerolog.InfoLevel)
	}
}
