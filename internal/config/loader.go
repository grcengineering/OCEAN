package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Load reads configuration from the given path, falling back to
// $HOME/.ocean/config.yaml if path is empty. Environment variables
// override file values.
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	if path == "" {
		home, _ := os.UserHomeDir()
		path = filepath.Join(home, ".ocean", "config.yaml")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil // Use defaults if no config file
		}
		return nil, err
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	// Override from environment variables
	if v := os.Getenv("OCEAN_STORAGE_PATH"); v != "" {
		cfg.StoragePath = v
	}
	if v := os.Getenv("OCEAN_LOG_LEVEL"); v != "" {
		cfg.LogLevel = v
	}
	if v := os.Getenv("OCEAN_KEY_PATH"); v != "" {
		cfg.KeyPath = v
	}

	return cfg, nil
}
