// Package config defines OCEAN's configuration structures and defaults.
package config

import "github.com/rs/zerolog"

// Config holds all OCEAN configuration.
type Config struct {
	StoragePath  string       `yaml:"storage_path"`
	LogLevel     string       `yaml:"log_level"`
	KeyPath      string       `yaml:"key_path"`
	ControlsDir  string       `yaml:"controls_dir"`
	OutputFormat string       `yaml:"output_format"`
	Server       ServerConfig `yaml:"server"`
}

// ServerConfig holds configuration for OCEAN's HTTP server.
type ServerConfig struct {
	Port      int    `yaml:"port"`
	AuthToken string `yaml:"auth_token"`
}

// DefaultConfig returns a Config populated with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		StoragePath:  "~/.ocean/ocean.db",
		LogLevel:     "info",
		KeyPath:      "~/.ocean/keys",
		ControlsDir:  "controls",
		OutputFormat: "json",
		Server: ServerConfig{
			Port: 8080,
		},
	}
}

// SetupLogging configures the global zerolog level based on the config's
// LogLevel field. If the level string is unrecognized, it defaults to info.
func SetupLogging(cfg *Config) {
	level, err := zerolog.ParseLevel(cfg.LogLevel)
	if err != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)
}
