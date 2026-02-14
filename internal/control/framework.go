package control

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Framework represents an external compliance or security framework
// (e.g., SOC 2, ISO 27001, NIST 800-53) and its mapping to OCEAN controls.
type Framework struct {
	ID       string             `json:"id" yaml:"id"`
	Name     string             `json:"name" yaml:"name"`
	Version  string             `json:"version" yaml:"version"`
	Controls []FrameworkControl `json:"controls" yaml:"controls"`
}

// FrameworkControl represents a single control reference within an external
// framework, along with the OCEAN control IDs that implement it.
type FrameworkControl struct {
	Ref             string   `json:"ref" yaml:"ref"`
	Title           string   `json:"title" yaml:"title"`
	Description     string   `json:"description,omitempty" yaml:"description,omitempty"`
	OceanControlIDs []string `json:"ocean_control_ids,omitempty" yaml:"ocean_control_ids,omitempty"`
}

// LoadFramework reads a single YAML framework definition from the given path.
func LoadFramework(path string) (*Framework, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading framework file %s: %w", path, err)
	}

	var fw Framework
	if err := yaml.Unmarshal(data, &fw); err != nil {
		return nil, fmt.Errorf("parsing framework YAML %s: %w", path, err)
	}

	if fw.ID == "" {
		return nil, fmt.Errorf("framework definition in %s is missing required 'id' field", path)
	}

	return &fw, nil
}

// LoadAllFrameworks scans a directory recursively for *.yaml framework
// definitions and returns all successfully parsed frameworks. Invalid YAML
// files are skipped with a warning rather than failing the entire load.
func LoadAllFrameworks(dir string) ([]*Framework, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("accessing frameworks directory %s: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", dir)
	}

	var frameworks []*Framework

	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories and non-YAML files.
		if info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		fw, err := LoadFramework(path)
		if err != nil {
			// Skip invalid files rather than failing entirely.
			return nil
		}

		frameworks = append(frameworks, fw)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking frameworks directory %s: %w", dir, err)
	}

	return frameworks, nil
}
