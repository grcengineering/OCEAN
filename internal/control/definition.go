// Package control defines types for OCEAN's control definitions, evaluation
// logic, and framework mappings.
package control

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Control represents a single security or compliance control that OCEAN
// monitors. A control ties together evidence requirements, collector/tester
// modules, evaluation logic, and framework mappings into a single auditable
// unit.
type Control struct {
	ID                       string             `json:"id" yaml:"id"`
	Name                     string             `json:"name" yaml:"name"`
	Description              string             `json:"description" yaml:"description"`
	ThreatMitigated          string             `json:"threat_mitigated" yaml:"threat_mitigated"`
	FrameworkMappings        []FrameworkMapping  `json:"framework_mappings,omitempty" yaml:"framework_mappings,omitempty"`
	EvidenceRequirements     []string           `json:"evidence_requirements" yaml:"evidence_requirements"`
	Collectors               []ModuleRef        `json:"collectors" yaml:"collectors"`
	Testers                  []ModuleRef        `json:"testers,omitempty" yaml:"testers,omitempty"`
	EvaluationLogic          EvaluationLogic    `json:"evaluation_logic" yaml:"evaluation"`
	EvaluationExpressionHash string             `json:"evaluation_expression_hash,omitempty" yaml:"-"`
}

// FrameworkMapping links an OCEAN control to a specific control reference
// within an external compliance framework (e.g., SOC 2 CC6.1, ISO 27001 A.9.4).
type FrameworkMapping struct {
	FrameworkID string `json:"framework_id" yaml:"framework"`
	ControlRef  string `json:"control_ref" yaml:"control"`
}

// ModuleRef is a reference to an OCEAN module by its unique identifier.
type ModuleRef struct {
	ModuleID string `json:"module_id" yaml:"module_id"`
}

// EvaluationLogic defines how evidence is evaluated to determine whether a
// control is operating effectively. It supports either a CEL expression for
// custom logic or a named preset for common patterns.
type EvaluationLogic struct {
	CELExpression string `json:"cel_expression,omitempty" yaml:"cel,omitempty"`
	Preset        string `json:"preset,omitempty" yaml:"preset,omitempty"`
}

// LoadControl reads a single YAML control definition from the given path.
func LoadControl(path string) (*Control, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading control file %s: %w", path, err)
	}

	var ctrl Control
	if err := yaml.Unmarshal(data, &ctrl); err != nil {
		return nil, fmt.Errorf("parsing control YAML %s: %w", path, err)
	}

	if ctrl.ID == "" {
		return nil, fmt.Errorf("control definition in %s is missing required 'id' field", path)
	}

	return &ctrl, nil
}

// LoadAllControls scans a directory recursively for *.yaml control definitions
// and returns all successfully parsed controls. Invalid YAML files are skipped
// with a warning rather than failing the entire load.
func LoadAllControls(dir string) ([]*Control, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("accessing controls directory %s: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", dir)
	}

	var controls []*Control

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

		ctrl, err := LoadControl(path)
		if err != nil {
			// Skip invalid files rather than failing entirely.
			return nil
		}

		controls = append(controls, ctrl)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking controls directory %s: %w", dir, err)
	}

	return controls, nil
}
