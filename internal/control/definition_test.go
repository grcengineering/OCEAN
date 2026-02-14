package control

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadControl_Valid(t *testing.T) {
	// Write a valid YAML control definition to a temp file.
	dir := t.TempDir()
	yamlContent := `id: mock.mfa_enforcement
name: MFA Enforcement
description: Verify MFA is enforced for all users
threat_mitigated: Unauthorized access via credential theft
framework_mappings:
  - framework: SOC2
    control: CC6.1
collectors:
  - module_id: mock.test
testers:
  - module_id: mock.safety_test
evaluation:
  preset: all_effective
`
	path := filepath.Join(dir, "mfa_enforcement.yaml")
	if err := os.WriteFile(path, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("writing test YAML: %v", err)
	}

	ctrl, err := LoadControl(path)
	if err != nil {
		t.Fatalf("LoadControl returned error: %v", err)
	}

	if ctrl.ID != "mock.mfa_enforcement" {
		t.Errorf("ID = %q, want %q", ctrl.ID, "mock.mfa_enforcement")
	}
	if ctrl.Name != "MFA Enforcement" {
		t.Errorf("Name = %q, want %q", ctrl.Name, "MFA Enforcement")
	}
	if ctrl.Description != "Verify MFA is enforced for all users" {
		t.Errorf("Description = %q, want %q", ctrl.Description, "Verify MFA is enforced for all users")
	}
	if ctrl.ThreatMitigated != "Unauthorized access via credential theft" {
		t.Errorf("ThreatMitigated = %q, want %q", ctrl.ThreatMitigated, "Unauthorized access via credential theft")
	}

	// Framework mappings.
	if len(ctrl.FrameworkMappings) != 1 {
		t.Fatalf("FrameworkMappings len = %d, want 1", len(ctrl.FrameworkMappings))
	}
	if ctrl.FrameworkMappings[0].FrameworkID != "SOC2" {
		t.Errorf("FrameworkMappings[0].FrameworkID = %q, want %q", ctrl.FrameworkMappings[0].FrameworkID, "SOC2")
	}
	if ctrl.FrameworkMappings[0].ControlRef != "CC6.1" {
		t.Errorf("FrameworkMappings[0].ControlRef = %q, want %q", ctrl.FrameworkMappings[0].ControlRef, "CC6.1")
	}

	// Collectors.
	if len(ctrl.Collectors) != 1 {
		t.Fatalf("Collectors len = %d, want 1", len(ctrl.Collectors))
	}
	if ctrl.Collectors[0].ModuleID != "mock.test" {
		t.Errorf("Collectors[0].ModuleID = %q, want %q", ctrl.Collectors[0].ModuleID, "mock.test")
	}

	// Testers.
	if len(ctrl.Testers) != 1 {
		t.Fatalf("Testers len = %d, want 1", len(ctrl.Testers))
	}
	if ctrl.Testers[0].ModuleID != "mock.safety_test" {
		t.Errorf("Testers[0].ModuleID = %q, want %q", ctrl.Testers[0].ModuleID, "mock.safety_test")
	}

	// Evaluation logic.
	if ctrl.EvaluationLogic.Preset != "all_effective" {
		t.Errorf("EvaluationLogic.Preset = %q, want %q", ctrl.EvaluationLogic.Preset, "all_effective")
	}
}

func TestLoadControl_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("not: [valid: yaml: {{"), 0644); err != nil {
		t.Fatalf("writing test YAML: %v", err)
	}

	_, err := LoadControl(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML, got nil")
	}
}

func TestLoadControl_FileNotFound(t *testing.T) {
	_, err := LoadControl("/nonexistent/path/to/control.yaml")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestLoadControl_MissingID(t *testing.T) {
	dir := t.TempDir()
	yamlContent := `name: Missing ID Control
description: This control has no ID
collectors:
  - module_id: mock.test
evaluation:
  preset: all_effective
`
	path := filepath.Join(dir, "missing_id.yaml")
	if err := os.WriteFile(path, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("writing test YAML: %v", err)
	}

	_, err := LoadControl(path)
	if err == nil {
		t.Fatal("expected error for missing control ID, got nil")
	}
}

func TestLoadAllControls(t *testing.T) {
	dir := t.TempDir()

	// Create a subdirectory with a control.
	subDir := filepath.Join(dir, "mock")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatalf("creating subdir: %v", err)
	}

	ctrl1 := `id: mock.ctrl_one
name: Control One
description: First control
collectors:
  - module_id: mock.test
evaluation:
  preset: all_effective
`
	ctrl2 := `id: mock.ctrl_two
name: Control Two
description: Second control
collectors:
  - module_id: mock.test
evaluation:
  preset: all_effective
`

	if err := os.WriteFile(filepath.Join(dir, "ctrl_one.yaml"), []byte(ctrl1), 0644); err != nil {
		t.Fatalf("writing control 1: %v", err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "ctrl_two.yaml"), []byte(ctrl2), 0644); err != nil {
		t.Fatalf("writing control 2: %v", err)
	}

	// Write a non-YAML file that should be ignored.
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("not yaml"), 0644); err != nil {
		t.Fatalf("writing txt file: %v", err)
	}

	controls, err := LoadAllControls(dir)
	if err != nil {
		t.Fatalf("LoadAllControls returned error: %v", err)
	}

	if len(controls) != 2 {
		t.Fatalf("got %d controls, want 2", len(controls))
	}

	// Verify both controls were loaded (order not guaranteed).
	ids := map[string]bool{}
	for _, c := range controls {
		ids[c.ID] = true
	}
	if !ids["mock.ctrl_one"] {
		t.Error("missing control mock.ctrl_one")
	}
	if !ids["mock.ctrl_two"] {
		t.Error("missing control mock.ctrl_two")
	}
}

func TestLoadAllControls_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	controls, err := LoadAllControls(dir)
	if err != nil {
		t.Fatalf("LoadAllControls returned error: %v", err)
	}
	if len(controls) != 0 {
		t.Fatalf("got %d controls, want 0", len(controls))
	}
}

func TestLoadAllControls_InvalidDirPath(t *testing.T) {
	_, err := LoadAllControls("/nonexistent/dir/path")
	if err == nil {
		t.Fatal("expected error for nonexistent directory, got nil")
	}
}

func TestLoadAllControls_SkipsInvalidYAML(t *testing.T) {
	dir := t.TempDir()

	validCtrl := `id: mock.valid
name: Valid Control
description: This is valid
collectors:
  - module_id: mock.test
evaluation:
  preset: all_effective
`
	invalidCtrl := `not: [valid: yaml: {{`

	if err := os.WriteFile(filepath.Join(dir, "valid.yaml"), []byte(validCtrl), 0644); err != nil {
		t.Fatalf("writing valid yaml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "invalid.yaml"), []byte(invalidCtrl), 0644); err != nil {
		t.Fatalf("writing invalid yaml: %v", err)
	}

	// LoadAllControls should skip invalid files and return what it can.
	controls, err := LoadAllControls(dir)
	if err != nil {
		t.Fatalf("LoadAllControls returned error: %v", err)
	}
	if len(controls) != 1 {
		t.Fatalf("got %d controls, want 1 (should skip invalid)", len(controls))
	}
	if controls[0].ID != "mock.valid" {
		t.Errorf("ID = %q, want %q", controls[0].ID, "mock.valid")
	}
}
