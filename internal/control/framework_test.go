package control

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFramework_Valid(t *testing.T) {
	dir := t.TempDir()
	yamlContent := `id: soc2
name: SOC 2 Type II
version: "2017"
controls:
  - ref: CC6.1
    title: Logical and Physical Access Controls
    description: "The entity implements logical access security software."
    ocean_control_ids:
      - iam.mfa_enforcement
      - iam.password_policy
  - ref: CC6.6
    title: System Boundary Protection
    ocean_control_ids:
      - network.waf_protection
`
	path := filepath.Join(dir, "soc2.yaml")
	if err := os.WriteFile(path, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("writing test YAML: %v", err)
	}

	fw, err := LoadFramework(path)
	if err != nil {
		t.Fatalf("LoadFramework returned error: %v", err)
	}

	if fw.ID != "soc2" {
		t.Errorf("ID = %q, want %q", fw.ID, "soc2")
	}
	if fw.Name != "SOC 2 Type II" {
		t.Errorf("Name = %q, want %q", fw.Name, "SOC 2 Type II")
	}
	if fw.Version != "2017" {
		t.Errorf("Version = %q, want %q", fw.Version, "2017")
	}
	if len(fw.Controls) != 2 {
		t.Fatalf("Controls len = %d, want 2", len(fw.Controls))
	}
	if fw.Controls[0].Ref != "CC6.1" {
		t.Errorf("Controls[0].Ref = %q, want %q", fw.Controls[0].Ref, "CC6.1")
	}
	if fw.Controls[0].Title != "Logical and Physical Access Controls" {
		t.Errorf("Controls[0].Title = %q, want %q", fw.Controls[0].Title, "Logical and Physical Access Controls")
	}
	if len(fw.Controls[0].OceanControlIDs) != 2 {
		t.Fatalf("Controls[0].OceanControlIDs len = %d, want 2", len(fw.Controls[0].OceanControlIDs))
	}
	if fw.Controls[0].OceanControlIDs[0] != "iam.mfa_enforcement" {
		t.Errorf("Controls[0].OceanControlIDs[0] = %q, want %q", fw.Controls[0].OceanControlIDs[0], "iam.mfa_enforcement")
	}
}

func TestLoadFramework_MissingID(t *testing.T) {
	dir := t.TempDir()
	yamlContent := `name: No ID Framework
version: "1.0"
controls:
  - ref: C1
    title: Control 1
`
	path := filepath.Join(dir, "noid.yaml")
	if err := os.WriteFile(path, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("writing test YAML: %v", err)
	}

	_, err := LoadFramework(path)
	if err == nil {
		t.Fatal("expected error for missing framework ID, got nil")
	}
}

func TestLoadFramework_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("not: [valid: yaml: {{"), 0644); err != nil {
		t.Fatalf("writing test YAML: %v", err)
	}

	_, err := LoadFramework(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML, got nil")
	}
}

func TestLoadFramework_FileNotFound(t *testing.T) {
	_, err := LoadFramework("/nonexistent/path/to/framework.yaml")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestLoadAllFrameworks(t *testing.T) {
	dir := t.TempDir()

	fw1 := `id: soc2
name: SOC 2 Type II
version: "2017"
controls:
  - ref: CC6.1
    title: Logical Access Controls
`
	fw2 := `id: iso27001
name: ISO 27001
version: "2022"
controls:
  - ref: A.9.4.2
    title: Secure Log-on Procedures
`
	if err := os.WriteFile(filepath.Join(dir, "soc2.yaml"), []byte(fw1), 0644); err != nil {
		t.Fatalf("writing framework 1: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "iso27001.yaml"), []byte(fw2), 0644); err != nil {
		t.Fatalf("writing framework 2: %v", err)
	}

	// Non-YAML file should be ignored.
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("not yaml"), 0644); err != nil {
		t.Fatalf("writing txt file: %v", err)
	}

	frameworks, err := LoadAllFrameworks(dir)
	if err != nil {
		t.Fatalf("LoadAllFrameworks returned error: %v", err)
	}

	if len(frameworks) != 2 {
		t.Fatalf("got %d frameworks, want 2", len(frameworks))
	}

	ids := map[string]bool{}
	for _, fw := range frameworks {
		ids[fw.ID] = true
	}
	if !ids["soc2"] {
		t.Error("missing framework soc2")
	}
	if !ids["iso27001"] {
		t.Error("missing framework iso27001")
	}
}

func TestLoadAllFrameworks_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	frameworks, err := LoadAllFrameworks(dir)
	if err != nil {
		t.Fatalf("LoadAllFrameworks returned error: %v", err)
	}
	if len(frameworks) != 0 {
		t.Fatalf("got %d frameworks, want 0", len(frameworks))
	}
}

func TestLoadAllFrameworks_InvalidDirPath(t *testing.T) {
	_, err := LoadAllFrameworks("/nonexistent/dir/path")
	if err == nil {
		t.Fatal("expected error for nonexistent directory, got nil")
	}
}

func TestLoadAllFrameworks_SkipsInvalidYAML(t *testing.T) {
	dir := t.TempDir()

	valid := `id: soc2
name: SOC 2
version: "2017"
controls:
  - ref: CC6.1
    title: Access Controls
`
	invalid := `not: [valid: yaml: {{`

	if err := os.WriteFile(filepath.Join(dir, "valid.yaml"), []byte(valid), 0644); err != nil {
		t.Fatalf("writing valid yaml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "invalid.yaml"), []byte(invalid), 0644); err != nil {
		t.Fatalf("writing invalid yaml: %v", err)
	}

	frameworks, err := LoadAllFrameworks(dir)
	if err != nil {
		t.Fatalf("LoadAllFrameworks returned error: %v", err)
	}
	if len(frameworks) != 1 {
		t.Fatalf("got %d frameworks, want 1 (should skip invalid)", len(frameworks))
	}
	if frameworks[0].ID != "soc2" {
		t.Errorf("ID = %q, want %q", frameworks[0].ID, "soc2")
	}
}
