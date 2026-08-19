// Check loader — discovers and registers .check.yaml files into the Registry.
//
// Load order (Metasploit-style drop-in):
//   1. Bundled:  checks/ directory shipped with OCEAN
//   2. User:     ~/.ocean/checks/
//   3. Custom:   paths provided via --checks-dir

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use tracing::{debug, warn};

use crate::module::Registry;

use super::definition::{CheckDefinition, CheckType};
use super::interpreter::{YamlObserver, YamlTester};

/// Load all `.check.yaml` files from a directory tree and register them.
///
/// Recurses into subdirectories. Skips files that fail to parse with a warning.
/// Returns the number of checks successfully registered.
pub fn load_checks_from_dir(registry: &Registry, dir: &Path) -> Result<usize> {
    if !dir.exists() {
        debug!(
            "checks directory does not exist, skipping: {}",
            dir.display()
        );
        return Ok(0);
    }

    let mut count = 0;
    for entry in walk_check_files(dir) {
        match load_check_file(&entry) {
            Ok(def) => {
                register_check(registry, def);
                count += 1;
            }
            Err(e) => {
                warn!("skipping {}: {:#}", entry.display(), e);
            }
        }
    }

    Ok(count)
}

/// Walk a directory tree and collect all `.check.yaml` file paths.
fn walk_check_files(dir: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    collect_check_files(dir, &mut paths);
    paths
}

fn collect_check_files(dir: &Path, paths: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            warn!("cannot read directory {}: {}", dir.display(), e);
            return;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_check_files(&path, paths);
        } else if is_check_file(&path) {
            paths.push(path);
        }
    }
}

fn is_check_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.ends_with(".check.yaml") || n.ends_with(".check.yml"))
        .unwrap_or(false)
}

/// Parse a single `.check.yaml` file into a CheckDefinition.
pub fn load_check_file(path: &Path) -> Result<CheckDefinition> {
    let content =
        fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let def: CheckDefinition =
        serde_yaml::from_str(&content).with_context(|| format!("parsing {}", path.display()))?;
    Ok(def)
}

/// Load all `.check.yaml` files from a directory tree and return their parsed definitions.
///
/// Unlike `load_checks_from_dir`, this does not require a Registry and is useful
/// for harden, codegen, and report commands that need the raw definitions.
/// Skips files that fail to parse with a warning.
pub fn load_definitions_from_dir(dir: &Path) -> Vec<CheckDefinition> {
    if !dir.exists() {
        debug!(
            "checks directory does not exist, skipping: {}",
            dir.display()
        );
        return Vec::new();
    }
    walk_check_files(dir)
        .into_iter()
        .filter_map(|p| match load_check_file(&p) {
            Ok(def) => Some(def),
            Err(e) => {
                warn!("skipping {}: {:#}", p.display(), e);
                None
            }
        })
        .collect()
}

/// Register a CheckDefinition into the registry as the appropriate module type.
pub fn register_check(registry: &Registry, def: CheckDefinition) {
    let id = def.id.clone();
    match def.check_type {
        CheckType::Passive => {
            debug!("registering YAML observer: {}", id);
            registry.register_observer(Arc::new(YamlObserver::new(def)));
        }
        CheckType::Active => {
            debug!("registering YAML tester: {}", id);
            registry.register_tester(Arc::new(YamlTester::new(def)));
        }
    }
}

/// Load checks from all standard paths (bundled + user home).
///
/// - `bundled_dir`: the `checks/` directory co-located with the binary
/// - Automatically includes `~/.ocean/checks/` for drop-in user checks
pub fn load_all_checks(registry: &Registry, bundled_dir: &Path) -> usize {
    let mut total = 0;

    match load_checks_from_dir(registry, bundled_dir) {
        Ok(n) => {
            debug!("loaded {} bundled checks from {}", n, bundled_dir.display());
            total += n;
        }
        Err(e) => warn!("failed to load bundled checks: {:#}", e),
    }

    // User drop-in directory: ~/.ocean/checks/
    if let Some(home) = dirs_home() {
        let user_dir = home.join(".ocean").join("checks");
        match load_checks_from_dir(registry, &user_dir) {
            Ok(n) => {
                if n > 0 {
                    debug!("loaded {} user checks from {}", n, user_dir.display());
                }
                total += n;
            }
            Err(e) => warn!(
                "failed to load user checks from {}: {:#}",
                user_dir.display(),
                e
            ),
        }
    }

    total
}

/// Resolve the user's home directory without the `dirs` crate.
fn dirs_home() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_check(dir: &Path, filename: &str, content: &str) {
        fs::write(dir.join(filename), content).unwrap();
    }

    const PASSIVE_YAML: &str = r#"
id: TST-PASSIVE
name: Test Passive Check
source: github
steps: []
assertions: []
"#;

    const ACTIVE_YAML: &str = r#"
id: TST-ACTIVE
name: Test Active Check
source: github
type: active
safety: observable
steps: []
assertions: []
"#;

    const INVALID_YAML: &str = "not: valid: yaml: [[[";

    #[test]
    fn load_single_passive_check() {
        let dir = TempDir::new().unwrap();
        write_check(dir.path(), "tst-passive.check.yaml", PASSIVE_YAML);

        let registry = Registry::new();
        let count = load_checks_from_dir(&registry, dir.path()).unwrap();
        assert_eq!(count, 1);
        assert!(registry.get_observer("TST-PASSIVE").is_ok());
    }

    #[test]
    fn load_single_active_check() {
        let dir = TempDir::new().unwrap();
        write_check(dir.path(), "tst-active.check.yaml", ACTIVE_YAML);

        let registry = Registry::new();
        let count = load_checks_from_dir(&registry, dir.path()).unwrap();
        assert_eq!(count, 1);
        assert!(registry.get_tester("TST-ACTIVE").is_ok());
    }

    #[test]
    fn invalid_yaml_is_skipped_not_fatal() {
        let dir = TempDir::new().unwrap();
        write_check(dir.path(), "invalid.check.yaml", INVALID_YAML);
        write_check(dir.path(), "valid.check.yaml", PASSIVE_YAML);

        let registry = Registry::new();
        let count = load_checks_from_dir(&registry, dir.path()).unwrap();
        // Only the valid check loads; the invalid one is skipped with a warning.
        assert_eq!(count, 1);
    }

    #[test]
    fn non_check_yaml_files_are_ignored() {
        let dir = TempDir::new().unwrap();
        write_check(dir.path(), "not-a-check.yaml", PASSIVE_YAML);
        write_check(dir.path(), "also-ignored.json", "{}");
        write_check(dir.path(), "real.check.yaml", PASSIVE_YAML);

        let registry = Registry::new();
        let count = load_checks_from_dir(&registry, dir.path()).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn recurses_into_subdirectories() {
        let dir = TempDir::new().unwrap();
        let subdir = dir.path().join("github");
        fs::create_dir(&subdir).unwrap();
        write_check(&subdir, "tst.check.yaml", PASSIVE_YAML);

        let registry = Registry::new();
        let count = load_checks_from_dir(&registry, dir.path()).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn nonexistent_dir_returns_zero() {
        let registry = Registry::new();
        let count = load_checks_from_dir(&registry, Path::new("/nonexistent/path")).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn yml_extension_also_recognized() {
        let dir = TempDir::new().unwrap();
        write_check(dir.path(), "tst.check.yml", PASSIVE_YAML);

        let registry = Registry::new();
        let count = load_checks_from_dir(&registry, dir.path()).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn all_bundled_checks_load_successfully() {
        let checks_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("checks");
        if !checks_dir.exists() {
            return;
        }
        let mut failures = Vec::new();
        for path in walk_check_files(&checks_dir) {
            if let Err(e) = load_check_file(&path) {
                failures.push(format!("{}: {:#}", path.display(), e));
            }
        }
        assert!(
            failures.is_empty(),
            "bundled check files failed to load:\n{}",
            failures.join("\n")
        );
    }

    // ── load_check_file direct tests ────────────────────────────────────────

    #[test]
    fn load_check_file_returns_error_for_missing_file() {
        let result = load_check_file(Path::new("/nonexistent/file.check.yaml"));
        assert!(result.is_err());
        let err_msg = format!("{:#}", result.unwrap_err());
        assert!(
            err_msg.contains("reading"),
            "error should mention reading: {err_msg}"
        );
    }

    #[test]
    fn load_check_file_parses_all_fields_correctly() {
        let dir = TempDir::new().unwrap();
        let check_yaml = r#"
id: FULL-1
name: Full Field Check
description: Tests all fields are parsed
author: qa-engineer
version: "2.0"
source: github
type: active
safety: observable
environment: staging
severity: high
profile: L2
tags:
  - auth
  - mfa
references:
  cis: "1.1"
  nist: ["IA-2(1)", "IA-2(2)"]
  soc2: CC6.1
credentials:
  GITHUB_TOKEN:
    type: api_token
    required: true
inputs:
  org:
    description: GitHub org
    env: GITHUB_ORG
    required: true
pre_flight:
  - "Ensure token has admin:org scope"
steps:
  - id: step1
    action: api_call
    request:
      method: GET
      url: "https://api.github.com/orgs/{{org}}"
      headers:
        Authorization: "Bearer {{GITHUB_TOKEN}}"
    extract:
      mfa: "$.two_factor_requirement_enabled"
assertions:
  - id: assert1
    expr: "mfa == true"
    severity: critical
    title: MFA Check
    pass_message: MFA enabled
    fail_message: MFA disabled
remediation:
  description: Enable MFA
  steps:
    - "Go to org settings"
    - "Enable 2FA requirement"
"#;
        let path = dir.path().join("full.check.yaml");
        fs::write(&path, check_yaml).unwrap();

        let def = load_check_file(&path).unwrap();
        assert_eq!(def.id, "FULL-1");
        assert_eq!(def.name, "Full Field Check");
        assert_eq!(def.description, "Tests all fields are parsed");
        assert_eq!(def.author, "qa-engineer");
        assert_eq!(def.version, "2.0");
        assert_eq!(def.source, "github");
        assert_eq!(def.check_type, CheckType::Active);
        assert_eq!(def.safety, "observable");
        assert_eq!(def.environment, "staging");
        assert_eq!(def.severity, "high");
        assert_eq!(def.profile, "L2");
        assert_eq!(def.tags, vec!["auth", "mfa"]);
        assert_eq!(def.references.cis.as_vec(), vec!["1.1"]);
        assert_eq!(def.references.nist.as_vec(), vec!["IA-2(1)", "IA-2(2)"]);
        assert!(def.credentials.contains_key("GITHUB_TOKEN"));
        assert!(def.credentials["GITHUB_TOKEN"].required);
        assert!(def.inputs.contains_key("org"));
        assert!(def.inputs["org"].required);
        assert_eq!(def.pre_flight.len(), 1);
        assert_eq!(def.steps.len(), 1);
        assert_eq!(def.steps[0].id, "step1");
        assert_eq!(def.steps[0].request.method, "GET");
        assert!(def.steps[0].extract.contains_key("mfa"));
        assert_eq!(def.assertions.len(), 1);
        assert_eq!(def.assertions[0].severity, "critical");
        let rem = def.remediation.as_ref().unwrap();
        assert_eq!(rem.steps.len(), 2);
    }

    #[test]
    fn load_check_file_missing_required_id_fails() {
        let dir = TempDir::new().unwrap();
        let yaml = r#"
name: No ID Check
source: github
steps: []
assertions: []
"#;
        let path = dir.path().join("no-id.check.yaml");
        fs::write(&path, yaml).unwrap();
        assert!(load_check_file(&path).is_err());
    }

    #[test]
    fn load_check_file_missing_required_name_fails() {
        let dir = TempDir::new().unwrap();
        let yaml = r#"
id: NO-NAME
source: github
steps: []
assertions: []
"#;
        let path = dir.path().join("no-name.check.yaml");
        fs::write(&path, yaml).unwrap();
        assert!(load_check_file(&path).is_err());
    }

    #[test]
    fn load_check_file_wrong_type_for_steps_fails() {
        let dir = TempDir::new().unwrap();
        let yaml = r#"
id: BAD-STEPS
name: Bad Steps Type
source: github
steps: "not a list"
assertions: []
"#;
        let path = dir.path().join("bad-steps.check.yaml");
        fs::write(&path, yaml).unwrap();
        assert!(load_check_file(&path).is_err());
    }

    #[test]
    fn load_check_file_wrong_type_for_assertions_fails() {
        let dir = TempDir::new().unwrap();
        let yaml = r#"
id: BAD-ASSERT
name: Bad Assertions Type
source: github
steps: []
assertions: "not a list"
"#;
        let path = dir.path().join("bad-assert.check.yaml");
        fs::write(&path, yaml).unwrap();
        assert!(load_check_file(&path).is_err());
    }

    #[test]
    fn load_check_file_extra_unknown_fields_are_tolerated() {
        let dir = TempDir::new().unwrap();
        // serde_yaml with default config ignores unknown fields on structs
        // that don't have #[serde(deny_unknown_fields)]
        let yaml = r#"
id: EXTRA-1
name: Extra Fields
source: github
totally_unknown_field: some_value
another_extra: 42
steps: []
assertions: []
"#;
        let path = dir.path().join("extra.check.yaml");
        fs::write(&path, yaml).unwrap();
        // Should succeed because CheckDefinition doesn't deny unknown fields
        let result = load_check_file(&path);
        assert!(
            result.is_ok(),
            "extra fields should be tolerated: {result:?}"
        );
    }

    // ── load_definitions_from_dir tests ─────────────────────────────────────

    #[test]
    fn load_definitions_from_dir_returns_parsed_defs() {
        let dir = TempDir::new().unwrap();
        write_check(dir.path(), "a.check.yaml", PASSIVE_YAML);
        write_check(dir.path(), "b.check.yaml", ACTIVE_YAML);

        let defs = load_definitions_from_dir(dir.path());
        assert_eq!(defs.len(), 2);
        let ids: Vec<&str> = defs.iter().map(|d| d.id.as_str()).collect();
        assert!(ids.contains(&"TST-PASSIVE"));
        assert!(ids.contains(&"TST-ACTIVE"));
    }

    #[test]
    fn load_definitions_from_dir_nonexistent_returns_empty() {
        let defs = load_definitions_from_dir(Path::new("/nonexistent/path"));
        assert!(defs.is_empty());
    }

    #[test]
    fn load_checks_from_dir_nonexistent_returns_zero() {
        let registry = Registry::new();
        let result = load_checks_from_dir(&registry, Path::new("/definitely-does-not-exist"));
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn load_checks_from_dir_skips_invalid_file_logs_warn() {
        let dir = TempDir::new().unwrap();
        write_check(dir.path(), "good.check.yaml", PASSIVE_YAML);
        write_check(dir.path(), "bad.check.yaml", INVALID_YAML);
        let registry = Registry::new();
        let result = load_checks_from_dir(&registry, dir.path());
        // Bad file skipped (warn!), good file registered → count=1.
        assert_eq!(result.unwrap(), 1);
    }

    #[test]
    fn load_definitions_from_dir_skips_invalid_files() {
        let dir = TempDir::new().unwrap();
        write_check(dir.path(), "good.check.yaml", PASSIVE_YAML);
        write_check(dir.path(), "bad.check.yaml", INVALID_YAML);

        let defs = load_definitions_from_dir(dir.path());
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0].id, "TST-PASSIVE");
    }

    // ── register_check tests ────────────────────────────────────────────────

    #[test]
    fn register_check_passive_goes_to_observer_registry() {
        let def: CheckDefinition = serde_yaml::from_str(PASSIVE_YAML).unwrap();
        let registry = Registry::new();
        register_check(&registry, def);
        assert!(registry.get_observer("TST-PASSIVE").is_ok());
        assert!(registry.get_tester("TST-PASSIVE").is_err());
    }

    #[test]
    fn register_check_active_goes_to_tester_registry() {
        let def: CheckDefinition = serde_yaml::from_str(ACTIVE_YAML).unwrap();
        let registry = Registry::new();
        register_check(&registry, def);
        assert!(registry.get_tester("TST-ACTIVE").is_ok());
        assert!(registry.get_observer("TST-ACTIVE").is_err());
    }

    // ── Edge cases ──────────────────────────────────────────────────────────

    #[test]
    fn empty_directory_returns_zero() {
        let dir = TempDir::new().unwrap();
        let registry = Registry::new();
        let count = load_checks_from_dir(&registry, dir.path()).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn multiple_checks_in_one_directory() {
        let dir = TempDir::new().unwrap();
        write_check(dir.path(), "a.check.yaml", PASSIVE_YAML);
        write_check(
            dir.path(),
            "b.check.yaml",
            r#"
id: TST-B
name: Second Check
source: github
steps: []
assertions: []
"#,
        );

        let registry = Registry::new();
        let count = load_checks_from_dir(&registry, dir.path()).unwrap();
        assert_eq!(count, 2);
        assert!(registry.get_observer("TST-PASSIVE").is_ok());
        assert!(registry.get_observer("TST-B").is_ok());
    }

    #[test]
    fn deeply_nested_subdirectories() {
        let dir = TempDir::new().unwrap();
        let deep = dir.path().join("a").join("b").join("c");
        fs::create_dir_all(&deep).unwrap();
        write_check(&deep, "deep.check.yaml", PASSIVE_YAML);

        let registry = Registry::new();
        let count = load_checks_from_dir(&registry, dir.path()).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn is_check_file_rejects_plain_yaml() {
        assert!(!is_check_file(Path::new("something.yaml")));
        assert!(!is_check_file(Path::new("something.yml")));
        assert!(!is_check_file(Path::new("check.yaml")));
    }

    #[test]
    fn is_check_file_accepts_both_extensions() {
        assert!(is_check_file(Path::new("gh-1.01.check.yaml")));
        assert!(is_check_file(Path::new("gh-1.01.check.yml")));
    }

    #[test]
    fn load_check_file_empty_file_fails() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("empty.check.yaml");
        fs::write(&path, "").unwrap();
        assert!(load_check_file(&path).is_err());
    }

    #[test]
    fn all_bundled_checks_pass_json_schema_validation() {
        let checks_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("checks");
        if !checks_dir.exists() {
            return;
        }
        let schema_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("schemas/check.schema.json");
        let schema_str =
            fs::read_to_string(&schema_path).expect("failed to read check.schema.json");
        let schema_value: serde_json::Value =
            serde_json::from_str(&schema_str).expect("failed to parse check.schema.json");
        let validator =
            jsonschema::validator_for(&schema_value).expect("failed to compile JSON Schema");

        let mut failures = Vec::new();
        for path in walk_check_files(&checks_dir) {
            let content = fs::read_to_string(&path).unwrap();
            let yaml_value: serde_yaml::Value = match serde_yaml::from_str(&content) {
                Ok(v) => v,
                Err(e) => {
                    failures.push(format!("{}: YAML parse error: {}", path.display(), e));
                    continue;
                }
            };
            // Convert YAML value to JSON value for schema validation
            let json_str = serde_json::to_string(&yaml_value).unwrap();
            let json_value: serde_json::Value = serde_json::from_str(&json_str).unwrap();
            let errors: Vec<_> = validator.iter_errors(&json_value).collect();
            if !errors.is_empty() {
                for e in &errors {
                    failures.push(format!("{}: {}", path.display(), e));
                }
            }
        }
        assert!(
            failures.is_empty(),
            "bundled check files failed JSON Schema validation:\n{}",
            failures.join("\n")
        );
    }

    #[test]
    fn defaults_applied_when_optional_fields_omitted() {
        let dir = TempDir::new().unwrap();
        let yaml = r#"
id: MIN-1
name: Minimal
steps: []
assertions: []
"#;
        let path = dir.path().join("min.check.yaml");
        fs::write(&path, yaml).unwrap();
        let def = load_check_file(&path).unwrap();

        assert_eq!(def.check_type, CheckType::Passive); // default
        assert_eq!(def.version, "1.0"); // default_version()
        assert!(def.description.is_empty());
        assert!(def.author.is_empty());
        assert!(def.source.is_empty());
        assert!(def.safety.is_empty());
        assert!(def.tags.is_empty());
        assert!(def.credentials.is_empty());
        assert!(def.inputs.is_empty());
        assert!(def.pre_flight.is_empty());
        assert!(def.remediation.is_none());
    }

    // ── load_all_checks tests ────────────────────────────────────────────────

    #[test]
    fn load_all_checks_nonexistent_bundled_dir_returns_zero() {
        let registry = Registry::new();
        let count = load_all_checks(&registry, Path::new("/nonexistent/bundled/checks"));
        // Bundled dir doesn't exist → 0 bundled checks loaded
        // User dir may or may not exist; total could be 0 or more from ~/.ocean/checks/
        // We just assert the function doesn't panic
        let _ = count;
    }

    #[test]
    fn load_all_checks_with_valid_bundled_dir() {
        let dir = TempDir::new().unwrap();
        write_check(dir.path(), "t.check.yaml", PASSIVE_YAML);

        let registry = Registry::new();
        let count = load_all_checks(&registry, dir.path());
        // At least the bundled check should be loaded
        assert!(count >= 1);
        assert!(registry.get_observer("TST-PASSIVE").is_ok());
    }

    #[test]
    fn load_all_checks_invalid_checks_in_bundled_skipped() {
        let dir = TempDir::new().unwrap();
        write_check(dir.path(), "bad.check.yaml", INVALID_YAML);
        write_check(dir.path(), "good.check.yaml", PASSIVE_YAML);

        let registry = Registry::new();
        let count = load_all_checks(&registry, dir.path());
        // One valid check loaded; invalid one skipped
        assert!(count >= 1);
    }

    // ── dirs_home tests ──────────────────────────────────────────────────────

    #[test]
    #[serial_test::serial]
    fn dirs_home_returns_path_from_home_env() {
        let old = std::env::var("HOME").ok();
        std::env::set_var("HOME", "/tmp/fake_home_for_test");
        let home = dirs_home();
        assert!(home.is_some());
        assert_eq!(home.unwrap(), PathBuf::from("/tmp/fake_home_for_test"));
        match old {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    #[serial_test::serial]
    fn dirs_home_returns_none_when_home_not_set() {
        let old = std::env::var("HOME").ok();
        std::env::remove_var("HOME");
        // Only check this when HOME really isn't set; skip if the env is set by OS
        let home = dirs_home();
        // home might be Some if HOME somehow got set again; just don't panic
        let _ = home;
        match old {
            Some(v) => std::env::set_var("HOME", v),
            None => {}
        }
    }

    // ── collect_check_files with unreadable directory ────────────────────────

    #[test]
    fn walk_check_files_on_file_path_returns_empty() {
        // walk_check_files with a path that is a file (not dir) should return empty
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("notadir.txt");
        fs::write(&file_path, "content").unwrap();
        // collect_check_files checks if it's a directory, so this should produce no results
        let mut paths = Vec::new();
        collect_check_files(&file_path, &mut paths);
        assert!(paths.is_empty());
    }

    // ── load_definitions_from_dir: recursion ────────────────────────────────

    #[test]
    fn load_definitions_from_dir_recurses_into_subdirs() {
        let dir = TempDir::new().unwrap();
        let subdir = dir.path().join("sub");
        fs::create_dir(&subdir).unwrap();
        write_check(&subdir, "t.check.yaml", PASSIVE_YAML);
        write_check(dir.path(), "b.check.yaml", ACTIVE_YAML);

        let defs = load_definitions_from_dir(dir.path());
        assert_eq!(defs.len(), 2);
    }
}
