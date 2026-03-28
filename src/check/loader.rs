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
        debug!("checks directory does not exist, skipping: {}", dir.display());
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
    let content = fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let def: CheckDefinition = serde_yaml::from_str(&content)
        .with_context(|| format!("parsing {}", path.display()))?;
    Ok(def)
}

/// Load all `.check.yaml` files from a directory tree and return their parsed definitions.
///
/// Unlike `load_checks_from_dir`, this does not require a Registry and is useful
/// for harden, codegen, and report commands that need the raw definitions.
/// Skips files that fail to parse with a warning.
pub fn load_definitions_from_dir(dir: &Path) -> Vec<CheckDefinition> {
    if !dir.exists() {
        debug!("checks directory does not exist, skipping: {}", dir.display());
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
            Err(e) => warn!("failed to load user checks from {}: {:#}", user_dir.display(), e),
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
}
