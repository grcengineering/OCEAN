// Fleet manifest parsing, validation, and env var interpolation.
//
// Security mitigations: F1 (pure string substitution), F2 (per-source allowlist),
// F3 (no nested interpolation), F5 (max 256 targets), F7 (target ID validation),
// F9 (256KB size limit), F10 (schema validation).

use std::collections::{HashMap, HashSet};
use std::path::Path;

use anyhow::{bail, Context, Result};
use regex::Regex;
use serde::Deserialize;

/// Maximum fleet manifest file size (256KB). [F9]
const MAX_MANIFEST_SIZE: u64 = 256 * 1024;

/// Maximum number of targets per fleet manifest. [F5]
const MAX_TARGETS: usize = 256;

// ─── Per-Source Credential Allowlists (F2) ──────────────────────────────────

/// Returns the set of allowed credential env var names for a given source.
fn allowed_credentials(source: &str) -> Option<&'static [&'static str]> {
    match source {
        "github" => Some(&[
            "GITHUB_TOKEN",
            "GITHUB_ORG",
            "GITHUB_API_URL",
        ]),
        "okta" => Some(&[
            "OKTA_API_TOKEN",
            "OKTA_DOMAIN",
            "OKTA_ORG_URL",
        ]),
        "aws" => Some(&[
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "AWS_REGION",
            "AWS_DEFAULT_REGION",
        ]),
        "azure" => Some(&[
            "AZURE_CLIENT_ID",
            "AZURE_CLIENT_SECRET",
            "AZURE_TENANT_ID",
            "AZURE_SUBSCRIPTION_ID",
        ]),
        _ => None,
    }
}

// ─── Env Var Interpolation (F1, F3) ─────────────────────────────────────────

/// Strict env var name pattern: uppercase letters, digits, underscores. [F1]
fn is_valid_env_var_name(name: &str) -> bool {
    lazy_static_regex().is_match(name)
}

fn lazy_static_regex() -> Regex {
    // This compiles a fresh regex each call; in production you'd use lazy_static or OnceCell.
    // Since manifest parsing is a one-time operation, this is acceptable.
    Regex::new(r"^[A-Z_][A-Z0-9_]*$").unwrap()
}

/// Resolves `${VAR_NAME}` references to their env var values.
///
/// Security: Pure string substitution only — no shell expansion, no backticks,
/// no $() processing. Single-pass, no nested interpolation. [F1, F3]
pub fn resolve_env_ref(value: &str) -> Result<String> {
    // F3: Reject nested interpolation
    if value.matches("${").count() > 1 {
        bail!("nested env var interpolation rejected: {value}");
    }

    // Check if value is an env var reference
    if let Some(inner) = value.strip_prefix("${").and_then(|s| s.strip_suffix('}')) {
        // F1: Validate env var name format
        if !is_valid_env_var_name(inner) {
            bail!(
                "invalid env var name '{inner}': must match [A-Z_][A-Z0-9_]*"
            );
        }
        std::env::var(inner).with_context(|| format!("env var {inner} not set"))
    } else {
        // Not an env var reference — return as-is (for non-secret fields like org names)
        Ok(value.to_string())
    }
}

// ─── Raw YAML Structures ────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct RawManifest {
    fleet: RawFleetMeta,
    targets: Vec<RawFleetTarget>,
}

#[derive(Debug, Deserialize)]
struct RawFleetMeta {
    name: String,
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawFleetTarget {
    id: String,
    source: String,
    credentials: HashMap<String, String>,
}

// ─── Validated Types ────────────────────────────────────────────────────────

/// Validated fleet metadata.
#[derive(Debug, Clone)]
pub struct FleetMeta {
    pub name: String,
    pub description: Option<String>,
}

/// A validated fleet target with resolved credentials.
#[derive(Debug, Clone)]
pub struct FleetTarget {
    pub id: String,
    pub source: String,
    /// Resolved credential values (env vars already interpolated).
    pub credentials: HashMap<String, String>,
}

/// A fully validated and resolved fleet manifest.
#[derive(Debug, Clone)]
pub struct FleetManifest {
    pub fleet: FleetMeta,
    pub targets: Vec<FleetTarget>,
}

impl FleetManifest {
    /// Parse and validate a fleet manifest from YAML bytes.
    ///
    /// Validation pipeline: [F9] size → [F10] parse → [F5] target count →
    /// duplicate IDs → [F7] target ID format → source type → [F2] credential
    /// allowlist → [F1] env var resolution.
    pub fn from_yaml(yaml: &[u8]) -> Result<Self> {
        // F9: Size limit
        if yaml.len() > MAX_MANIFEST_SIZE as usize {
            bail!(
                "fleet manifest exceeds maximum size of {}KB",
                MAX_MANIFEST_SIZE / 1024
            );
        }

        // Parse YAML
        let raw: RawManifest =
            serde_yaml::from_slice(yaml).context("invalid fleet manifest YAML")?;

        // Validate fleet name is non-empty
        if raw.fleet.name.trim().is_empty() {
            bail!("fleet manifest 'fleet.name' must not be empty");
        }

        // F5: Target count
        if raw.targets.is_empty() {
            bail!("fleet manifest must contain at least one target");
        }
        if raw.targets.len() > MAX_TARGETS {
            bail!(
                "fleet manifest contains {} targets, maximum is {MAX_TARGETS}",
                raw.targets.len()
            );
        }

        // Duplicate target ID check
        let mut seen_ids = HashSet::new();
        for t in &raw.targets {
            if !seen_ids.insert(&t.id) {
                bail!("duplicate target ID: '{}'", t.id);
            }
        }

        // Validate and resolve each target
        let mut targets = Vec::with_capacity(raw.targets.len());
        for raw_target in raw.targets {
            targets.push(validate_target(raw_target)?);
        }

        Ok(FleetManifest {
            fleet: FleetMeta {
                name: raw.fleet.name,
                description: raw.fleet.description,
            },
            targets,
        })
    }

    /// Load a fleet manifest from a file path.
    pub fn from_file(path: &Path) -> Result<Self> {
        // F9: Check file size before reading
        let metadata = std::fs::metadata(path)
            .with_context(|| format!("cannot read fleet manifest: {}", path.display()))?;
        if metadata.len() > MAX_MANIFEST_SIZE {
            bail!(
                "fleet manifest file exceeds maximum size of {}KB",
                MAX_MANIFEST_SIZE / 1024
            );
        }

        let bytes = std::fs::read(path)
            .with_context(|| format!("cannot read fleet manifest: {}", path.display()))?;
        Self::from_yaml(&bytes)
    }
}

/// Target ID pattern: alphanumeric start, then alphanumeric/underscore/hyphen, max 64 chars. [F7]
fn is_valid_target_id(id: &str) -> bool {
    let re = Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$").unwrap();
    re.is_match(id)
}

/// Known source types.
const KNOWN_SOURCES: &[&str] = &["github", "okta", "aws", "azure"];

fn validate_target(raw: RawFleetTarget) -> Result<FleetTarget> {
    // F7: Target ID validation
    if !is_valid_target_id(&raw.id) {
        bail!(
            "invalid target ID '{}': must match [a-zA-Z0-9][a-zA-Z0-9_-]{{0,63}}",
            raw.id
        );
    }

    // Source type check
    if !KNOWN_SOURCES.contains(&raw.source.as_str()) {
        bail!(
            "unknown source '{}' for target '{}'; expected one of: {}",
            raw.source,
            raw.id,
            KNOWN_SOURCES.join(", ")
        );
    }

    // F2: Credential allowlist per source
    let allowlist = allowed_credentials(&raw.source).unwrap(); // safe: source validated above
    for key in raw.credentials.keys() {
        if !allowlist.contains(&key.as_str()) {
            bail!(
                "credential '{}' not allowed for source '{}' (target '{}'). Allowed: {}",
                key,
                raw.source,
                raw.id,
                allowlist.join(", ")
            );
        }
    }

    // F1: Resolve env var references in credential values
    let mut resolved_credentials = HashMap::new();
    for (key, value) in &raw.credentials {
        let resolved = resolve_env_ref(value)
            .with_context(|| format!("target '{}', credential '{}'", raw.id, key))?;
        resolved_credentials.insert(key.clone(), resolved);
    }

    Ok(FleetTarget {
        id: raw.id,
        source: raw.source,
        credentials: resolved_credentials,
    })
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // UT-010: Valid fleet manifest parses successfully
    #[test]
    fn valid_manifest_parses() {
        std::env::set_var("TEST_GH_TOKEN", "ghp_test123");
        std::env::set_var("TEST_GH_ORG", "acme");
        let yaml = br#"
fleet:
  name: "Test Fleet"
  description: "A test fleet"
targets:
  - id: "github-main"
    source: github
    credentials:
      GITHUB_TOKEN: "${TEST_GH_TOKEN}"
      GITHUB_ORG: "${TEST_GH_ORG}"
"#;
        let manifest = FleetManifest::from_yaml(yaml).unwrap();
        assert_eq!(manifest.fleet.name, "Test Fleet");
        assert_eq!(manifest.fleet.description.as_deref(), Some("A test fleet"));
        assert_eq!(manifest.targets.len(), 1);
        assert_eq!(manifest.targets[0].id, "github-main");
        assert_eq!(manifest.targets[0].source, "github");
        assert_eq!(
            manifest.targets[0].credentials.get("GITHUB_TOKEN").unwrap(),
            "ghp_test123"
        );
    }

    // UT-011: Fleet manifest with 0 targets rejected
    #[test]
    fn empty_targets_rejected() {
        let yaml = br#"
fleet:
  name: "Empty"
targets: []
"#;
        let err = FleetManifest::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("at least one target"),
            "unexpected error: {err}"
        );
    }

    // UT-012: Duplicate target IDs rejected
    #[test]
    fn duplicate_ids_rejected() {
        std::env::set_var("TEST_DUP_TOKEN", "tok");
        let yaml = br#"
fleet:
  name: "Dup"
targets:
  - id: "same-id"
    source: github
    credentials:
      GITHUB_TOKEN: "${TEST_DUP_TOKEN}"
  - id: "same-id"
    source: github
    credentials:
      GITHUB_TOKEN: "${TEST_DUP_TOKEN}"
"#;
        let err = FleetManifest::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("duplicate target ID"),
            "unexpected error: {err}"
        );
    }

    // UT-013: Unknown source type rejected
    #[test]
    fn unknown_source_rejected() {
        let yaml = br#"
fleet:
  name: "Bad Source"
targets:
  - id: "jira-target"
    source: jira
    credentials: {}
"#;
        let err = FleetManifest::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("unknown source 'jira'"),
            "unexpected error: {err}"
        );
    }

    // UT-014: Env var interpolation resolves set vars
    #[test]
    fn env_var_resolves() {
        std::env::set_var("TEST_RESOLVE_VAR", "secret_value");
        let result = resolve_env_ref("${TEST_RESOLVE_VAR}").unwrap();
        assert_eq!(result, "secret_value");
    }

    // UT-015: Env var interpolation fails on unset vars
    #[test]
    fn unset_env_var_fails() {
        std::env::remove_var("DEFINITELY_NOT_SET_12345");
        let err = resolve_env_ref("${DEFINITELY_NOT_SET_12345}").unwrap_err();
        assert!(
            err.to_string().contains("not set"),
            "unexpected error: {err}"
        );
    }

    // UT-016: Fleet manifest validates required fields
    #[test]
    fn missing_fleet_name_rejected() {
        let yaml = br#"
fleet:
  name: ""
targets:
  - id: "t1"
    source: github
    credentials: {}
"#;
        let err = FleetManifest::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("must not be empty"),
            "unexpected error: {err}"
        );
    }

    // UT-017: Credentials accept only env var syntax for known secrets
    #[test]
    fn credential_allowlist_enforced() {
        std::env::set_var("TEST_ALLOW_TOKEN", "tok");
        let yaml = br#"
fleet:
  name: "Allowlist Test"
targets:
  - id: "github-test"
    source: github
    credentials:
      GITHUB_TOKEN: "${TEST_ALLOW_TOKEN}"
      AWS_SECRET_ACCESS_KEY: "${TEST_ALLOW_TOKEN}"
"#;
        let err = FleetManifest::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("not allowed for source 'github'"),
            "unexpected error: {err}"
        );
    }

    // F1: Shell injection via interpolation rejected
    #[test]
    fn shell_injection_rejected() {
        let err = resolve_env_ref("${SHELL$(whoami)}").unwrap_err();
        assert!(
            err.to_string().contains("invalid env var name"),
            "unexpected error: {err}"
        );
    }

    // F3: Nested interpolation rejected
    #[test]
    fn nested_interpolation_rejected() {
        let err = resolve_env_ref("${${INNER}}").unwrap_err();
        assert!(
            err.to_string().contains("nested"),
            "unexpected error: {err}"
        );
    }

    // F7: Path traversal in target ID rejected
    #[test]
    fn path_traversal_id_rejected() {
        let yaml = br#"
fleet:
  name: "Traversal"
targets:
  - id: "../../etc/passwd"
    source: github
    credentials: {}
"#;
        let err = FleetManifest::from_yaml(yaml).unwrap_err();
        assert!(
            err.to_string().contains("invalid target ID"),
            "unexpected error: {err}"
        );
    }

    // F5: Exceeding max targets rejected
    #[test]
    fn excess_targets_rejected() {
        let mut yaml = String::from("fleet:\n  name: \"Big\"\ntargets:\n");
        for i in 0..257 {
            yaml.push_str(&format!(
                "  - id: \"t{i}\"\n    source: github\n    credentials: {{}}\n"
            ));
        }
        let err = FleetManifest::from_yaml(yaml.as_bytes()).unwrap_err();
        assert!(
            err.to_string().contains("maximum is 256"),
            "unexpected error: {err}"
        );
    }

    // F9: Oversized manifest rejected
    #[test]
    fn oversized_manifest_rejected() {
        let big = vec![b' '; (MAX_MANIFEST_SIZE as usize) + 1];
        let err = FleetManifest::from_yaml(&big).unwrap_err();
        assert!(
            err.to_string().contains("exceeds maximum size"),
            "unexpected error: {err}"
        );
    }

    // Non-env-var values pass through
    #[test]
    fn plain_value_passes_through() {
        let result = resolve_env_ref("acme-corp").unwrap();
        assert_eq!(result, "acme-corp");
    }
}
