// CheckDefinition — Rust representation of a .check.yaml file.
//
// The .check.yaml format is the single source of truth for all OCEAN checks.
// This module provides the serde-deserializable structs for that format.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ─── Top-level check definition ───────────────────────────────────────────────

/// Deserializes a `.check.yaml` file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckDefinition {
    /// Unique check identifier (e.g., "GH-1.01").
    pub id: String,

    /// Human-readable name.
    pub name: String,

    /// Description of what this check verifies.
    #[serde(default)]
    pub description: String,

    #[serde(default)]
    pub author: String,

    #[serde(default = "default_version")]
    pub version: String,

    /// Source system (e.g., "github", "aws", "okta").
    #[serde(default)]
    pub source: String,

    /// "passive" (default) or "active".
    #[serde(rename = "type", default)]
    pub check_type: CheckType,

    /// Safety classification for active checks (e.g., "observable", "reversible").
    #[serde(default)]
    pub safety: String,

    /// Required environment for active checks (e.g., "staging", "production").
    #[serde(default)]
    pub environment: String,

    /// Hardening profile tier: "L1", "L2", or "L3".
    #[serde(default)]
    pub profile: String,

    #[serde(default)]
    pub tags: Vec<String>,

    /// Compliance framework references (CIS, NIST, SOC2, etc.).
    #[serde(default)]
    pub references: CheckReferences,

    /// Credentials this check requires, keyed by env var name.
    #[serde(default)]
    pub credentials: HashMap<String, CredentialDef>,

    /// Runtime inputs (org name, repo, etc.), keyed by input name.
    #[serde(default)]
    pub inputs: HashMap<String, InputDef>,

    /// Pre-flight checks to display before running an active test.
    #[serde(default)]
    pub pre_flight: Vec<String>,

    /// HTTP steps to execute in order.
    #[serde(default)]
    pub steps: Vec<CheckStep>,

    /// CEL assertions evaluated against extracted variables.
    #[serde(default)]
    pub assertions: Vec<CheckAssertion>,

    /// Remediation guidance and automated fix logic.
    #[serde(default)]
    pub remediation: Option<RemediationDef>,

    /// Set to "native" for checks that delegate to compiled Rust modules.
    #[serde(default)]
    pub implementation: String,

    /// Rust module name when `implementation == "native"`.
    #[serde(default)]
    pub native_module: String,
}

fn default_version() -> String {
    "1.0".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum CheckType {
    #[default]
    Passive,
    Active,
}

// ─── Compliance references ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CheckReferences {
    #[serde(default)]
    pub cis: StringOrVec,
    #[serde(default)]
    pub nist: StringOrVec,
    #[serde(default)]
    pub soc2: StringOrVec,
    #[serde(default)]
    pub iso27001: StringOrVec,
    #[serde(default)]
    pub pci_dss: StringOrVec,
    #[serde(default)]
    pub disa_stig: StringOrVec,
}

/// Accepts either a single string or a list of strings in YAML.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(untagged)]
pub enum StringOrVec {
    #[default]
    None,
    One(String),
    Many(Vec<String>),
}

impl StringOrVec {
    pub fn as_vec(&self) -> Vec<String> {
        match self {
            StringOrVec::None => vec![],
            StringOrVec::One(s) => vec![s.clone()],
            StringOrVec::Many(v) => v.clone(),
        }
    }
}

// ─── Credentials and inputs ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialDef {
    #[serde(rename = "type")]
    pub cred_type: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputDef {
    #[serde(default)]
    pub description: String,
    /// Environment variable name to read this input from.
    #[serde(default)]
    pub env: String,
    #[serde(default)]
    pub required: bool,
}

// ─── Steps ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckStep {
    pub id: String,

    /// Currently only "api_call" is supported.
    #[serde(default = "default_action")]
    pub action: String,

    /// Optional CEL expression; step is skipped when it evaluates to false.
    #[serde(default)]
    pub when: String,

    pub request: RequestDef,

    /// JSONPath expressions keyed by variable name. Extracted into the run context.
    #[serde(default)]
    pub extract: HashMap<String, String>,

    /// Per-status-code error handling (e.g., `422: "continue"`).
    #[serde(default)]
    pub on_error: HashMap<String, String>,
}

fn default_action() -> String {
    "api_call".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestDef {
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub body: Option<serde_json::Value>,
    /// When true, follow GitHub-style `Link: <url>; rel="next"` pagination.
    #[serde(default)]
    pub paginate: bool,
}

// ─── Assertions ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckAssertion {
    pub id: String,
    /// CEL expression evaluated against the run context variables.
    pub expr: String,
    #[serde(default = "default_severity")]
    pub severity: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub pass_message: String,
    #[serde(default)]
    pub fail_message: String,
    #[serde(default)]
    pub finding: Option<FindingDef>,
}

fn default_severity() -> String {
    "medium".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingDef {
    #[serde(default)]
    pub description: String,
}

// ─── Remediation ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationDef {
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub steps: Vec<String>,
    #[serde(default)]
    pub api: Option<RemediationApi>,
    #[serde(default)]
    pub cli: Option<RemediationCli>,
    #[serde(default)]
    pub terraform: Option<RemediationTerraform>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationApi {
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub body: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationCli {
    pub command: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationTerraform {
    #[serde(default)]
    pub resources: Vec<serde_json::Value>,
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL_CHECK: &str = r#"
id: TST-1
name: Test Check
source: github
steps: []
assertions: []
"#;

    const PASSIVE_CHECK: &str = r#"
id: GH-1.01
name: Enforce 2FA for Organization Members
source: github
profile: L1
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
    description: GitHub organization name
    env: GITHUB_ORG
    required: true

steps:
  - id: get_org_settings
    action: api_call
    request:
      method: GET
      url: "https://api.github.com/orgs/{{org}}"
      headers:
        Authorization: "Bearer {{GITHUB_TOKEN}}"
    extract:
      mfa_enforced: "$.two_factor_requirement_enabled"

assertions:
  - id: mfa_enforcement
    expr: "mfa_enforced == true"
    severity: critical
    title: Organization MFA Enforcement
    pass_message: "MFA is enforced"
    fail_message: "MFA is NOT enforced"
"#;

    #[test]
    fn deserialize_minimal_check() {
        let def: CheckDefinition = serde_yaml::from_str(MINIMAL_CHECK).unwrap();
        assert_eq!(def.id, "TST-1");
        assert_eq!(def.check_type, CheckType::Passive);
        assert!(def.steps.is_empty());
        assert!(def.assertions.is_empty());
    }

    #[test]
    fn deserialize_passive_check_with_references() {
        let def: CheckDefinition = serde_yaml::from_str(PASSIVE_CHECK).unwrap();
        assert_eq!(def.id, "GH-1.01");
        assert_eq!(def.profile, "L1");
        assert_eq!(def.references.cis.as_vec(), vec!["1.1"]);
        assert_eq!(def.references.nist.as_vec(), vec!["IA-2(1)", "IA-2(2)"]);
        assert_eq!(def.references.soc2.as_vec(), vec!["CC6.1"]);
        assert_eq!(def.steps.len(), 1);
        assert_eq!(def.assertions.len(), 1);
    }

    #[test]
    fn step_has_extract_and_headers() {
        let def: CheckDefinition = serde_yaml::from_str(PASSIVE_CHECK).unwrap();
        let step = &def.steps[0];
        assert_eq!(step.id, "get_org_settings");
        assert_eq!(step.request.method, "GET");
        assert!(step.extract.contains_key("mfa_enforced"));
        assert_eq!(step.extract["mfa_enforced"], "$.two_factor_requirement_enabled");
    }

    #[test]
    fn assertion_fields_parsed() {
        let def: CheckDefinition = serde_yaml::from_str(PASSIVE_CHECK).unwrap();
        let a = &def.assertions[0];
        assert_eq!(a.id, "mfa_enforcement");
        assert_eq!(a.expr, "mfa_enforced == true");
        assert_eq!(a.severity, "critical");
    }

    #[test]
    fn string_or_vec_as_vec() {
        let s = StringOrVec::One("foo".to_string());
        assert_eq!(s.as_vec(), vec!["foo"]);

        let v = StringOrVec::Many(vec!["a".to_string(), "b".to_string()]);
        assert_eq!(v.as_vec(), vec!["a", "b"]);

        let n = StringOrVec::None;
        assert!(n.as_vec().is_empty());
    }

    #[test]
    fn active_check_type_deserialized() {
        let yaml = r#"
id: ACT-1
name: Active Test
source: github
type: active
steps: []
assertions: []
"#;
        let def: CheckDefinition = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(def.check_type, CheckType::Active);
    }
}
