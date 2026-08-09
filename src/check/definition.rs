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

    /// Top-level severity for native checks that have no assertions.
    #[serde(default)]
    pub severity: String,

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
    /// HTH guide control this check derives from, as "vendor-slug:N.N" (e.g. "slack:1.2").
    #[serde(default)]
    pub hth: String,
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
    /// Default value when not provided via env var.
    #[serde(default)]
    pub default: String,
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

    /// Documentation note for this step.
    #[serde(default)]
    pub note: String,
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
    /// Form-urlencoded body (key/value pairs, templated like everything else).
    /// Mutually exclusive with `body` — OAuth token endpoints (SailPoint,
    /// OneLogin, Zoom S2S) are form-only and reject JSON bodies.
    #[serde(default)]
    pub body_form: Option<HashMap<String, String>>,
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
    /// Manual remediation steps for checks that cannot be automated.
    #[serde(default)]
    pub manual: Vec<String>,
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
    pub headers: HashMap<String, String>,
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

    // ── Serialization round-trip ─────────────────────────────────────────────

    #[test]
    fn serde_round_trip_minimal() {
        let def: CheckDefinition = serde_yaml::from_str(MINIMAL_CHECK).unwrap();
        let yaml_out = serde_yaml::to_string(&def).unwrap();
        let def2: CheckDefinition = serde_yaml::from_str(&yaml_out).unwrap();
        assert_eq!(def.id, def2.id);
        assert_eq!(def.name, def2.name);
        assert_eq!(def.check_type, def2.check_type);
    }

    #[test]
    fn serde_round_trip_full() {
        let def: CheckDefinition = serde_yaml::from_str(PASSIVE_CHECK).unwrap();
        let yaml_out = serde_yaml::to_string(&def).unwrap();
        let def2: CheckDefinition = serde_yaml::from_str(&yaml_out).unwrap();
        assert_eq!(def.id, def2.id);
        assert_eq!(def.profile, def2.profile);
        assert_eq!(def.references.cis.as_vec(), def2.references.cis.as_vec());
        assert_eq!(def.references.nist.as_vec(), def2.references.nist.as_vec());
        assert_eq!(def.steps.len(), def2.steps.len());
        assert_eq!(def.assertions.len(), def2.assertions.len());
    }

    // ── Default values ───────────────────────────────────────────────────────

    #[test]
    fn default_version_is_1_0() {
        let def: CheckDefinition = serde_yaml::from_str(MINIMAL_CHECK).unwrap();
        assert_eq!(def.version, "1.0");
    }

    #[test]
    fn default_check_type_is_passive() {
        let def: CheckDefinition = serde_yaml::from_str(MINIMAL_CHECK).unwrap();
        assert_eq!(def.check_type, CheckType::Passive);
    }

    #[test]
    fn defaults_for_optional_string_fields() {
        let def: CheckDefinition = serde_yaml::from_str(MINIMAL_CHECK).unwrap();
        assert!(def.description.is_empty());
        assert!(def.author.is_empty());
        assert!(def.safety.is_empty());
        assert!(def.environment.is_empty());
        assert!(def.severity.is_empty());
        assert!(def.profile.is_empty());
        assert!(def.implementation.is_empty());
        assert!(def.native_module.is_empty());
    }

    #[test]
    fn defaults_for_optional_collections() {
        let def: CheckDefinition = serde_yaml::from_str(MINIMAL_CHECK).unwrap();
        assert!(def.tags.is_empty());
        assert!(def.credentials.is_empty());
        assert!(def.inputs.is_empty());
        assert!(def.pre_flight.is_empty());
        assert!(def.remediation.is_none());
    }

    // ── Credential definitions ───────────────────────────────────────────────

    #[test]
    fn credential_def_parsed() {
        let def: CheckDefinition = serde_yaml::from_str(PASSIVE_CHECK).unwrap();
        assert!(def.credentials.contains_key("GITHUB_TOKEN"));
        let cred = &def.credentials["GITHUB_TOKEN"];
        assert_eq!(cred.cred_type, "api_token");
        assert!(cred.required);
    }

    #[test]
    fn credential_with_scopes() {
        let yaml = r#"
id: CRED-1
name: Cred Test
steps: []
assertions: []
credentials:
  GITHUB_TOKEN:
    type: api_token
    scopes:
      - read:org
      - admin:org
    required: true
"#;
        let def: CheckDefinition = serde_yaml::from_str(yaml).unwrap();
        let cred = &def.credentials["GITHUB_TOKEN"];
        assert_eq!(cred.scopes, vec!["read:org", "admin:org"]);
    }

    #[test]
    fn multiple_credentials() {
        let yaml = r#"
id: MULTI-CRED
name: Multi Cred
steps: []
assertions: []
credentials:
  GITHUB_TOKEN:
    type: api_token
    required: true
  AWS_ACCESS_KEY:
    type: env
    required: false
"#;
        let def: CheckDefinition = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(def.credentials.len(), 2);
        assert!(def.credentials["GITHUB_TOKEN"].required);
        assert!(!def.credentials["AWS_ACCESS_KEY"].required);
    }

    // ── Input definitions ────────────────────────────────────────────────────

    #[test]
    fn input_def_parsed() {
        let def: CheckDefinition = serde_yaml::from_str(PASSIVE_CHECK).unwrap();
        assert!(def.inputs.contains_key("org"));
        let input = &def.inputs["org"];
        assert_eq!(input.description, "GitHub organization name");
        assert_eq!(input.env, "GITHUB_ORG");
        assert!(input.required);
    }

    #[test]
    fn input_with_default_value() {
        let yaml = r#"
id: INPUT-DEFAULT
name: Input Default
steps: []
assertions: []
inputs:
  branch:
    description: Branch name
    env: BRANCH
    default: main
    required: false
"#;
        let def: CheckDefinition = serde_yaml::from_str(yaml).unwrap();
        let input = &def.inputs["branch"];
        assert_eq!(input.default, "main");
        assert!(!input.required);
    }

    // ── Steps ────────────────────────────────────────────────────────────────

    #[test]
    fn step_default_action_is_api_call() {
        let yaml = r#"
id: STEP-DEF
name: Step Default
steps:
  - id: s1
    request:
      method: GET
      url: "https://example.com"
assertions: []
"#;
        let def: CheckDefinition = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(def.steps[0].action, "api_call");
    }

    #[test]
    fn step_with_when_guard() {
        let yaml = r#"
id: WHEN-1
name: When Guard
steps:
  - id: conditional
    when: "status_code == 200"
    request:
      method: POST
      url: "https://example.com/cleanup"
assertions: []
"#;
        let def: CheckDefinition = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(def.steps[0].when, "status_code == 200");
    }

    #[test]
    fn step_with_on_error() {
        let yaml = r#"
id: ERR-1
name: Error Handler
steps:
  - id: create
    request:
      method: POST
      url: "https://example.com"
    on_error:
      "422": continue
      "500": abort
assertions: []
"#;
        let def: CheckDefinition = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(def.steps[0].on_error["422"], "continue");
        assert_eq!(def.steps[0].on_error["500"], "abort");
    }

    #[test]
    fn step_with_body() {
        let yaml = r#"
id: BODY-1
name: Body Test
steps:
  - id: post_data
    request:
      method: POST
      url: "https://example.com"
      body:
        key: value
        nested:
          inner: true
assertions: []
"#;
        let def: CheckDefinition = serde_yaml::from_str(yaml).unwrap();
        let body = def.steps[0].request.body.as_ref().unwrap();
        assert_eq!(body["key"], "value");
        assert_eq!(body["nested"]["inner"], true);
    }

    #[test]
    fn step_with_paginate() {
        let yaml = r#"
id: PAGE-1
name: Paginate Test
steps:
  - id: list
    request:
      method: GET
      url: "https://api.github.com/orgs/acme/repos"
      paginate: true
assertions: []
"#;
        let def: CheckDefinition = serde_yaml::from_str(yaml).unwrap();
        assert!(def.steps[0].request.paginate);
    }

    #[test]
    fn step_note_field() {
        let yaml = r#"
id: NOTE-1
name: Note Test
steps:
  - id: s1
    note: "This step fetches org settings"
    request:
      method: GET
      url: "https://example.com"
assertions: []
"#;
        let def: CheckDefinition = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(def.steps[0].note, "This step fetches org settings");
    }

    // ── Assertions ───────────────────────────────────────────────────────────

    #[test]
    fn assertion_default_severity_is_medium() {
        let yaml = r#"
id: ASEV-1
name: Default Severity
steps: []
assertions:
  - id: a1
    expr: "x == true"
"#;
        let def: CheckDefinition = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(def.assertions[0].severity, "medium");
    }

    #[test]
    fn assertion_with_finding_def() {
        let yaml = r#"
id: FIND-1
name: Finding Test
steps: []
assertions:
  - id: a1
    expr: "x == true"
    finding:
      description: "Detailed finding description"
"#;
        let def: CheckDefinition = serde_yaml::from_str(yaml).unwrap();
        let finding = def.assertions[0].finding.as_ref().unwrap();
        assert_eq!(finding.description, "Detailed finding description");
    }

    #[test]
    fn multiple_assertions() {
        let yaml = r#"
id: MULTI-A
name: Multi Assert
steps: []
assertions:
  - id: a1
    expr: "x == true"
    severity: critical
  - id: a2
    expr: "y > 0"
    severity: high
  - id: a3
    expr: "z != null"
    severity: low
"#;
        let def: CheckDefinition = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(def.assertions.len(), 3);
        assert_eq!(def.assertions[0].id, "a1");
        assert_eq!(def.assertions[1].id, "a2");
        assert_eq!(def.assertions[2].id, "a3");
    }

    // ── Remediation blocks ───────────────────────────────────────────────────

    #[test]
    fn remediation_with_api() {
        let yaml = r#"
id: REM-API
name: Remediation API
steps: []
assertions: []
remediation:
  description: "Enable MFA"
  steps:
    - "Navigate to settings"
  api:
    method: PATCH
    url: "https://api.github.com/orgs/{{org}}"
    headers:
      Authorization: "Bearer {{GITHUB_TOKEN}}"
    body:
      two_factor_requirement_enabled: true
"#;
        let def: CheckDefinition = serde_yaml::from_str(yaml).unwrap();
        let rem = def.remediation.as_ref().unwrap();
        assert_eq!(rem.description, "Enable MFA");
        assert_eq!(rem.steps.len(), 1);
        let api = rem.api.as_ref().unwrap();
        assert_eq!(api.method, "PATCH");
        assert!(api.url.contains("orgs"));
        assert!(api.headers.contains_key("Authorization"));
        assert!(api.body.is_some());
    }

    #[test]
    fn remediation_with_cli() {
        let yaml = r#"
id: REM-CLI
name: Remediation CLI
steps: []
assertions: []
remediation:
  description: "Fix via CLI"
  cli:
    command: "gh api orgs/{{org}} -X PATCH -f two_factor_requirement_enabled=true"
"#;
        let def: CheckDefinition = serde_yaml::from_str(yaml).unwrap();
        let cli = def.remediation.as_ref().unwrap().cli.as_ref().unwrap();
        assert!(cli.command.contains("gh api"));
    }

    #[test]
    fn remediation_with_terraform() {
        let yaml = r#"
id: REM-TF
name: Remediation Terraform
steps: []
assertions: []
remediation:
  description: "Fix via Terraform"
  terraform:
    resources:
      - type: github_organization_settings
        name: org_settings
        attributes:
          two_factor_requirement_enabled: true
"#;
        let def: CheckDefinition = serde_yaml::from_str(yaml).unwrap();
        let tf = def.remediation.as_ref().unwrap().terraform.as_ref().unwrap();
        assert_eq!(tf.resources.len(), 1);
    }

    #[test]
    fn remediation_with_manual_steps() {
        let yaml = r#"
id: REM-MANUAL
name: Manual Remediation
steps: []
assertions: []
remediation:
  description: "Manual fix"
  manual:
    - "Go to admin console"
    - "Enable MFA requirement"
    - "Notify all users"
"#;
        let def: CheckDefinition = serde_yaml::from_str(yaml).unwrap();
        let rem = def.remediation.as_ref().unwrap();
        assert_eq!(rem.manual.len(), 3);
    }

    // ── References edge cases ────────────────────────────────────────────────

    #[test]
    fn references_all_frameworks() {
        let yaml = r#"
id: REF-ALL
name: All Refs
steps: []
assertions: []
references:
  cis: "1.1"
  nist: ["IA-2(1)", "IA-2(2)"]
  soc2: CC6.1
  iso27001: "A.9.4.2"
  pci_dss: ["8.3", "8.3.1"]
  disa_stig: "V-123456"
"#;
        let def: CheckDefinition = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(def.references.cis.as_vec(), vec!["1.1"]);
        assert_eq!(def.references.nist.as_vec(), vec!["IA-2(1)", "IA-2(2)"]);
        assert_eq!(def.references.soc2.as_vec(), vec!["CC6.1"]);
        assert_eq!(def.references.iso27001.as_vec(), vec!["A.9.4.2"]);
        assert_eq!(def.references.pci_dss.as_vec(), vec!["8.3", "8.3.1"]);
        assert_eq!(def.references.disa_stig.as_vec(), vec!["V-123456"]);
    }

    #[test]
    fn references_empty_default() {
        let def: CheckDefinition = serde_yaml::from_str(MINIMAL_CHECK).unwrap();
        assert!(def.references.cis.as_vec().is_empty());
        assert!(def.references.nist.as_vec().is_empty());
        assert!(def.references.soc2.as_vec().is_empty());
        assert!(def.references.iso27001.as_vec().is_empty());
        assert!(def.references.pci_dss.as_vec().is_empty());
        assert!(def.references.disa_stig.as_vec().is_empty());
    }

    // ── Tags ─────────────────────────────────────────────────────────────────

    #[test]
    fn tags_parsed() {
        let yaml = r#"
id: TAG-1
name: Tags Test
steps: []
assertions: []
tags:
  - auth
  - mfa
  - github
"#;
        let def: CheckDefinition = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(def.tags, vec!["auth", "mfa", "github"]);
    }

    // ── Metadata fields ──────────────────────────────────────────────────────

    #[test]
    fn all_metadata_fields() {
        let yaml = r#"
id: META-1
name: Metadata Test
description: Full metadata check
author: qa-bot
version: "3.0"
source: aws
type: active
safety: reversible
environment: production
severity: critical
profile: L3
steps: []
assertions: []
"#;
        let def: CheckDefinition = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(def.id, "META-1");
        assert_eq!(def.description, "Full metadata check");
        assert_eq!(def.author, "qa-bot");
        assert_eq!(def.version, "3.0");
        assert_eq!(def.source, "aws");
        assert_eq!(def.check_type, CheckType::Active);
        assert_eq!(def.safety, "reversible");
        assert_eq!(def.environment, "production");
        assert_eq!(def.severity, "critical");
        assert_eq!(def.profile, "L3");
    }

    // ── Native implementation ────────────────────────────────────────────────

    #[test]
    fn native_implementation_fields() {
        let yaml = r#"
id: NAT-1
name: Native Module
source: github
implementation: native
native_module: github_secret_push
steps: []
assertions: []
"#;
        let def: CheckDefinition = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(def.implementation, "native");
        assert_eq!(def.native_module, "github_secret_push");
    }

    // ── Pre-flight ───────────────────────────────────────────────────────────

    #[test]
    fn pre_flight_checks_parsed() {
        let yaml = r#"
id: PF-1
name: Pre-flight
type: active
steps: []
assertions: []
pre_flight:
  - "Ensure admin:org scope on token"
  - "Verify org membership"
"#;
        let def: CheckDefinition = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(def.pre_flight.len(), 2);
        assert!(def.pre_flight[0].contains("admin:org"));
    }

    // ── CheckType equality ───────────────────────────────────────────────────

    #[test]
    fn check_type_equality() {
        assert_eq!(CheckType::Passive, CheckType::Passive);
        assert_eq!(CheckType::Active, CheckType::Active);
        assert_ne!(CheckType::Passive, CheckType::Active);
    }

    // ── StringOrVec PartialEq via as_vec ─────────────────────────────────────

    #[test]
    fn string_or_vec_one_round_trip() {
        let yaml = "cis: \"1.1\"";
        let refs: CheckReferences = serde_yaml::from_str(&format!(
            "{yaml}\nnist: []\nsoc2: []\niso27001: []\npci_dss: []\ndisa_stig: []"
        ))
        .unwrap();
        let out = serde_yaml::to_string(&refs).unwrap();
        let refs2: CheckReferences = serde_yaml::from_str(&out).unwrap();
        assert_eq!(refs.cis.as_vec(), refs2.cis.as_vec());
    }

    // ── Multiple steps with extract ──────────────────────────────────────────

    #[test]
    fn multiple_steps_with_extracts() {
        let yaml = r#"
id: MULTI-STEP
name: Multi Step
steps:
  - id: step1
    request:
      method: GET
      url: "https://example.com/orgs/acme"
    extract:
      org_id: "$.id"
      org_name: "$.login"
  - id: step2
    request:
      method: GET
      url: "https://example.com/orgs/acme/members"
    extract:
      member_count: "$length"
assertions:
  - id: has_members
    expr: "member_count > 0"
"#;
        let def: CheckDefinition = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(def.steps.len(), 2);
        assert_eq!(def.steps[0].extract.len(), 2);
        assert_eq!(def.steps[1].extract.len(), 1);
        assert_eq!(def.steps[1].extract["member_count"], "$length");
    }

    // ── Request headers ──────────────────────────────────────────────────────

    #[test]
    fn request_headers_parsed() {
        let yaml = r#"
id: HDR-1
name: Headers
steps:
  - id: s1
    request:
      method: GET
      url: "https://example.com"
      headers:
        Authorization: "Bearer {{token}}"
        Accept: "application/vnd.github+json"
        X-Custom: "value"
assertions: []
"#;
        let def: CheckDefinition = serde_yaml::from_str(yaml).unwrap();
        let headers = &def.steps[0].request.headers;
        assert_eq!(headers.len(), 3);
        assert!(headers.contains_key("Authorization"));
        assert!(headers.contains_key("Accept"));
        assert!(headers.contains_key("X-Custom"));
    }
}
