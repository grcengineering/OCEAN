// SARIF 2.1.0 output for OCEAN check results.
//
// Produces Static Analysis Results Interchange Format (SARIF) v2.1.0 JSON,
// compatible with GitHub Code Scanning, VS Code SARIF Viewer, and other
// SARIF-consuming tools.

use anyhow::Result;
use serde::Serialize;
use std::io::Write;

use crate::check::definition::CheckDefinition;

// ─── SARIF schema types ──────────────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifLog {
    #[serde(rename = "$schema")]
    pub schema: &'static str,
    pub version: &'static str,
    pub runs: Vec<SarifRun>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifDriver {
    pub name: String,
    pub version: String,
    pub information_uri: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<SarifRule>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRule {
    pub id: String,
    pub name: String,
    pub short_description: SarifMessage,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_description: Option<SarifMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help: Option<SarifMessage>,
    pub default_configuration: SarifRuleConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<SarifRuleProperties>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifMessage {
    pub text: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRuleConfig {
    pub level: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRuleProperties {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_severity: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifResult {
    pub rule_id: String,
    pub level: String,
    pub message: SarifMessage,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub locations: Vec<SarifLocation>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifLocation {
    pub physical_location: SarifPhysicalLocation,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifPhysicalLocation {
    pub artifact_location: SarifArtifactLocation,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifArtifactLocation {
    pub uri: String,
}

// ─── Severity mapping ────────────────────────────────────────────────────────

fn ocean_severity_to_sarif_level(severity: &str) -> &'static str {
    match severity.to_lowercase().as_str() {
        "critical" | "high" => "error",
        "medium" => "warning",
        "low" | "info" => "note",
        _ => "warning",
    }
}

fn ocean_severity_to_score(severity: &str) -> &'static str {
    match severity.to_lowercase().as_str() {
        "critical" => "9.0",
        "high" => "7.0",
        "medium" => "5.0",
        "low" => "3.0",
        "info" => "1.0",
        _ => "5.0",
    }
}

// ─── Check result for SARIF conversion ───────────────────────────────────────

/// A single check execution result, ready for SARIF conversion.
pub struct CheckResult {
    pub check_id: String,
    pub check_name: String,
    pub description: String,
    pub severity: String,
    pub tags: Vec<String>,
    /// "PASS", "FAIL", or "ERROR"
    pub status: String,
    pub message: String,
    pub source: String,
}

// ─── SARIF generation ────────────────────────────────────────────────────────

/// Build a SARIF log from check definitions and their execution results.
pub fn build_sarif(defs: &[CheckDefinition], results: &[CheckResult]) -> SarifLog {
    let rules: Vec<SarifRule> = defs
        .iter()
        .map(|def| {
            let severity = effective_severity(def);
            SarifRule {
                id: def.id.clone(),
                name: def.name.clone(),
                short_description: SarifMessage {
                    text: def.name.clone(),
                },
                full_description: if def.description.is_empty() {
                    None
                } else {
                    Some(SarifMessage {
                        text: def.description.clone(),
                    })
                },
                help: if def.description.is_empty() {
                    None
                } else {
                    Some(SarifMessage {
                        text: def.description.clone(),
                    })
                },
                default_configuration: SarifRuleConfig {
                    level: ocean_severity_to_sarif_level(&severity).to_string(),
                },
                properties: Some(SarifRuleProperties {
                    tags: def.tags.clone(),
                    security_severity: Some(ocean_severity_to_score(&severity).to_string()),
                }),
            }
        })
        .collect();

    let sarif_results: Vec<SarifResult> = results
        .iter()
        .filter(|r| r.status != "PASS")
        .map(|r| SarifResult {
            rule_id: r.check_id.clone(),
            level: ocean_severity_to_sarif_level(&r.severity).to_string(),
            message: SarifMessage {
                text: r.message.clone(),
            },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: format!("ocean://{}/{}", r.source, r.check_id),
                    },
                },
            }],
        })
        .collect();

    SarifLog {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        version: "2.1.0",
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "OCEAN".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    information_uri: "https://grc.engineering".to_string(),
                    rules,
                },
            },
            results: sarif_results,
        }],
    }
}

/// Write SARIF JSON to a writer.
pub fn write_sarif<W: Write>(w: &mut W, sarif: &SarifLog) -> Result<()> {
    let json = serde_json::to_string_pretty(sarif)?;
    writeln!(w, "{json}")?;
    Ok(())
}

/// Determine effective severity: assertion-level first, then top-level fallback.
fn effective_severity(def: &CheckDefinition) -> String {
    if let Some(a) = def.assertions.first() {
        if !a.severity.is_empty() {
            return a.severity.clone();
        }
    }
    if !def.severity.is_empty() {
        return def.severity.clone();
    }
    "medium".to_string()
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_def() -> CheckDefinition {
        serde_yaml::from_str(
            r#"
id: GH-1.01
name: Org MFA Enforcement
description: Verifies MFA is required for all organization members
source: github
profile: L1
tags: [mfa, identity]
steps: []
assertions:
  - id: mfa_enforced
    expr: "mfa == true"
    severity: critical
"#,
        )
        .unwrap()
    }

    #[test]
    fn sarif_log_has_correct_version() {
        let def = sample_def();
        let results = vec![CheckResult {
            check_id: "GH-1.01".into(),
            check_name: "Org MFA Enforcement".into(),
            description: "test".into(),
            severity: "critical".into(),
            tags: vec!["mfa".into()],
            status: "FAIL".into(),
            message: "MFA is not enforced".into(),
            source: "github".into(),
        }];
        let sarif = build_sarif(&[def], &results);
        assert_eq!(sarif.version, "2.1.0");
        assert_eq!(sarif.runs.len(), 1);
        assert_eq!(sarif.runs[0].results.len(), 1);
        assert_eq!(sarif.runs[0].results[0].level, "error");
    }

    #[test]
    fn passing_checks_excluded_from_results() {
        let def = sample_def();
        let results = vec![CheckResult {
            check_id: "GH-1.01".into(),
            check_name: "Org MFA".into(),
            description: "test".into(),
            severity: "critical".into(),
            tags: vec![],
            status: "PASS".into(),
            message: "MFA is enforced".into(),
            source: "github".into(),
        }];
        let sarif = build_sarif(&[def], &results);
        assert!(sarif.runs[0].results.is_empty());
    }

    #[test]
    fn severity_mapping() {
        assert_eq!(ocean_severity_to_sarif_level("critical"), "error");
        assert_eq!(ocean_severity_to_sarif_level("high"), "error");
        assert_eq!(ocean_severity_to_sarif_level("medium"), "warning");
        assert_eq!(ocean_severity_to_sarif_level("low"), "note");
        assert_eq!(ocean_severity_to_sarif_level("info"), "note");
    }

    #[test]
    fn severity_mapping_unknown_falls_back_to_warning() {
        assert_eq!(ocean_severity_to_sarif_level("anything-else"), "warning");
        assert_eq!(ocean_severity_to_sarif_level(""), "warning");
    }

    #[test]
    fn severity_to_score_full_mapping() {
        assert_eq!(ocean_severity_to_score("critical"), "9.0");
        assert_eq!(ocean_severity_to_score("high"), "7.0");
        assert_eq!(ocean_severity_to_score("medium"), "5.0");
        assert_eq!(ocean_severity_to_score("low"), "3.0");
        assert_eq!(ocean_severity_to_score("info"), "1.0");
        assert_eq!(ocean_severity_to_score("anything-else"), "5.0");
    }

    #[test]
    fn build_sarif_with_empty_description_omits_full_description_and_help() {
        let mut def = sample_def();
        def.description = String::new();
        let sarif = build_sarif(&[def], &[]);
        let rule = &sarif.runs[0].tool.driver.rules[0];
        assert!(rule.full_description.is_none());
        assert!(rule.help.is_none());
    }

    #[test]
    fn write_sarif_produces_valid_json() {
        let def = sample_def();
        let sarif = build_sarif(&[def], &[]);
        let mut buf = Vec::new();
        write_sarif(&mut buf, &sarif).unwrap();
        let s = String::from_utf8(buf).unwrap();
        let _: serde_json::Value = serde_json::from_str(&s).unwrap();
    }

    #[test]
    fn write_sarif_fault_injection() {
        use crate::testutil::FailingWriter;
        let def = sample_def();
        let sarif = build_sarif(&[def], &[]);
        for n in 0..5 {
            let mut w = FailingWriter::new(n);
            let _ = write_sarif(&mut w, &sarif);
        }
    }

    #[test]
    fn effective_severity_prefers_assertion() {
        let def = sample_def();
        assert_eq!(effective_severity(&def), "critical");
    }

    #[test]
    fn effective_severity_falls_back_to_top_level() {
        let def: CheckDefinition = serde_yaml::from_str(
            r#"
id: AWS-IAM-1.01
name: Root Account MFA
source: aws
severity: critical
implementation: native
native_module: aws_iam
"#,
        )
        .unwrap();
        assert_eq!(effective_severity(&def), "critical");
    }
}
