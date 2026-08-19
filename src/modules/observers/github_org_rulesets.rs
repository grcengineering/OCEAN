use std::collections::HashMap;

use anyhow::{anyhow, Result};
use chrono::Utc;
use uuid::Uuid;

use crate::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId,
};
use crate::module::{observer::Observer, CredentialReq, Module};
use crate::modules::github_common::{github_get, DEFAULT_GITHUB_API};

// ─── OrgRulesetsObserver ──────────────────────────────────────────────────────

/// Queries the GitHub organization rulesets API to determine whether branch
/// rulesets are configured and whether deletion protection is enabled.
///
/// Required config: `GITHUB_TOKEN`, `GITHUB_ORG`.
/// Optional: `GITHUB_API_URL` (test override).
pub struct OrgRulesetsObserver;

impl Module for OrgRulesetsObserver {
    fn id(&self) -> &str {
        "github.org_rulesets"
    }
    fn name(&self) -> &str {
        "GitHub Org Rulesets Observer"
    }
    fn version(&self) -> &str {
        "0.1.0"
    }
    fn source_system(&self) -> &str {
        "github"
    }
    fn evidence_types(&self) -> &[i32] {
        &[1003]
    }

    fn credential_requirements(&self) -> Vec<CredentialReq> {
        vec![
            CredentialReq {
                name: "GITHUB_TOKEN".to_string(),
                cred_type: "api_token".to_string(),
                description: "GitHub PAT with admin:org scope for reading org rulesets".to_string(),
                required: true,
            },
            CredentialReq {
                name: "GITHUB_ORG".to_string(),
                cred_type: "config".to_string(),
                description: "GitHub organization name".to_string(),
                required: true,
            },
        ]
    }
}

impl Observer for OrgRulesetsObserver {
    fn observe(&self, config: &HashMap<String, String>) -> Result<Vec<Evidence>> {
        let token = config
            .get("GITHUB_TOKEN")
            .ok_or_else(|| anyhow!("GITHUB_TOKEN is required"))?;
        let org = config
            .get("GITHUB_ORG")
            .ok_or_else(|| anyhow!("GITHUB_ORG is required"))?;
        let base_url = config
            .get("GITHUB_API_URL")
            .map(|s| s.as_str())
            .unwrap_or(DEFAULT_GITHUB_API);

        let now = Utc::now();
        let path = format!("/orgs/{}/rulesets", org);
        let endpoint = format!("{}{}", base_url.trim_end_matches('/'), path);

        let (body, status) = github_get(token, base_url, &path)?;

        // 404 means rulesets feature not enabled for the org.
        if status == 404 {
            return Ok(vec![Evidence {
                id: Uuid::new_v4(),
                control_id: "GH-2.3".to_string(),
                class_uid: 1003,
                category_uid: 2,
                activity_id: 1,
                time: now,
                confidence_level: ConfidenceLevel::PassiveObservation,
                metadata: Metadata {
                    module: ModuleInfo {
                        name: "github.org_rulesets".to_string(),
                        version: "0.1.0".to_string(),
                        module_type: "observer".to_string(),
                    },
                    source: SourceInfo {
                        system: "github".to_string(),
                        api_version: "v3".to_string(),
                        endpoint: endpoint.clone(),
                    },
                    original_time: None,
                    processed_time: now,
                    safety_classification: None,
                },
                observables: vec![
                    Observable {
                        obs_type: "resource".to_string(),
                        value: format!("{}:rulesets", org),
                        name: String::new(),
                    },
                    Observable {
                        obs_type: "domain".to_string(),
                        value: "github.com".to_string(),
                        name: String::new(),
                    },
                ],
                status_id: StatusId::Ineffective,
                status: format!("Org rulesets feature not available for {}", org),
                raw_data: serde_json::json!({
                    "ruleset_count": 0,
                    "active_rulesets": 0,
                    "deletion_protected": false
                }),
                findings: vec![Finding {
                    title: "Org Rulesets Not Available".to_string(),
                    description: format!(
                        "The organization {} does not have access to the rulesets API (404). \
                         Branch rulesets may not be enabled.",
                        org
                    ),
                    severity_id: 3,
                }],
                test_transcript: None,
                enrichments: vec![],
            }]);
        }

        if status != 200 {
            return Err(anyhow!(
                "GitHub API returned status {} for {}",
                status,
                path
            ));
        }

        let rulesets = body
            .as_array()
            .ok_or_else(|| anyhow!("Expected JSON array from org rulesets API"))?;

        let ruleset_count = rulesets.len();
        let active_rulesets = rulesets
            .iter()
            .filter(|r| r.get("enforcement").and_then(|v| v.as_str()) == Some("active"))
            .count();

        let deletion_protected = rulesets.iter().any(|r| {
            r.get("enforcement").and_then(|v| v.as_str()) == Some("active")
                && r.get("rules")
                    .and_then(|v| v.as_array())
                    .map(|rules| {
                        rules.iter().any(|rule| {
                            rule.get("type").and_then(|t| t.as_str()) == Some("deletion")
                        })
                    })
                    .unwrap_or(false)
        });

        let mut findings: Vec<Finding> = Vec::new();
        let status_id;

        if active_rulesets >= 1 && deletion_protected {
            status_id = StatusId::Effective;
            findings.push(Finding {
                title: "Org Rulesets Configured with Deletion Protection".to_string(),
                description: format!(
                    "Organization {} has {} active ruleset(s) including deletion protection.",
                    org, active_rulesets
                ),
                severity_id: 0,
            });
        } else {
            status_id = StatusId::Ineffective;
            if active_rulesets == 0 {
                findings.push(Finding {
                    title: "No Active Org Rulesets".to_string(),
                    description: format!(
                        "Organization {} has no active rulesets configured. \
                         Branch protection rules are not enforced at the org level.",
                        org
                    ),
                    severity_id: 3,
                });
            } else {
                findings.push(Finding {
                    title: "Org Rulesets Missing Deletion Protection".to_string(),
                    description: format!(
                        "Organization {} has {} active ruleset(s) but none include deletion \
                         protection (GH-2.5).",
                        org, active_rulesets
                    ),
                    severity_id: 3,
                });
            }
        }

        let status_msg = if status_id == StatusId::Effective {
            format!(
                "Org rulesets with deletion protection configured for {}",
                org
            )
        } else {
            format!("Org rulesets not adequately configured for {}", org)
        };

        Ok(vec![Evidence {
            id: Uuid::new_v4(),
            control_id: "GH-2.3".to_string(),
            class_uid: 1003,
            category_uid: 2,
            activity_id: 1,
            time: now,
            confidence_level: ConfidenceLevel::PassiveObservation,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "github.org_rulesets".to_string(),
                    version: "0.1.0".to_string(),
                    module_type: "observer".to_string(),
                },
                source: SourceInfo {
                    system: "github".to_string(),
                    api_version: "v3".to_string(),
                    endpoint,
                },
                original_time: None,
                processed_time: now,
                safety_classification: None,
            },
            observables: vec![
                Observable {
                    obs_type: "resource".to_string(),
                    value: format!("{}:rulesets", org),
                    name: String::new(),
                },
                Observable {
                    obs_type: "domain".to_string(),
                    value: "github.com".to_string(),
                    name: String::new(),
                },
            ],
            status_id,
            status: status_msg,
            raw_data: serde_json::json!({
                "ruleset_count": ruleset_count,
                "active_rulesets": active_rulesets,
                "deletion_protected": deletion_protected
            }),
            findings,
            test_transcript: None,
            enrichments: vec![],
        }])
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::github_common::{mock_server, test_config_with_org};

    #[test]
    fn org_rulesets_active_with_deletion_is_effective() {
        let srv = mock_server(
            200,
            r#"[{"id":1,"enforcement":"active","rules":[{"type":"deletion"}]}]"#,
        );
        let ev = &OrgRulesetsObserver
            .observe(&test_config_with_org(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert_eq!(ev.raw_data["active_rulesets"], 1);
        assert_eq!(ev.raw_data["deletion_protected"], true);
    }

    #[test]
    fn org_rulesets_no_rulesets_is_ineffective() {
        let srv = mock_server(200, r#"[]"#);
        let ev = &OrgRulesetsObserver
            .observe(&test_config_with_org(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert_eq!(ev.raw_data["active_rulesets"], 0);
        assert_eq!(ev.raw_data["deletion_protected"], false);
    }

    #[test]
    fn org_rulesets_404_is_ineffective_with_finding() {
        let srv = mock_server(404, r#"{"message":"Not Found"}"#);
        let ev = &OrgRulesetsObserver
            .observe(&test_config_with_org(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "Org Rulesets Not Available"));
    }

    #[test]
    fn org_rulesets_500_returns_err() {
        let srv = mock_server(500, r#"{"message":"Internal Server Error"}"#);
        let result = OrgRulesetsObserver.observe(&test_config_with_org(&srv));
        assert!(result.is_err());
    }

    #[test]
    fn org_rulesets_active_without_deletion_is_ineffective() {
        let srv = mock_server(
            200,
            r#"[{"id":1,"enforcement":"active","rules":[{"type":"required_status_checks"}]}]"#,
        );
        let ev = &OrgRulesetsObserver
            .observe(&test_config_with_org(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "Org Rulesets Missing Deletion Protection"));
    }

    #[test]
    fn org_rulesets_evidence_types() {
        assert_eq!(OrgRulesetsObserver.evidence_types(), &[1003]);
    }

    #[test]
    fn org_rulesets_credential_requirements() {
        let reqs = OrgRulesetsObserver.credential_requirements();
        assert_eq!(reqs.len(), 2);
        assert!(reqs.iter().any(|r| r.name == "GITHUB_TOKEN" && r.required));
        assert!(reqs.iter().any(|r| r.name == "GITHUB_ORG" && r.required));
    }

    #[test]
    fn org_rulesets_missing_token_errors() {
        let err = OrgRulesetsObserver
            .observe(&HashMap::from([(
                "GITHUB_ORG".to_string(),
                "org".to_string(),
            )]))
            .unwrap_err();
        assert!(err.to_string().contains("GITHUB_TOKEN"));
    }

    #[test]
    fn org_rulesets_missing_org_errors() {
        let err = OrgRulesetsObserver
            .observe(&HashMap::from([(
                "GITHUB_TOKEN".to_string(),
                "tok".to_string(),
            )]))
            .unwrap_err();
        assert!(err.to_string().contains("GITHUB_ORG"));
    }

    #[test]
    fn org_rulesets_connection_refused_errors() {
        let mut cfg = test_config_with_org("placeholder");
        cfg.insert(
            "GITHUB_API_URL".to_string(),
            "http://127.0.0.1:1".to_string(),
        );
        let result = OrgRulesetsObserver.observe(&cfg);
        assert!(result.is_err());
    }

    #[test]
    fn org_rulesets_non_array_response_errors() {
        let srv = mock_server(200, r#""not an array""#);
        let result = OrgRulesetsObserver.observe(&test_config_with_org(&srv));
        assert!(result.is_err());
    }

    #[test]
    fn metadata_complete() {
        use crate::module::Module;
        let obs = OrgRulesetsObserver;
        assert_eq!(obs.id(), "github.org_rulesets");
        assert!(!obs.name().is_empty());
        assert_eq!(obs.version(), "0.1.0");
        assert_eq!(obs.source_system(), "github");
        assert!(!obs.evidence_types().is_empty());
        let creds = obs.credential_requirements();
        assert!(!creds.is_empty());
    }
}
