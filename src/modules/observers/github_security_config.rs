use std::collections::HashMap;

use anyhow::{anyhow, Result};
use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

use crate::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId,
};
use crate::module::{observer::Observer, CredentialReq, Module};
use crate::modules::github_common::{github_get, DEFAULT_GITHUB_API};

// ─── SecurityConfigObserver ───────────────────────────────────────────────────

/// Checks whether code security configurations have been defined for the
/// organization (GH-8.3). Requires GitHub Enterprise Cloud or GHAS. Returns
/// unknown if the endpoint is unavailable due to plan limitations.
///
/// Required config: `GITHUB_TOKEN`, `GITHUB_ORG`.
/// Optional: `GITHUB_API_URL` (test override).
pub struct SecurityConfigObserver;

impl Module for SecurityConfigObserver {
    fn id(&self) -> &str {
        "github.security_config"
    }
    fn name(&self) -> &str {
        "GitHub Security Configuration Observer"
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
                description: "GitHub PAT with admin:org scope for reading security configurations"
                    .to_string(),
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

impl Observer for SecurityConfigObserver {
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
        let path = format!("/orgs/{}/code-security/configurations", org);
        let endpoint = format!("{}{}", base_url.trim_end_matches('/'), path);

        let (body, status) = github_get(token, base_url, &path)?;

        let (status_id, raw_data, findings) = match status {
            200 => {
                let config_count = body.as_array().map(|a| a.len()).unwrap_or(0);
                let raw = json!({ "config_count": config_count });

                if config_count >= 1 {
                    (
                        StatusId::Effective,
                        raw,
                        vec![Finding {
                            title: "Security Configurations Present".to_string(),
                            description: format!(
                                "Organization {} has {} code security configuration(s) defined, \
                                 indicating an org-wide security posture is being enforced (GH-8.3).",
                                org, config_count
                            ),
                            severity_id: 0,
                        }],
                    )
                } else {
                    (
                        StatusId::Ineffective,
                        raw,
                        vec![Finding {
                            title: "No Security Configurations".to_string(),
                            description: format!(
                                "Organization {} has no code security configurations defined. \
                                 Create and apply security configurations to enforce a consistent \
                                 security posture across repositories (GH-8.3).",
                                org
                            ),
                            severity_id: 2,
                        }],
                    )
                }
            }
            404 | 403 => {
                let raw = json!({ "config_count": 0 });
                (
                    StatusId::Unknown,
                    raw,
                    vec![Finding {
                        title: "Security Configuration Check Unavailable".to_string(),
                        description: format!(
                            "Organization {} returned HTTP {} for code security configurations. \
                             This feature requires GitHub Enterprise Cloud or GHAS. \
                             Upgrade to access org security configuration enforcement (GH-8.3).",
                            org, status
                        ),
                        severity_id: 1,
                    }],
                )
            }
            _ => {
                return Err(anyhow!(
                    "GitHub API returned unexpected status {} for {}",
                    status,
                    path
                ));
            }
        };

        let status_msg = match status_id {
            StatusId::Effective => {
                format!(
                    "Security configurations are defined for organization {}",
                    org
                )
            }
            StatusId::Ineffective => {
                format!("No security configurations found for organization {}", org)
            }
            _ => format!(
                "Security configuration check unavailable for organization {} (GHEC/GHAS required)",
                org
            ),
        };

        Ok(vec![Evidence {
            id: Uuid::new_v4(),
            control_id: "GH-8.3".to_string(),
            class_uid: 1003,
            category_uid: 2,
            activity_id: 1,
            time: now,
            confidence_level: ConfidenceLevel::PassiveObservation,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "github.security_config".to_string(),
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
                    value: format!("{}:security_config", org),
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
            raw_data,
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
    fn one_config_is_effective() {
        let srv = mock_server(
            200,
            r#"[{"id":1,"name":"Default Security Policy","target_type":"all"}]"#,
        );
        let ev = &SecurityConfigObserver
            .observe(&test_config_with_org(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "Security Configurations Present"));
        assert_eq!(ev.raw_data["config_count"], 1);
    }

    #[test]
    fn empty_configs_is_ineffective() {
        let srv = mock_server(200, r#"[]"#);
        let ev = &SecurityConfigObserver
            .observe(&test_config_with_org(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "No Security Configurations"));
    }

    #[test]
    fn security_config_404_is_unknown() {
        let srv = mock_server(404, r#"{"message":"Not Found"}"#);
        let ev = &SecurityConfigObserver
            .observe(&test_config_with_org(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Unknown);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "Security Configuration Check Unavailable"));
    }

    #[test]
    fn security_config_unexpected_status_returns_err() {
        let srv = mock_server(500, r#"{"message":"Internal Server Error"}"#);
        let result = SecurityConfigObserver.observe(&test_config_with_org(&srv));
        assert!(result.is_err());
    }

    #[test]
    fn security_config_evidence_types() {
        assert_eq!(SecurityConfigObserver.evidence_types(), &[1003]);
    }

    #[test]
    fn security_config_credential_requirements() {
        let reqs = SecurityConfigObserver.credential_requirements();
        assert_eq!(reqs.len(), 2);
        assert!(reqs.iter().any(|r| r.name == "GITHUB_TOKEN" && r.required));
        assert!(reqs.iter().any(|r| r.name == "GITHUB_ORG" && r.required));
    }

    #[test]
    fn security_config_missing_token_errors() {
        let err = SecurityConfigObserver
            .observe(&HashMap::from([(
                "GITHUB_ORG".to_string(),
                "org".to_string(),
            )]))
            .unwrap_err();
        assert!(err.to_string().contains("GITHUB_TOKEN"));
    }

    #[test]
    fn security_config_missing_org_errors() {
        let err = SecurityConfigObserver
            .observe(&HashMap::from([(
                "GITHUB_TOKEN".to_string(),
                "tok".to_string(),
            )]))
            .unwrap_err();
        assert!(err.to_string().contains("GITHUB_ORG"));
    }
}
