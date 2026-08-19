use std::collections::HashMap;

use anyhow::{anyhow, Result};
use chrono::Utc;
use uuid::Uuid;

use crate::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId,
};
use crate::module::{observer::Observer, CredentialReq, Module};
use crate::modules::github_common::{github_get, DEFAULT_GITHUB_API};

// ─── DependabotAlertsObserver ───────────────────────────────────────────────

/// Queries the GitHub Dependabot Alerts API to gather evidence about
/// critical open dependency vulnerabilities in a repository.
///
/// Required config: `GITHUB_TOKEN`, `GITHUB_OWNER`, `GITHUB_REPO`.
/// Optional: `GITHUB_API_URL` (test override).
pub struct DependabotAlertsObserver;

impl Module for DependabotAlertsObserver {
    fn id(&self) -> &str {
        "github.dependabot_alerts"
    }
    fn name(&self) -> &str {
        "GitHub Dependabot Alerts Observer"
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
                description: "GitHub PAT with repo scope for reading Dependabot alerts".to_string(),
                required: true,
            },
            CredentialReq {
                name: "GITHUB_OWNER".to_string(),
                cred_type: "config".to_string(),
                description: "GitHub repository owner (user or organization)".to_string(),
                required: true,
            },
            CredentialReq {
                name: "GITHUB_REPO".to_string(),
                cred_type: "config".to_string(),
                description: "GitHub repository name".to_string(),
                required: true,
            },
        ]
    }
}

impl Observer for DependabotAlertsObserver {
    fn observe(&self, config: &HashMap<String, String>) -> Result<Vec<Evidence>> {
        let token = config
            .get("GITHUB_TOKEN")
            .ok_or_else(|| anyhow!("GITHUB_TOKEN is required"))?;
        let owner = config
            .get("GITHUB_OWNER")
            .ok_or_else(|| anyhow!("GITHUB_OWNER is required"))?;
        let repo = config
            .get("GITHUB_REPO")
            .ok_or_else(|| anyhow!("GITHUB_REPO is required"))?;
        let base_url = config
            .get("GITHUB_API_URL")
            .map(|s| s.as_str())
            .unwrap_or(DEFAULT_GITHUB_API);

        let now = Utc::now();
        let path = format!(
            "/repos/{}/{}/dependabot/alerts?state=open&severity=critical&per_page=1",
            owner, repo
        );
        let endpoint = format!("{}{}", base_url.trim_end_matches('/'), path);

        let (body, status) = github_get(token, base_url, &path)?;

        // 404 means Dependabot alerts are not enabled for the repository.
        if status == 404 {
            return Ok(vec![Evidence {
                id: Uuid::new_v4(),
                control_id: "scm.dependency_management".to_string(),
                class_uid: 1003,
                category_uid: 2,
                activity_id: 1,
                time: now,
                confidence_level: ConfidenceLevel::PassiveObservation,
                metadata: Metadata {
                    module: ModuleInfo {
                        name: "github.dependabot_alerts".to_string(),
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
                        value: format!("{}/{}:dependabot_alerts", owner, repo),
                        name: String::new(),
                    },
                    Observable {
                        obs_type: "domain".to_string(),
                        value: "github.com".to_string(),
                        name: String::new(),
                    },
                ],
                status_id: StatusId::Unknown,
                status: format!("Dependabot alerts not enabled on {}/{}", owner, repo),
                raw_data: body,
                findings: vec![Finding {
                    title: "Dependabot Alerts Not Enabled".to_string(),
                    description: "Dependabot alerts not enabled".to_string(),
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

        let alerts = body
            .as_array()
            .ok_or_else(|| anyhow!("Expected JSON array from Dependabot alerts API"))?;
        let alert_count = alerts.len();

        let (status_id, status_msg, findings) = if alert_count == 0 {
            (
                StatusId::Effective,
                format!("No critical open Dependabot alerts on {}/{}", owner, repo),
                vec![Finding {
                    title: "No Critical Dependabot Alerts".to_string(),
                    description: format!(
                        "No critical open Dependabot alerts found for {}/{}.",
                        owner, repo
                    ),
                    severity_id: 0,
                }],
            )
        } else {
            (
                StatusId::Ineffective,
                format!(
                    "{} critical open Dependabot alert(s) on {}/{}",
                    alert_count, owner, repo
                ),
                vec![Finding {
                    title: "Critical Dependabot Alerts Found".to_string(),
                    description: format!(
                        "{} critical open Dependabot alert(s) found for {}/{}.",
                        alert_count, owner, repo
                    ),
                    severity_id: 4,
                }],
            )
        };

        Ok(vec![Evidence {
            id: Uuid::new_v4(),
            control_id: "scm.dependency_management".to_string(),
            class_uid: 1003,
            category_uid: 2,
            activity_id: 1,
            time: now,
            confidence_level: ConfidenceLevel::PassiveObservation,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "github.dependabot_alerts".to_string(),
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
                    value: format!("{}/{}:dependabot_alerts", owner, repo),
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
            raw_data: body,
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
    use crate::modules::github_common::{mock_server, test_config};

    #[test]
    fn dependabot_no_alerts_is_effective() {
        let srv = mock_server(200, "[]");
        let ev = &DependabotAlertsObserver
            .observe(&test_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert_eq!(ev.findings[0].title, "No Critical Dependabot Alerts");
        assert_eq!(ev.control_id, "scm.dependency_management");
        assert_eq!(ev.class_uid, 1003);
        assert_eq!(ev.observables.len(), 2);
    }

    #[test]
    fn dependabot_has_alerts_is_ineffective() {
        let srv = mock_server(
            200,
            r#"[{"number":1,"state":"open","security_vulnerability":{"severity":"critical"}}]"#,
        );
        let ev = &DependabotAlertsObserver
            .observe(&test_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert_eq!(ev.findings[0].title, "Critical Dependabot Alerts Found");
        assert!(ev.findings[0].description.contains("1 critical"));
        assert!(ev.status.contains("1 critical"));
    }

    #[test]
    fn dependabot_not_enabled_returns_unknown() {
        let srv = mock_server(404, r#"{"message":"Dependabot alerts are not enabled"}"#);
        let ev = &DependabotAlertsObserver
            .observe(&test_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Unknown);
        assert_eq!(ev.findings[0].title, "Dependabot Alerts Not Enabled");
        assert!(ev.findings[0]
            .description
            .contains("Dependabot alerts not enabled"));
    }

    #[test]
    fn dependabot_api_error_returns_err() {
        let srv = mock_server(500, r#"{"message":"Internal Server Error"}"#);
        let result = DependabotAlertsObserver.observe(&test_config(&srv));
        assert!(result.is_err());
    }

    #[test]
    fn dependabot_evidence_types() {
        assert_eq!(DependabotAlertsObserver.evidence_types(), &[1003]);
    }

    #[test]
    fn dependabot_credential_requirements() {
        let reqs = DependabotAlertsObserver.credential_requirements();
        assert_eq!(reqs.len(), 3);
        assert!(reqs.iter().any(|r| r.name == "GITHUB_TOKEN" && r.required));
        assert!(reqs.iter().any(|r| r.name == "GITHUB_OWNER" && r.required));
        assert!(reqs.iter().any(|r| r.name == "GITHUB_REPO" && r.required));
    }

    #[test]
    fn dependabot_missing_token_errors() {
        let err = DependabotAlertsObserver
            .observe(&HashMap::from([
                ("GITHUB_OWNER".to_string(), "acme".to_string()),
                ("GITHUB_REPO".to_string(), "app".to_string()),
            ]))
            .unwrap_err();
        assert!(err.to_string().contains("GITHUB_TOKEN"));
    }

    #[test]
    fn dependabot_missing_owner_errors() {
        let err = DependabotAlertsObserver
            .observe(&HashMap::from([
                ("GITHUB_TOKEN".to_string(), "tok".to_string()),
                ("GITHUB_REPO".to_string(), "app".to_string()),
            ]))
            .unwrap_err();
        assert!(err.to_string().contains("GITHUB_OWNER"));
    }

    #[test]
    fn dependabot_missing_repo_errors() {
        let err = DependabotAlertsObserver
            .observe(&HashMap::from([
                ("GITHUB_TOKEN".to_string(), "tok".to_string()),
                ("GITHUB_OWNER".to_string(), "acme".to_string()),
            ]))
            .unwrap_err();
        assert!(err.to_string().contains("GITHUB_REPO"));
    }

    #[test]
    fn dependabot_connection_refused_errors() {
        let mut cfg = test_config("http://127.0.0.1:1");
        cfg.remove("GITHUB_API_URL");
        cfg.insert(
            "GITHUB_API_URL".to_string(),
            "http://127.0.0.1:1".to_string(),
        );
        let result = DependabotAlertsObserver.observe(&cfg);
        assert!(result.is_err());
    }

    #[test]
    fn dependabot_non_array_response_errors() {
        let srv = mock_server(200, r#""not an array""#);
        let result = DependabotAlertsObserver.observe(&test_config(&srv));
        assert!(result.is_err());
    }

    #[test]
    fn metadata_complete() {
        use crate::module::Module;
        let obs = DependabotAlertsObserver;
        assert_eq!(obs.id(), "github.dependabot_alerts");
        assert!(!obs.name().is_empty());
        assert_eq!(obs.version(), "0.1.0");
        assert_eq!(obs.source_system(), "github");
        assert!(!obs.evidence_types().is_empty());
        let creds = obs.credential_requirements();
        assert!(!creds.is_empty());
    }
}
