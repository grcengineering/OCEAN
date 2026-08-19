use std::collections::HashMap;

use anyhow::{anyhow, Result};
use chrono::Utc;
use uuid::Uuid;

use crate::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId,
    EVIDENCE_SCHEMA_VERSION,
};
use crate::module::{observer::Observer, CredentialReq, Module};
use crate::modules::github_common::{github_get, DEFAULT_GITHUB_API};

// ─── CodeScanningAlertsObserver ─────────────────────────────────────────────

/// Queries the GitHub Code Scanning Alerts API to gather evidence about
/// critical open code scanning alerts in a repository.
///
/// Required config: `GITHUB_TOKEN`, `GITHUB_OWNER`, `GITHUB_REPO`.
/// Optional: `GITHUB_API_URL` (test override).
pub struct CodeScanningAlertsObserver;

impl Module for CodeScanningAlertsObserver {
    fn id(&self) -> &str {
        "github.code_scanning_alerts"
    }
    fn name(&self) -> &str {
        "GitHub Code Scanning Alerts Observer"
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
                description: "GitHub PAT with repo scope for reading code scanning alerts"
                    .to_string(),
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

impl Observer for CodeScanningAlertsObserver {
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
            "/repos/{}/{}/code-scanning/alerts?state=open&severity=critical&per_page=1",
            owner, repo
        );
        let endpoint = format!("{}{}", base_url.trim_end_matches('/'), path);

        let (body, status) = github_get(token, base_url, &path)?;

        // 404 means code scanning is not configured for the repository.
        if status == 404 {
            return Ok(vec![Evidence {
                schema_version: EVIDENCE_SCHEMA_VERSION.to_string(),
                connected_account: None,
                population: None,
                evaluation: None,
                id: Uuid::new_v4(),
                control_id: "scm.code_scanning".to_string(),
                class_uid: 1003,
                category_uid: 2,
                activity_id: 1,
                time: now,
                confidence_level: ConfidenceLevel::PassiveObservation,
                metadata: Metadata {
                    module: ModuleInfo {
                        name: "github.code_scanning_alerts".to_string(),
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
                        value: format!("{}/{}:code_scanning_alerts", owner, repo),
                        name: String::new(),
                    },
                    Observable {
                        obs_type: "domain".to_string(),
                        value: "github.com".to_string(),
                        name: String::new(),
                    },
                ],
                status_id: StatusId::Unknown,
                status: format!("Code scanning not configured on {}/{}", owner, repo),
                raw_data: body,
                findings: vec![Finding {
                    title: "Code Scanning Not Configured".to_string(),
                    description: "Code scanning not configured".to_string(),
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
            .ok_or_else(|| anyhow!("Expected JSON array from code scanning alerts API"))?;
        let alert_count = alerts.len();

        let (status_id, status_msg, findings) = if alert_count == 0 {
            (
                StatusId::Effective,
                format!(
                    "No critical open code scanning alerts on {}/{}",
                    owner, repo
                ),
                vec![Finding {
                    title: "No Critical Code Scanning Alerts".to_string(),
                    description: format!(
                        "No critical open code scanning alerts found for {}/{}.",
                        owner, repo
                    ),
                    severity_id: 0,
                }],
            )
        } else {
            (
                StatusId::Ineffective,
                format!(
                    "{} critical open code scanning alert(s) on {}/{}",
                    alert_count, owner, repo
                ),
                vec![Finding {
                    title: "Critical Code Scanning Alerts Found".to_string(),
                    description: format!(
                        "{} critical open code scanning alert(s) found for {}/{}.",
                        alert_count, owner, repo
                    ),
                    severity_id: 4,
                }],
            )
        };

        Ok(vec![Evidence {
            schema_version: EVIDENCE_SCHEMA_VERSION.to_string(),
            connected_account: None,
            population: None,
            evaluation: None,
            id: Uuid::new_v4(),
            control_id: "scm.code_scanning".to_string(),
            class_uid: 1003,
            category_uid: 2,
            activity_id: 1,
            time: now,
            confidence_level: ConfidenceLevel::PassiveObservation,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "github.code_scanning_alerts".to_string(),
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
                    value: format!("{}/{}:code_scanning_alerts", owner, repo),
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
    fn code_scanning_no_alerts_is_effective() {
        let srv = mock_server(200, "[]");
        let ev = &CodeScanningAlertsObserver
            .observe(&test_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert_eq!(ev.findings[0].title, "No Critical Code Scanning Alerts");
        assert_eq!(ev.control_id, "scm.code_scanning");
        assert_eq!(ev.class_uid, 1003);
        assert_eq!(ev.observables.len(), 2);
    }

    #[test]
    fn code_scanning_has_alerts_is_ineffective() {
        let srv = mock_server(
            200,
            r#"[{"number":1,"state":"open","rule":{"severity":"critical"}}]"#,
        );
        let ev = &CodeScanningAlertsObserver
            .observe(&test_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert_eq!(ev.findings[0].title, "Critical Code Scanning Alerts Found");
        assert!(ev.findings[0].description.contains("1 critical"));
        assert!(ev.status.contains("1 critical"));
    }

    #[test]
    fn code_scanning_not_configured_returns_unknown() {
        let srv = mock_server(404, r#"{"message":"no analysis found"}"#);
        let ev = &CodeScanningAlertsObserver
            .observe(&test_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Unknown);
        assert_eq!(ev.findings[0].title, "Code Scanning Not Configured");
        assert!(ev.findings[0]
            .description
            .contains("Code scanning not configured"));
    }

    #[test]
    fn code_scanning_api_error_returns_err() {
        let srv = mock_server(500, r#"{"message":"Internal Server Error"}"#);
        let result = CodeScanningAlertsObserver.observe(&test_config(&srv));
        assert!(result.is_err());
    }
}
