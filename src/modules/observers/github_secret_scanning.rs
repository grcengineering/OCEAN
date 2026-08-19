use std::collections::HashMap;

use anyhow::{anyhow, Result};
use chrono::Utc;
use uuid::Uuid;

use crate::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId,
};
use crate::module::{observer::Observer, CredentialReq, Module};
use crate::modules::github_common::{github_get, DEFAULT_GITHUB_API};

// ─── SecretScanningAlertsObserver ───────────────────────────────────────────

/// Queries the GitHub secret scanning alerts API to gather evidence about
/// open secret scanning alerts in a repository. An empty list of open alerts
/// indicates effective secret management.
///
/// Required config: `GITHUB_TOKEN`, `GITHUB_OWNER`, `GITHUB_REPO`.
/// Optional: `GITHUB_API_URL` (test override).
pub struct SecretScanningAlertsObserver;

impl Module for SecretScanningAlertsObserver {
    fn id(&self) -> &str {
        "github.secret_scanning_alerts"
    }
    fn name(&self) -> &str {
        "GitHub Secret Scanning Alerts Observer"
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
                description: "GitHub PAT with repo scope for reading secret scanning alerts"
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

impl Observer for SecretScanningAlertsObserver {
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
            "/repos/{}/{}/secret-scanning/alerts?state=open&per_page=1",
            owner, repo
        );
        let endpoint = format!("{}{}", base_url.trim_end_matches('/'), path);

        let (body, status) = github_get(token, base_url, &path)?;

        // 404 means secret scanning is not enabled on this repository.
        if status == 404 {
            return Ok(vec![Evidence {
                id: Uuid::new_v4(),
                control_id: "scm.secret_scanning".to_string(),
                class_uid: 1003,
                category_uid: 2,
                activity_id: 1,
                time: now,
                confidence_level: ConfidenceLevel::PassiveObservation,
                metadata: Metadata {
                    module: ModuleInfo {
                        name: "github.secret_scanning_alerts".to_string(),
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
                        value: format!("{}/{}:secret_scanning_alerts", owner, repo),
                        name: String::new(),
                    },
                    Observable {
                        obs_type: "domain".to_string(),
                        value: "github.com".to_string(),
                        name: String::new(),
                    },
                ],
                status_id: StatusId::Unknown,
                status: format!("Secret scanning is not enabled on {}/{}", owner, repo),
                raw_data: body,
                findings: vec![Finding {
                    title: "Secret Scanning Not Enabled".to_string(),
                    description: format!(
                        "Secret scanning feature is not enabled on {}/{}. \
                         Unable to check for open secret scanning alerts.",
                        owner, repo
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

        let alerts = body
            .as_array()
            .ok_or_else(|| anyhow!("Expected JSON array from secret scanning alerts API"))?;

        let (status_id, status_msg, findings) = if alerts.is_empty() {
            (
                StatusId::Effective,
                format!("No open secret scanning alerts on {}/{}", owner, repo),
                vec![Finding {
                    title: "No Open Secret Scanning Alerts".to_string(),
                    description: format!(
                        "No open secret scanning alerts were found on {}/{}.",
                        owner, repo
                    ),
                    severity_id: 0,
                }],
            )
        } else {
            (
                StatusId::Ineffective,
                format!("Open secret scanning alerts found on {}/{}", owner, repo),
                vec![Finding {
                    title: "Open Secret Scanning Alerts".to_string(),
                    description: format!(
                        "One or more open secret scanning alerts exist on {}/{}. \
                         Exposed secrets should be rotated and alerts resolved.",
                        owner, repo
                    ),
                    severity_id: 4,
                }],
            )
        };

        Ok(vec![Evidence {
            id: Uuid::new_v4(),
            control_id: "scm.secret_scanning".to_string(),
            class_uid: 1003,
            category_uid: 2,
            activity_id: 1,
            time: now,
            confidence_level: ConfidenceLevel::PassiveObservation,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "github.secret_scanning_alerts".to_string(),
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
                    value: format!("{}/{}:secret_scanning_alerts", owner, repo),
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
    fn secret_scanning_no_alerts_is_effective() {
        let srv = mock_server(200, "[]");
        let ev = &SecretScanningAlertsObserver
            .observe(&test_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert_eq!(ev.findings[0].title, "No Open Secret Scanning Alerts");
        assert_eq!(ev.control_id, "scm.secret_scanning");
        assert_eq!(ev.class_uid, 1003);
        assert_eq!(ev.observables.len(), 2);
    }

    #[test]
    fn secret_scanning_alerts_exist_is_ineffective() {
        let body = r#"[{"number":1,"state":"open","secret_type":"github_personal_access_token"}]"#;
        let srv = mock_server(200, body);
        let ev = &SecretScanningAlertsObserver
            .observe(&test_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert_eq!(ev.findings[0].title, "Open Secret Scanning Alerts");
    }

    #[test]
    fn secret_scanning_404_returns_unknown() {
        let srv = mock_server(404, r#"{"message":"Secret scanning is disabled"}"#);
        let ev = &SecretScanningAlertsObserver
            .observe(&test_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Unknown);
        assert_eq!(ev.findings[0].title, "Secret Scanning Not Enabled");
    }

    #[test]
    fn secret_scanning_500_returns_error() {
        let srv = mock_server(500, r#"{"message":"Internal Server Error"}"#);
        let result = SecretScanningAlertsObserver.observe(&test_config(&srv));
        assert!(result.is_err());
    }

    #[test]
    fn secret_scanning_evidence_types() {
        assert_eq!(SecretScanningAlertsObserver.evidence_types(), &[1003]);
    }

    #[test]
    fn secret_scanning_credential_requirements() {
        let reqs = SecretScanningAlertsObserver.credential_requirements();
        assert_eq!(reqs.len(), 3);
        assert!(reqs.iter().any(|r| r.name == "GITHUB_TOKEN" && r.required));
        assert!(reqs.iter().any(|r| r.name == "GITHUB_OWNER" && r.required));
        assert!(reqs.iter().any(|r| r.name == "GITHUB_REPO" && r.required));
    }

    #[test]
    fn secret_scanning_missing_token_errors() {
        let err = SecretScanningAlertsObserver
            .observe(&HashMap::from([
                ("GITHUB_OWNER".to_string(), "acme".to_string()),
                ("GITHUB_REPO".to_string(), "app".to_string()),
            ]))
            .unwrap_err();
        assert!(err.to_string().contains("GITHUB_TOKEN"));
    }

    #[test]
    fn secret_scanning_missing_owner_errors() {
        let err = SecretScanningAlertsObserver
            .observe(&HashMap::from([
                ("GITHUB_TOKEN".to_string(), "tok".to_string()),
                ("GITHUB_REPO".to_string(), "app".to_string()),
            ]))
            .unwrap_err();
        assert!(err.to_string().contains("GITHUB_OWNER"));
    }

    #[test]
    fn secret_scanning_missing_repo_errors() {
        let err = SecretScanningAlertsObserver
            .observe(&HashMap::from([
                ("GITHUB_TOKEN".to_string(), "tok".to_string()),
                ("GITHUB_OWNER".to_string(), "acme".to_string()),
            ]))
            .unwrap_err();
        assert!(err.to_string().contains("GITHUB_REPO"));
    }

    #[test]
    fn secret_scanning_connection_refused_errors() {
        let mut cfg = test_config("placeholder");
        cfg.insert(
            "GITHUB_API_URL".to_string(),
            "http://127.0.0.1:1".to_string(),
        );
        let result = SecretScanningAlertsObserver.observe(&cfg);
        assert!(result.is_err());
    }

    #[test]
    fn secret_scanning_non_array_response_errors() {
        let srv = mock_server(200, r#""not an array""#);
        let result = SecretScanningAlertsObserver.observe(&test_config(&srv));
        assert!(result.is_err());
    }

    #[test]
    fn metadata_complete() {
        use crate::module::Module;
        let obs = SecretScanningAlertsObserver;
        assert_eq!(obs.id(), "github.secret_scanning_alerts");
        assert!(!obs.name().is_empty());
        assert_eq!(obs.version(), "0.1.0");
        assert_eq!(obs.source_system(), "github");
        assert!(!obs.evidence_types().is_empty());
        let creds = obs.credential_requirements();
        assert!(!creds.is_empty());
    }
}
