use std::collections::HashMap;

use anyhow::{anyhow, Result};
use chrono::Utc;
use uuid::Uuid;

use crate::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId,
};
use crate::module::{observer::Observer, CredentialReq, Module};
use crate::modules::github_common::{github_get, DEFAULT_GITHUB_API};

// ─── RepoSecurityObserver ───────────────────────────────────────────────────

/// Queries the GitHub repository API to gather evidence about repository
/// security settings including secret scanning, push protection, and
/// Dependabot security updates.
///
/// Required config: `GITHUB_TOKEN`, `GITHUB_OWNER`, `GITHUB_REPO`.
/// Optional: `GITHUB_API_URL` (test override).
pub struct RepoSecurityObserver;

impl Module for RepoSecurityObserver {
    fn id(&self) -> &str {
        "github.repo_security"
    }
    fn name(&self) -> &str {
        "GitHub Repository Security Settings Observer"
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
                description: "GitHub PAT with repo scope for reading repository settings"
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

impl Observer for RepoSecurityObserver {
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
        let path = format!("/repos/{}/{}", owner, repo);
        let endpoint = format!("{}{}", base_url.trim_end_matches('/'), &path);

        let (body, status) = github_get(token, base_url, &path)?;

        if status == 404 {
            return Err(anyhow!(
                "Repository {}/{} not found (404)",
                owner,
                repo
            ));
        }

        if status != 200 {
            return Err(anyhow!(
                "GitHub API returned status {} for {}",
                status,
                path
            ));
        }

        let mut findings: Vec<Finding> = Vec::new();
        let mut status_id = StatusId::Effective;

        if let Some(security) = body.get("security_and_analysis") {
            // Secret scanning
            let secret_scanning_enabled = security
                .get("secret_scanning")
                .and_then(|v| v.get("status"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                == "enabled";

            if !secret_scanning_enabled {
                findings.push(Finding {
                    title: "Secret Scanning Not Enabled".to_string(),
                    description: format!(
                        "Secret scanning is not enabled on {}/{}. \
                         Secrets committed to the repository will not be detected.",
                        owner, repo
                    ),
                    severity_id: 3,
                });
                status_id = StatusId::Ineffective;
            }

            // Secret scanning push protection
            let push_protection_enabled = security
                .get("secret_scanning_push_protection")
                .and_then(|v| v.get("status"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                == "enabled";

            if !push_protection_enabled {
                findings.push(Finding {
                    title: "Secret Scanning Push Protection Not Enabled".to_string(),
                    description: format!(
                        "Push protection is not enabled on {}/{}. \
                         Pushes containing secrets will not be blocked.",
                        owner, repo
                    ),
                    severity_id: 3,
                });
                status_id = StatusId::Ineffective;
            }

            // Dependabot security updates
            let dependabot_enabled = security
                .get("dependabot_security_updates")
                .and_then(|v| v.get("status"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                == "enabled";

            if !dependabot_enabled {
                findings.push(Finding {
                    title: "Dependabot Security Updates Not Enabled".to_string(),
                    description: format!(
                        "Dependabot security updates are not enabled on {}/{}. \
                         Vulnerable dependencies will not be automatically updated.",
                        owner, repo
                    ),
                    severity_id: 3,
                });
                status_id = StatusId::Ineffective;
            }
        } else {
            findings.push(Finding {
                title: "Security and Analysis Settings Missing".to_string(),
                description: format!(
                    "The security_and_analysis field is missing from the {}/{} repository response. \
                     Secret scanning, push protection, and Dependabot may not be configured.",
                    owner, repo
                ),
                severity_id: 4,
            });
            status_id = StatusId::Ineffective;
        }

        if findings.is_empty() {
            findings.push(Finding {
                title: "Repository Security Settings Properly Configured".to_string(),
                description: format!(
                    "Secret scanning, push protection, and Dependabot security updates \
                     are all enabled on {}/{}.",
                    owner, repo
                ),
                severity_id: 0,
            });
        }

        let status_msg = if status_id == StatusId::Effective {
            format!(
                "Repository security settings are properly configured on {}/{}",
                owner, repo
            )
        } else {
            format!(
                "Repository security settings on {}/{} have gaps",
                owner, repo
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
                    name: "github.repo_security".to_string(),
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
                    value: format!("{}/{}:repo_security", owner, repo),
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

    const ALL_ENABLED: &str = r#"{
        "security_and_analysis": {
            "secret_scanning": { "status": "enabled" },
            "secret_scanning_push_protection": { "status": "enabled" },
            "dependabot_security_updates": { "status": "enabled" }
        }
    }"#;

    const SOME_DISABLED: &str = r#"{
        "security_and_analysis": {
            "secret_scanning": { "status": "enabled" },
            "secret_scanning_push_protection": { "status": "disabled" },
            "dependabot_security_updates": { "status": "disabled" }
        }
    }"#;

    const NO_SECURITY_FIELD: &str = r#"{
        "name": "app",
        "full_name": "acme/app"
    }"#;

    #[test]
    fn repo_security_all_enabled_is_effective() {
        let srv = mock_server(200, ALL_ENABLED);
        let ev = &RepoSecurityObserver
            .observe(&test_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert_eq!(
            ev.findings[0].title,
            "Repository Security Settings Properly Configured"
        );
        assert_eq!(ev.control_id, "scm.secret_scanning");
        assert_eq!(ev.class_uid, 1003);
        assert_eq!(ev.observables.len(), 2);
    }

    #[test]
    fn repo_security_some_disabled_is_ineffective() {
        let srv = mock_server(200, SOME_DISABLED);
        let ev = &RepoSecurityObserver
            .observe(&test_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "Secret Scanning Push Protection Not Enabled"));
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "Dependabot Security Updates Not Enabled"));
    }

    #[test]
    fn repo_security_missing_security_field_is_ineffective() {
        let srv = mock_server(200, NO_SECURITY_FIELD);
        let ev = &RepoSecurityObserver
            .observe(&test_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert_eq!(
            ev.findings[0].title,
            "Security and Analysis Settings Missing"
        );
    }

    #[test]
    fn repo_security_404_returns_error() {
        let srv = mock_server(404, r#"{"message":"Not Found"}"#);
        let result = RepoSecurityObserver.observe(&test_config(&srv));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn repo_security_500_returns_error() {
        let srv = mock_server(500, r#"{"message":"Internal Server Error"}"#);
        let result = RepoSecurityObserver.observe(&test_config(&srv));
        assert!(result.is_err());
    }

    #[test]
    fn repo_security_secret_scanning_disabled_finding() {
        let srv = mock_server(
            200,
            r#"{
                "security_and_analysis": {
                    "secret_scanning": { "status": "disabled" },
                    "secret_scanning_push_protection": { "status": "enabled" },
                    "dependabot_security_updates": { "status": "enabled" }
                }
            }"#,
        );
        let ev = &RepoSecurityObserver
            .observe(&test_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "Secret Scanning Not Enabled"));
    }

    #[test]
    fn repo_security_evidence_types() {
        assert_eq!(RepoSecurityObserver.evidence_types(), &[1003]);
    }

    #[test]
    fn repo_security_credential_requirements() {
        let reqs = RepoSecurityObserver.credential_requirements();
        assert_eq!(reqs.len(), 3);
        assert!(reqs.iter().any(|r| r.name == "GITHUB_TOKEN" && r.required));
        assert!(reqs.iter().any(|r| r.name == "GITHUB_OWNER" && r.required));
        assert!(reqs.iter().any(|r| r.name == "GITHUB_REPO" && r.required));
    }

    #[test]
    fn repo_security_missing_token_errors() {
        let err = RepoSecurityObserver
            .observe(&HashMap::from([
                ("GITHUB_OWNER".to_string(), "acme".to_string()),
                ("GITHUB_REPO".to_string(), "app".to_string()),
            ]))
            .unwrap_err();
        assert!(err.to_string().contains("GITHUB_TOKEN"));
    }

    #[test]
    fn repo_security_missing_owner_errors() {
        let err = RepoSecurityObserver
            .observe(&HashMap::from([
                ("GITHUB_TOKEN".to_string(), "tok".to_string()),
                ("GITHUB_REPO".to_string(), "app".to_string()),
            ]))
            .unwrap_err();
        assert!(err.to_string().contains("GITHUB_OWNER"));
    }

    #[test]
    fn repo_security_missing_repo_errors() {
        let err = RepoSecurityObserver
            .observe(&HashMap::from([
                ("GITHUB_TOKEN".to_string(), "tok".to_string()),
                ("GITHUB_OWNER".to_string(), "acme".to_string()),
            ]))
            .unwrap_err();
        assert!(err.to_string().contains("GITHUB_REPO"));
    }

    #[test]
    fn repo_security_connection_refused_errors() {
        let mut cfg = test_config("placeholder");
        cfg.insert("GITHUB_API_URL".to_string(), "http://127.0.0.1:1".to_string());
        let result = RepoSecurityObserver.observe(&cfg);
        assert!(result.is_err());
    }

    #[test]
    fn metadata_complete() {
        use crate::module::Module;
        let obs = RepoSecurityObserver;
        assert_eq!(obs.id(), "github.repo_security");
        assert!(!obs.name().is_empty());
        assert_eq!(obs.version(), "0.1.0");
        assert_eq!(obs.source_system(), "github");
        assert!(!obs.evidence_types().is_empty());
        let creds = obs.credential_requirements();
        assert!(!creds.is_empty());
    }
}
