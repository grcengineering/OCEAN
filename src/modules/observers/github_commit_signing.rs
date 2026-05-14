use std::collections::HashMap;

use anyhow::{anyhow, Result};
use chrono::Utc;
use uuid::Uuid;

use crate::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId,
};
use crate::module::{observer::Observer, CredentialReq, Module};
use crate::modules::github_common::{github_get, DEFAULT_GITHUB_API};

// ─── CommitSigningObserver ────────────────────────────────────────────────────

/// Checks whether commit signing is required on the default branch of a repository.
///
/// Queries the branch protection endpoint to determine if required signatures
/// are enabled, which enforces that all commits are signed.
///
/// Required config: `GITHUB_TOKEN`, `GITHUB_OWNER`, `GITHUB_REPO`.
/// Optional: `GITHUB_API_URL` (test override), `GITHUB_BRANCH` (defaults to "main").
pub struct CommitSigningObserver;

impl Module for CommitSigningObserver {
    fn id(&self) -> &str {
        "github.commit_signing"
    }
    fn name(&self) -> &str {
        "GitHub Commit Signing Observer"
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
                description: "GitHub PAT with repo scope for reading branch protection".to_string(),
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

impl Observer for CommitSigningObserver {
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
        let branch = config
            .get("GITHUB_BRANCH")
            .map(|s| s.as_str())
            .unwrap_or("main");
        let base_url = config
            .get("GITHUB_API_URL")
            .map(|s| s.as_str())
            .unwrap_or(DEFAULT_GITHUB_API);

        let now = Utc::now();
        let path = format!(
            "/repos/{}/{}/branches/{}/protection/required_signatures",
            owner, repo, branch
        );
        let endpoint = format!("{}{}", base_url.trim_end_matches('/'), &path);

        let (body, status) = github_get(token, base_url, &path)?;

        // 404 means either branch protection isn't enabled or the endpoint isn't available.
        if status == 404 {
            return Ok(vec![Evidence {
                id: Uuid::new_v4(),
                control_id: "GH-2.4".to_string(),
                class_uid: 1003,
                category_uid: 2,
                activity_id: 1,
                time: now,
                confidence_level: ConfidenceLevel::PassiveObservation,
                metadata: Metadata {
                    module: ModuleInfo {
                        name: "github.commit_signing".to_string(),
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
                        value: format!("{}/{}:{}", owner, repo, branch),
                        name: String::new(),
                    },
                    Observable {
                        obs_type: "domain".to_string(),
                        value: "github.com".to_string(),
                        name: String::new(),
                    },
                ],
                status_id: StatusId::Ineffective,
                status: format!(
                    "Commit signing not required on {}/{}:{}",
                    owner, repo, branch
                ),
                raw_data: serde_json::json!({
                    "required_signatures_enabled": false,
                    "branch": branch
                }),
                findings: vec![Finding {
                    title: "Commit Signing Not Required".to_string(),
                    description: format!(
                        "Required signatures are not enabled on branch {} of {}/{}. \
                         Enable commit signing enforcement to ensure all commits are signed.",
                        branch, owner, repo
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

        let signing_enabled = body
            .get("enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let status_id = if signing_enabled {
            StatusId::Effective
        } else {
            StatusId::Ineffective
        };

        let mut findings: Vec<Finding> = Vec::new();
        if !signing_enabled {
            findings.push(Finding {
                title: "Commit Signing Not Enforced".to_string(),
                description: format!(
                    "Required signatures are disabled on branch {} of {}/{}. \
                     All commits should be signed to ensure authenticity.",
                    branch, owner, repo
                ),
                severity_id: 3,
            });
        }

        let status_msg = if signing_enabled {
            format!(
                "Commit signing required on {}/{}:{}",
                owner, repo, branch
            )
        } else {
            format!(
                "Commit signing not required on {}/{}:{}",
                owner, repo, branch
            )
        };

        Ok(vec![Evidence {
            id: Uuid::new_v4(),
            control_id: "GH-2.4".to_string(),
            class_uid: 1003,
            category_uid: 2,
            activity_id: 1,
            time: now,
            confidence_level: ConfidenceLevel::PassiveObservation,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "github.commit_signing".to_string(),
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
                    value: format!("{}/{}:{}", owner, repo, branch),
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
                "required_signatures_enabled": signing_enabled,
                "branch": branch
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
    use crate::modules::github_common::{mock_server, test_config};

    #[test]
    fn commit_signing_enabled_is_effective() {
        let srv = mock_server(200, r#"{"enabled":true,"url":"https://api.github.com/..."}"#);
        let ev = &CommitSigningObserver
            .observe(&test_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert!(ev.findings.is_empty());
        assert_eq!(ev.raw_data["required_signatures_enabled"], true);
    }

    #[test]
    fn commit_signing_disabled_is_ineffective() {
        let srv = mock_server(200, r#"{"enabled":false}"#);
        let ev = &CommitSigningObserver
            .observe(&test_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "Commit Signing Not Enforced"));
    }

    #[test]
    fn commit_signing_404_is_ineffective() {
        let srv = mock_server(404, r#"{"message":"Not Found"}"#);
        let ev = &CommitSigningObserver
            .observe(&test_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "Commit Signing Not Required"));
    }

    #[test]
    fn commit_signing_500_returns_err() {
        let srv = mock_server(500, r#"{"message":"Internal Server Error"}"#);
        let result = CommitSigningObserver.observe(&test_config(&srv));
        assert!(result.is_err());
    }

    #[test]
    fn commit_signing_evidence_types() {
        assert_eq!(CommitSigningObserver.evidence_types(), &[1003]);
    }

    #[test]
    fn commit_signing_credential_requirements() {
        let reqs = CommitSigningObserver.credential_requirements();
        assert_eq!(reqs.len(), 3);
        assert!(reqs.iter().any(|r| r.name == "GITHUB_TOKEN" && r.required));
        assert!(reqs.iter().any(|r| r.name == "GITHUB_OWNER" && r.required));
        assert!(reqs.iter().any(|r| r.name == "GITHUB_REPO" && r.required));
    }

    #[test]
    fn commit_signing_missing_token_errors() {
        let err = CommitSigningObserver
            .observe(&HashMap::from([
                ("GITHUB_OWNER".to_string(), "acme".to_string()),
                ("GITHUB_REPO".to_string(), "app".to_string()),
            ]))
            .unwrap_err();
        assert!(err.to_string().contains("GITHUB_TOKEN"));
    }

    #[test]
    fn commit_signing_missing_owner_errors() {
        let err = CommitSigningObserver
            .observe(&HashMap::from([
                ("GITHUB_TOKEN".to_string(), "tok".to_string()),
                ("GITHUB_REPO".to_string(), "app".to_string()),
            ]))
            .unwrap_err();
        assert!(err.to_string().contains("GITHUB_OWNER"));
    }

    #[test]
    fn commit_signing_missing_repo_errors() {
        let err = CommitSigningObserver
            .observe(&HashMap::from([
                ("GITHUB_TOKEN".to_string(), "tok".to_string()),
                ("GITHUB_OWNER".to_string(), "acme".to_string()),
            ]))
            .unwrap_err();
        assert!(err.to_string().contains("GITHUB_REPO"));
    }

    #[test]
    fn commit_signing_custom_branch_used() {
        let srv = mock_server(200, r#"{"enabled":true}"#);
        let mut cfg = test_config(&srv);
        cfg.insert("GITHUB_BRANCH".to_string(), "develop".to_string());
        let ev = &CommitSigningObserver.observe(&cfg).unwrap()[0];
        assert!(ev.status.contains("develop"));
    }

    #[test]
    fn commit_signing_connection_refused_errors() {
        let mut cfg = test_config("placeholder");
        cfg.insert("GITHUB_API_URL".to_string(), "http://127.0.0.1:1".to_string());
        let result = CommitSigningObserver.observe(&cfg);
        assert!(result.is_err());
    }

    #[test]
    fn metadata_complete() {
        use crate::module::Module;
        let obs = CommitSigningObserver;
        assert_eq!(obs.id(), "github.commit_signing");
        assert!(!obs.name().is_empty());
        assert_eq!(obs.version(), "0.1.0");
        assert_eq!(obs.source_system(), "github");
        assert!(!obs.evidence_types().is_empty());
        let creds = obs.credential_requirements();
        assert!(!creds.is_empty());
    }
}
