use std::collections::HashMap;

use anyhow::{anyhow, Result};
use chrono::Utc;
use uuid::Uuid;

use crate::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId,
};
use crate::module::{observer::Observer, CredentialReq, Module};
use crate::modules::github_common::{github_get, DEFAULT_GITHUB_API};

// ─── DependencyReviewObserver ────────────────────────────────────────────────

/// Checks whether the dependency graph is enabled for a repository, which is
/// the prerequisite for dependency review and Dependabot security updates
/// (GH-6.1). Reads `security_and_analysis.dependency_graph.status` from the
/// repository metadata endpoint.
///
/// Required config: `GITHUB_TOKEN`, `GITHUB_OWNER`, `GITHUB_REPO`.
/// Optional: `GITHUB_API_URL` (test override).
pub struct DependencyReviewObserver;

impl Module for DependencyReviewObserver {
    fn id(&self) -> &str {
        "github.dependency_review"
    }
    fn name(&self) -> &str {
        "GitHub Dependency Review Observer"
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
                description: "GitHub PAT with repo scope for reading repository security settings"
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

impl Observer for DependencyReviewObserver {
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
        let endpoint = format!("{}{}", base_url.trim_end_matches('/'), path);

        let (body, status) = github_get(token, base_url, &path)?;

        if status != 200 {
            return Err(anyhow!(
                "GitHub API returned status {} for {}",
                status,
                path
            ));
        }

        let dep_graph_status = body
            .get("security_and_analysis")
            .and_then(|s| s.get("dependency_graph"))
            .and_then(|d| d.get("status"))
            .and_then(|v| v.as_str())
            .unwrap_or("disabled");

        let enabled = dep_graph_status == "enabled";

        let (status_id, findings) = if enabled {
            (
                StatusId::Effective,
                vec![Finding {
                    title: "Dependency Graph Enabled".to_string(),
                    description: format!(
                        "Repository {}/{} has the dependency graph enabled, supporting \
                         dependency review and vulnerability tracking (GH-6.1).",
                        owner, repo
                    ),
                    severity_id: 0,
                }],
            )
        } else {
            (
                StatusId::Ineffective,
                vec![Finding {
                    title: "Dependency Graph Disabled".to_string(),
                    description: format!(
                        "Repository {}/{} has the dependency graph disabled or not configured. \
                         Enable the dependency graph to support dependency review and \
                         Dependabot alerts (GH-6.1).",
                        owner, repo
                    ),
                    severity_id: 2,
                }],
            )
        };

        let status_msg = if enabled {
            format!("Dependency graph is enabled for {}/{}", owner, repo)
        } else {
            format!("Dependency graph is disabled for {}/{}", owner, repo)
        };

        Ok(vec![Evidence {
            id: Uuid::new_v4(),
            control_id: "GH-6.1".to_string(),
            class_uid: 1003,
            category_uid: 2,
            activity_id: 1,
            time: now,
            confidence_level: ConfidenceLevel::PassiveObservation,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "github.dependency_review".to_string(),
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
                    value: format!("{}/{}:dependency_graph", owner, repo),
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
    fn dependency_graph_enabled_is_effective() {
        let srv = mock_server(
            200,
            r#"{"name":"app","security_and_analysis":{"dependency_graph":{"status":"enabled"}}}"#,
        );
        let ev = &DependencyReviewObserver
            .observe(&test_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "Dependency Graph Enabled"));
    }

    #[test]
    fn dependency_graph_disabled_is_ineffective_with_finding() {
        let srv = mock_server(
            200,
            r#"{"name":"app","security_and_analysis":{"dependency_graph":{"status":"disabled"}}}"#,
        );
        let ev = &DependencyReviewObserver
            .observe(&test_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "Dependency Graph Disabled"));
    }

    #[test]
    fn dependency_review_404_returns_err() {
        let srv = mock_server(404, r#"{"message":"Not Found"}"#);
        let result = DependencyReviewObserver.observe(&test_config(&srv));
        assert!(result.is_err());
    }

    #[test]
    fn dependency_review_evidence_types() {
        assert_eq!(DependencyReviewObserver.evidence_types(), &[1003]);
    }

    #[test]
    fn dependency_review_credential_requirements() {
        let reqs = DependencyReviewObserver.credential_requirements();
        assert_eq!(reqs.len(), 3);
        assert!(reqs.iter().any(|r| r.name == "GITHUB_TOKEN" && r.required));
        assert!(reqs.iter().any(|r| r.name == "GITHUB_OWNER" && r.required));
        assert!(reqs.iter().any(|r| r.name == "GITHUB_REPO" && r.required));
    }

    #[test]
    fn dependency_review_missing_token_errors() {
        let err = DependencyReviewObserver
            .observe(&HashMap::from([
                ("GITHUB_OWNER".to_string(), "acme".to_string()),
                ("GITHUB_REPO".to_string(), "app".to_string()),
            ]))
            .unwrap_err();
        assert!(err.to_string().contains("GITHUB_TOKEN"));
    }

    #[test]
    fn dependency_review_missing_owner_errors() {
        let err = DependencyReviewObserver
            .observe(&HashMap::from([
                ("GITHUB_TOKEN".to_string(), "tok".to_string()),
                ("GITHUB_REPO".to_string(), "app".to_string()),
            ]))
            .unwrap_err();
        assert!(err.to_string().contains("GITHUB_OWNER"));
    }

    #[test]
    fn dependency_review_missing_repo_errors() {
        let err = DependencyReviewObserver
            .observe(&HashMap::from([
                ("GITHUB_TOKEN".to_string(), "tok".to_string()),
                ("GITHUB_OWNER".to_string(), "acme".to_string()),
            ]))
            .unwrap_err();
        assert!(err.to_string().contains("GITHUB_REPO"));
    }

    #[test]
    fn dependency_review_connection_refused_errors() {
        let mut cfg = test_config("placeholder");
        cfg.insert(
            "GITHUB_API_URL".to_string(),
            "http://127.0.0.1:1".to_string(),
        );
        let result = DependencyReviewObserver.observe(&cfg);
        assert!(result.is_err());
    }

    #[test]
    fn metadata_complete() {
        use crate::module::Module;
        let obs = DependencyReviewObserver;
        assert_eq!(obs.id(), "github.dependency_review");
        assert!(!obs.name().is_empty());
        assert_eq!(obs.version(), "0.1.0");
        assert_eq!(obs.source_system(), "github");
        assert!(!obs.evidence_types().is_empty());
        let creds = obs.credential_requirements();
        assert!(!creds.is_empty());
    }
}
