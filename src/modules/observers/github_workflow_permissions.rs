use std::collections::HashMap;

use anyhow::{anyhow, Result};
use chrono::Utc;
use uuid::Uuid;

use crate::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId,
};
use crate::module::{observer::Observer, CredentialReq, Module};
use crate::modules::github_common::{github_get, DEFAULT_GITHUB_API};

// ─── WorkflowPermissionsObserver ────────────────────────────────────────────

/// Queries the GitHub Actions workflow permissions API at the repository level
/// to determine the default token permissions for workflows and whether
/// workflows can approve pull request reviews.
///
/// Required config: `GITHUB_TOKEN`, `GITHUB_OWNER`, `GITHUB_REPO`.
/// Optional: `GITHUB_API_URL` (test override).
pub struct WorkflowPermissionsObserver;

impl Module for WorkflowPermissionsObserver {
    fn id(&self) -> &str {
        "github.workflow_permissions"
    }
    fn name(&self) -> &str {
        "GitHub Workflow Permissions Observer"
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
                description: "GitHub PAT with repo scope for reading workflow permissions"
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

impl Observer for WorkflowPermissionsObserver {
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
        let path = format!("/repos/{}/{}/actions/permissions/workflow", owner, repo);
        let endpoint = format!("{}{}", base_url.trim_end_matches('/'), &path);

        let (body, status) = github_get(token, base_url, &path)?;

        if status != 200 {
            return Err(anyhow!(
                "GitHub API returned status {} for {}",
                status,
                path
            ));
        }

        let mut findings: Vec<Finding> = Vec::new();
        let mut status_id = StatusId::Effective;

        // Check default_workflow_permissions field.
        let default_perms = body
            .get("default_workflow_permissions")
            .and_then(|v| v.as_str())
            .unwrap_or("write");

        if default_perms == "write" {
            status_id = StatusId::Ineffective;
            findings.push(Finding {
                title: "Workflow Token Has Write Permissions".to_string(),
                description: format!(
                    "Repository {}/{} grants write permissions to the GITHUB_TOKEN by default. \
                     Consider restricting to read-only.",
                    owner, repo
                ),
                severity_id: 3,
            });
        } else {
            findings.push(Finding {
                title: "Workflow Token Has Read-Only Permissions".to_string(),
                description: format!(
                    "Repository {}/{} restricts the default GITHUB_TOKEN to read permissions.",
                    owner, repo
                ),
                severity_id: 0,
            });
        }

        // Check can_approve_pull_request_reviews field.
        let can_approve = body
            .get("can_approve_pull_request_reviews")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if can_approve {
            findings.push(Finding {
                title: "Workflows Can Approve Pull Requests".to_string(),
                description: format!(
                    "Repository {}/{} allows GitHub Actions workflows to approve pull request reviews. \
                     This could allow automated bypass of review requirements.",
                    owner, repo
                ),
                severity_id: 2,
            });
        }

        let status_msg = if status_id == StatusId::Effective {
            format!(
                "Workflow permissions are properly restricted for {}/{}",
                owner, repo
            )
        } else {
            format!(
                "Workflow permissions are overly permissive for {}/{}",
                owner, repo
            )
        };

        Ok(vec![Evidence {
            id: Uuid::new_v4(),
            control_id: "scm.actions_security".to_string(),
            class_uid: 1003,
            category_uid: 2,
            activity_id: 1,
            time: now,
            confidence_level: ConfidenceLevel::PassiveObservation,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "github.workflow_permissions".to_string(),
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
                    value: format!("{}/{}:workflow_permissions", owner, repo),
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
    fn workflow_observer_id() {
        assert_eq!(
            WorkflowPermissionsObserver.id(),
            "github.workflow_permissions"
        );
    }

    #[test]
    fn workflow_observer_name() {
        assert_eq!(
            WorkflowPermissionsObserver.name(),
            "GitHub Workflow Permissions Observer"
        );
    }

    #[test]
    fn workflow_read_permissions_is_effective() {
        let srv = mock_server(
            200,
            r#"{"default_workflow_permissions":"read","can_approve_pull_request_reviews":false}"#,
        );
        let ev = &WorkflowPermissionsObserver
            .observe(&test_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "Workflow Token Has Read-Only Permissions"));
        assert_eq!(ev.control_id, "scm.actions_security");
        assert_eq!(ev.class_uid, 1003);
    }

    #[test]
    fn workflow_write_permissions_is_ineffective() {
        let srv = mock_server(
            200,
            r#"{"default_workflow_permissions":"write","can_approve_pull_request_reviews":false}"#,
        );
        let ev = &WorkflowPermissionsObserver
            .observe(&test_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "Workflow Token Has Write Permissions"));
    }

    #[test]
    fn workflow_can_approve_prs_finding() {
        let srv = mock_server(
            200,
            r#"{"default_workflow_permissions":"read","can_approve_pull_request_reviews":true}"#,
        );
        let ev = &WorkflowPermissionsObserver
            .observe(&test_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "Workflows Can Approve Pull Requests"));
    }

    #[test]
    fn workflow_api_error_returns_err() {
        let srv = mock_server(500, r#"{"message":"Internal Server Error"}"#);
        let result = WorkflowPermissionsObserver.observe(&test_config(&srv));
        assert!(result.is_err());
    }

    #[test]
    fn workflow_missing_token_errors() {
        let err = WorkflowPermissionsObserver
            .observe(&HashMap::from([
                ("GITHUB_OWNER".to_string(), "o".to_string()),
                ("GITHUB_REPO".to_string(), "r".to_string()),
            ]))
            .unwrap_err();
        assert!(err.to_string().contains("GITHUB_TOKEN"));
    }

    #[test]
    fn workflow_missing_owner_errors() {
        let err = WorkflowPermissionsObserver
            .observe(&HashMap::from([
                ("GITHUB_TOKEN".to_string(), "tok".to_string()),
                ("GITHUB_REPO".to_string(), "r".to_string()),
            ]))
            .unwrap_err();
        assert!(err.to_string().contains("GITHUB_OWNER"));
    }

    #[test]
    fn workflow_missing_repo_errors() {
        let err = WorkflowPermissionsObserver
            .observe(&HashMap::from([
                ("GITHUB_TOKEN".to_string(), "tok".to_string()),
                ("GITHUB_OWNER".to_string(), "o".to_string()),
            ]))
            .unwrap_err();
        assert!(err.to_string().contains("GITHUB_REPO"));
    }

    #[test]
    fn workflow_evidence_types() {
        assert_eq!(WorkflowPermissionsObserver.evidence_types(), &[1003]);
    }

    #[test]
    fn workflow_credential_requirements() {
        let reqs = WorkflowPermissionsObserver.credential_requirements();
        assert_eq!(reqs.len(), 3);
        assert!(reqs.iter().any(|r| r.name == "GITHUB_TOKEN" && r.required));
        assert!(reqs.iter().any(|r| r.name == "GITHUB_OWNER" && r.required));
        assert!(reqs.iter().any(|r| r.name == "GITHUB_REPO" && r.required));
    }
}
