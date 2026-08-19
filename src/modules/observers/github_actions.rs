use std::collections::HashMap;

use anyhow::{anyhow, Result};
use chrono::Utc;
use uuid::Uuid;

use crate::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId,
};
use crate::module::{observer::Observer, CredentialReq, Module};
use crate::modules::github_common::{github_get, DEFAULT_GITHUB_API};

// ─── ActionsPermissionsObserver ─────────────────────────────────────────────

/// Queries the GitHub Actions permissions API at the organization level to
/// determine whether actions usage is restricted. Checks `allowed_actions`
/// and `enabled_repositories` fields.
///
/// Required config: `GITHUB_TOKEN`, `GITHUB_ORG`.
/// Optional: `GITHUB_API_URL` (test override).
pub struct ActionsPermissionsObserver;

impl Module for ActionsPermissionsObserver {
    fn id(&self) -> &str {
        "github.actions_permissions"
    }
    fn name(&self) -> &str {
        "GitHub Actions Permissions Observer"
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
                description: "GitHub PAT with admin:org scope for reading actions permissions"
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

impl Observer for ActionsPermissionsObserver {
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
        let path = format!("/orgs/{}/actions/permissions", org);
        let endpoint = format!("{}{}", base_url.trim_end_matches('/'), path);

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

        // Check allowed_actions field.
        let allowed_actions = body
            .get("allowed_actions")
            .and_then(|v| v.as_str())
            .unwrap_or("all");

        if allowed_actions == "all" {
            status_id = StatusId::Ineffective;
            findings.push(Finding {
                title: "Actions Unrestricted".to_string(),
                description: format!(
                    "Organization {} allows all GitHub Actions without restriction. \
                     Consider limiting to selected or local-only actions.",
                    org
                ),
                severity_id: 3,
            });
        } else {
            findings.push(Finding {
                title: "Actions Restricted".to_string(),
                description: format!(
                    "Organization {} restricts GitHub Actions to '{}' mode.",
                    org, allowed_actions
                ),
                severity_id: 0,
            });
        }

        // Check enabled_repositories field.
        let enabled_repositories = body
            .get("enabled_repositories")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if enabled_repositories == "none" {
            findings.push(Finding {
                title: "Actions Disabled Entirely".to_string(),
                description: format!(
                    "GitHub Actions are disabled for all repositories in organization {}.",
                    org
                ),
                severity_id: 1,
            });
        }

        let status_msg = if status_id == StatusId::Effective {
            format!(
                "Actions permissions are restricted for organization {}",
                org
            )
        } else {
            format!(
                "Actions permissions are unrestricted for organization {}",
                org
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
                    name: "github.actions_permissions".to_string(),
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
                    value: format!("{}:actions_permissions", org),
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
    use crate::modules::github_common::{mock_server, test_config_with_org};

    #[test]
    fn actions_observer_id() {
        assert_eq!(
            ActionsPermissionsObserver.id(),
            "github.actions_permissions"
        );
    }

    #[test]
    fn actions_observer_name() {
        assert_eq!(
            ActionsPermissionsObserver.name(),
            "GitHub Actions Permissions Observer"
        );
    }

    #[test]
    fn actions_restricted_is_effective() {
        let srv = mock_server(
            200,
            r#"{"enabled_repositories":"all","allowed_actions":"selected"}"#,
        );
        let ev = &ActionsPermissionsObserver
            .observe(&test_config_with_org(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert!(ev.findings.iter().any(|f| f.title == "Actions Restricted"));
        assert_eq!(ev.control_id, "scm.actions_security");
        assert_eq!(ev.class_uid, 1003);
    }

    #[test]
    fn actions_unrestricted_is_ineffective() {
        let srv = mock_server(
            200,
            r#"{"enabled_repositories":"all","allowed_actions":"all"}"#,
        );
        let ev = &ActionsPermissionsObserver
            .observe(&test_config_with_org(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "Actions Unrestricted"));
    }

    #[test]
    fn actions_disabled_entirely_finding() {
        let srv = mock_server(
            200,
            r#"{"enabled_repositories":"none","allowed_actions":"selected"}"#,
        );
        let ev = &ActionsPermissionsObserver
            .observe(&test_config_with_org(&srv))
            .unwrap()[0];
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "Actions Disabled Entirely"));
    }

    #[test]
    fn actions_api_error_returns_err() {
        let srv = mock_server(403, r#"{"message":"Forbidden"}"#);
        let result = ActionsPermissionsObserver.observe(&test_config_with_org(&srv));
        assert!(result.is_err());
    }

    #[test]
    fn actions_missing_token_errors() {
        let err = ActionsPermissionsObserver
            .observe(&HashMap::from([(
                "GITHUB_ORG".to_string(),
                "org".to_string(),
            )]))
            .unwrap_err();
        assert!(err.to_string().contains("GITHUB_TOKEN"));
    }

    #[test]
    fn actions_missing_org_errors() {
        let err = ActionsPermissionsObserver
            .observe(&HashMap::from([(
                "GITHUB_TOKEN".to_string(),
                "tok".to_string(),
            )]))
            .unwrap_err();
        assert!(err.to_string().contains("GITHUB_ORG"));
    }

    #[test]
    fn actions_evidence_types() {
        assert_eq!(ActionsPermissionsObserver.evidence_types(), &[1003]);
    }

    #[test]
    fn actions_credential_requirements() {
        let reqs = ActionsPermissionsObserver.credential_requirements();
        assert_eq!(reqs.len(), 2);
        assert!(reqs.iter().any(|r| r.name == "GITHUB_TOKEN" && r.required));
        assert!(reqs.iter().any(|r| r.name == "GITHUB_ORG" && r.required));
    }
}
