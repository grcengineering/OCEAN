use std::collections::HashMap;

use anyhow::{anyhow, Result};
use chrono::Utc;
use uuid::Uuid;

use crate::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId,
};
use crate::module::{observer::Observer, CredentialReq, Module};
use crate::modules::github_common::{github_get, DEFAULT_GITHUB_API};

// ─── ActionsAllowedObserver ───────────────────────────────────────────────────

/// Checks whether GitHub Actions is restricted to only allow actions from
/// verified creators or specific approved actions in the organization.
///
/// Queries `GET /orgs/{org}/actions/permissions/selected-actions` to determine
/// if the org restricts which actions can run (vs allowing all actions).
///
/// Required config: `GITHUB_TOKEN`, `GITHUB_ORG`.
/// Optional: `GITHUB_API_URL` (test override).
pub struct ActionsAllowedObserver;

impl Module for ActionsAllowedObserver {
    fn id(&self) -> &str {
        "github.actions_allowed"
    }
    fn name(&self) -> &str {
        "GitHub Actions Allowed Observer"
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
                description: "GitHub PAT with admin:org scope for reading Actions permissions"
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

impl Observer for ActionsAllowedObserver {
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
        // First check the org-level allowed actions policy.
        let perms_path = format!("/orgs/{}/actions/permissions", org);
        let endpoint = format!("{}{}", base_url.trim_end_matches('/'), &perms_path);

        let (body, status) = github_get(token, base_url, &perms_path)?;

        if status != 200 {
            return Err(anyhow!(
                "GitHub API returned status {} for {}",
                status,
                perms_path
            ));
        }

        // allowed_actions: "all" | "local_only" | "selected"
        let allowed_actions = body
            .get("allowed_actions")
            .and_then(|v| v.as_str())
            .unwrap_or("all");

        let enabled_repos = body
            .get("enabled_repositories")
            .and_then(|v| v.as_str())
            .unwrap_or("all");

        // "selected" is most restrictive; "local_only" is acceptable; "all" is unrestricted.
        let (status_id, severity_id, finding_title, finding_desc) = match allowed_actions {
            "selected" => (
                StatusId::Effective,
                0,
                "Actions Restricted to Selected".to_string(),
                format!(
                    "Organization {} restricts GitHub Actions to only selected approved actions.",
                    org
                ),
            ),
            "local_only" => (
                StatusId::Effective,
                0,
                "Actions Restricted to Local Only".to_string(),
                format!(
                    "Organization {} restricts GitHub Actions to locally-defined actions only.",
                    org
                ),
            ),
            _ => (
                StatusId::Ineffective,
                3,
                "Actions Unrestricted".to_string(),
                format!(
                    "Organization {} allows all GitHub Actions without restriction. \
                     Restrict to verified creators or selected actions to reduce supply chain risk.",
                    org
                ),
            ),
        };

        let status_msg = if status_id == StatusId::Effective {
            format!("Actions restricted for organization {}", org)
        } else {
            format!("Actions unrestricted for organization {}", org)
        };

        Ok(vec![Evidence {
            id: Uuid::new_v4(),
            control_id: "GH-3.1".to_string(),
            class_uid: 1003,
            category_uid: 2,
            activity_id: 1,
            time: now,
            confidence_level: ConfidenceLevel::PassiveObservation,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "github.actions_allowed".to_string(),
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
            raw_data: serde_json::json!({
                "allowed_actions": allowed_actions,
                "enabled_repositories": enabled_repos
            }),
            findings: vec![Finding {
                title: finding_title,
                description: finding_desc,
                severity_id,
            }],
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
    fn actions_selected_is_effective() {
        let srv = mock_server(
            200,
            r#"{"allowed_actions":"selected","enabled_repositories":"all"}"#,
        );
        let ev = &ActionsAllowedObserver
            .observe(&test_config_with_org(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert_eq!(ev.raw_data["allowed_actions"], "selected");
    }

    #[test]
    fn actions_all_is_ineffective() {
        let srv = mock_server(
            200,
            r#"{"allowed_actions":"all","enabled_repositories":"all"}"#,
        );
        let ev = &ActionsAllowedObserver
            .observe(&test_config_with_org(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "Actions Unrestricted"));
    }

    #[test]
    fn actions_api_error_returns_err() {
        let srv = mock_server(403, r#"{"message":"Forbidden"}"#);
        let result = ActionsAllowedObserver.observe(&test_config_with_org(&srv));
        assert!(result.is_err());
    }
}
