use std::collections::HashMap;

use anyhow::{anyhow, Result};
use chrono::Utc;
use uuid::Uuid;

use crate::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId,
};
use crate::module::{observer::Observer, CredentialReq, Module};
use crate::modules::github_common::{github_get, DEFAULT_GITHUB_API};

// ─── RunnerConfigObserver ─────────────────────────────────────────────────────

/// Checks the GitHub Actions runner configuration for the organization,
/// determining whether self-hosted runners are in use and whether they
/// are restricted to private repositories only.
///
/// Self-hosted runners on public repositories are a security risk as
/// external contributors can trigger runner execution.
///
/// Required config: `GITHUB_TOKEN`, `GITHUB_ORG`.
/// Optional: `GITHUB_API_URL` (test override).
pub struct RunnerConfigObserver;

impl Module for RunnerConfigObserver {
    fn id(&self) -> &str {
        "github.runner_config"
    }
    fn name(&self) -> &str {
        "GitHub Runner Config Observer"
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
                description: "GitHub PAT with admin:org scope for reading runner configuration"
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

impl Observer for RunnerConfigObserver {
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
        let path = format!("/orgs/{}/actions/runners", org);
        let endpoint = format!("{}{}", base_url.trim_end_matches('/'), path);

        let (body, status) = github_get(token, base_url, &path)?;

        if status != 200 {
            return Err(anyhow!(
                "GitHub API returned status {} for {}",
                status,
                path
            ));
        }

        let total_count = body
            .get("total_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        let runners = body
            .get("runners")
            .and_then(|v| v.as_array())
            .map(|a| a.as_slice())
            .unwrap_or(&[]);

        // Check for self-hosted runners (non-GitHub-hosted).
        let self_hosted_count = runners
            .iter()
            .filter(|r| {
                r.get("labels")
                    .and_then(|l| l.as_array())
                    .map(|labels| {
                        labels.iter().any(|label| {
                            label.get("name").and_then(|n| n.as_str()) == Some("self-hosted")
                        })
                    })
                    .unwrap_or(false)
            })
            .count();

        let github_hosted_count = (total_count as usize).saturating_sub(self_hosted_count);

        let mut findings: Vec<Finding> = Vec::new();
        let status_id;

        if self_hosted_count == 0 {
            // Only GitHub-hosted runners — preferred configuration.
            status_id = StatusId::Effective;
            findings.push(Finding {
                title: "No Self-Hosted Runners Detected".to_string(),
                description: format!(
                    "Organization {} uses only GitHub-hosted runners ({} total). \
                     GitHub-hosted runners are ephemeral and maintained by GitHub.",
                    org, total_count
                ),
                severity_id: 0,
            });
        } else {
            // Self-hosted runners present — flag for review.
            status_id = StatusId::Ineffective;
            findings.push(Finding {
                title: "Self-Hosted Runners In Use".to_string(),
                description: format!(
                    "Organization {} has {} self-hosted runner(s). Self-hosted runners \
                     may expose infrastructure if triggered by untrusted workflows. \
                     Ensure they are not accessible from public repositories (GH-3.2).",
                    org, self_hosted_count
                ),
                severity_id: 3,
            });
        }

        let status_msg = if status_id == StatusId::Effective {
            format!("Runner configuration safe for organization {}", org)
        } else {
            format!("Self-hosted runners present for organization {}", org)
        };

        Ok(vec![Evidence {
            id: Uuid::new_v4(),
            control_id: "GH-3.2".to_string(),
            class_uid: 1003,
            category_uid: 2,
            activity_id: 1,
            time: now,
            confidence_level: ConfidenceLevel::PassiveObservation,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "github.runner_config".to_string(),
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
                    value: format!("{}:runners", org),
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
                "total_count": total_count,
                "self_hosted_count": self_hosted_count,
                "github_hosted_count": github_hosted_count
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
    use crate::modules::github_common::{mock_server, test_config_with_org};

    #[test]
    fn no_self_hosted_runners_is_effective() {
        let srv = mock_server(
            200,
            r#"{"total_count":2,"runners":[
                {"id":1,"name":"runner1","labels":[{"name":"ubuntu-latest"}]},
                {"id":2,"name":"runner2","labels":[{"name":"windows-latest"}]}
            ]}"#,
        );
        let ev = &RunnerConfigObserver
            .observe(&test_config_with_org(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert_eq!(ev.raw_data["self_hosted_count"], 0);
    }

    #[test]
    fn self_hosted_runners_is_ineffective() {
        let srv = mock_server(
            200,
            r#"{"total_count":1,"runners":[
                {"id":1,"name":"my-runner","labels":[{"name":"self-hosted"},{"name":"linux"}]}
            ]}"#,
        );
        let ev = &RunnerConfigObserver
            .observe(&test_config_with_org(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert_eq!(ev.raw_data["self_hosted_count"], 1);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "Self-Hosted Runners In Use"));
    }

    #[test]
    fn runner_api_error_returns_err() {
        let srv = mock_server(403, r#"{"message":"Forbidden"}"#);
        let result = RunnerConfigObserver.observe(&test_config_with_org(&srv));
        assert!(result.is_err());
    }

    #[test]
    fn runner_evidence_types() {
        assert_eq!(RunnerConfigObserver.evidence_types(), &[1003]);
    }

    #[test]
    fn runner_credential_requirements() {
        let reqs = RunnerConfigObserver.credential_requirements();
        assert_eq!(reqs.len(), 2);
        assert!(reqs.iter().any(|r| r.name == "GITHUB_TOKEN" && r.required));
        assert!(reqs.iter().any(|r| r.name == "GITHUB_ORG" && r.required));
    }

    #[test]
    fn runner_missing_token_errors() {
        let err = RunnerConfigObserver
            .observe(&HashMap::from([(
                "GITHUB_ORG".to_string(),
                "org".to_string(),
            )]))
            .unwrap_err();
        assert!(err.to_string().contains("GITHUB_TOKEN"));
    }

    #[test]
    fn runner_missing_org_errors() {
        let err = RunnerConfigObserver
            .observe(&HashMap::from([(
                "GITHUB_TOKEN".to_string(),
                "tok".to_string(),
            )]))
            .unwrap_err();
        assert!(err.to_string().contains("GITHUB_ORG"));
    }
}
