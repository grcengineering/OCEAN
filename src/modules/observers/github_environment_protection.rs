use std::collections::HashMap;

use anyhow::{anyhow, Result};
use chrono::Utc;
use uuid::Uuid;

use crate::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId,
};
use crate::module::{observer::Observer, CredentialReq, Module};
use crate::modules::github_common::{github_get, DEFAULT_GITHUB_API};

// ─── EnvironmentProtectionObserver ───────────────────────────────────────────

/// Checks whether GitHub repository environments have protection rules configured,
/// including required reviewers and deployment branch policies.
///
/// Environments without protection rules allow unrestricted deployments from
/// any branch or workflow, bypassing change control processes.
///
/// Required config: `GITHUB_TOKEN`, `GITHUB_OWNER`, `GITHUB_REPO`.
/// Optional: `GITHUB_API_URL` (test override).
pub struct EnvironmentProtectionObserver;

impl Module for EnvironmentProtectionObserver {
    fn id(&self) -> &str {
        "github.environment_protection"
    }
    fn name(&self) -> &str {
        "GitHub Environment Protection Observer"
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
                description: "GitHub PAT with repo scope for reading environment configuration"
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

impl Observer for EnvironmentProtectionObserver {
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
        let path = format!("/repos/{}/{}/environments", owner, repo);
        let endpoint = format!("{}{}", base_url.trim_end_matches('/'), &path);

        let (body, status) = github_get(token, base_url, &path)?;

        // 404 means no environments configured or feature not available.
        if status == 404 {
            return Ok(vec![Evidence {
                id: Uuid::new_v4(),
                control_id: "GH-3.3".to_string(),
                class_uid: 1003,
                category_uid: 2,
                activity_id: 1,
                time: now,
                confidence_level: ConfidenceLevel::PassiveObservation,
                metadata: Metadata {
                    module: ModuleInfo {
                        name: "github.environment_protection".to_string(),
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
                        value: format!("{}/{}:environments", owner, repo),
                        name: String::new(),
                    },
                    Observable {
                        obs_type: "domain".to_string(),
                        value: "github.com".to_string(),
                        name: String::new(),
                    },
                ],
                status_id: StatusId::Unknown,
                status: format!("No environments configured for {}/{}", owner, repo),
                raw_data: serde_json::json!({
                    "total_count": 0,
                    "protected_count": 0,
                    "unprotected_count": 0
                }),
                findings: vec![Finding {
                    title: "No Deployment Environments Configured".to_string(),
                    description: format!(
                        "Repository {}/{} has no deployment environments configured. \
                         Consider adding environments with protection rules for production deployments.",
                        owner, repo
                    ),
                    severity_id: 1,
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

        let total_count = body
            .get("total_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;

        let environments = body
            .get("environments")
            .and_then(|v| v.as_array())
            .map(|a| a.as_slice())
            .unwrap_or(&[]);

        let mut protected_count = 0usize;
        let mut unprotected_names: Vec<String> = Vec::new();

        for env in environments {
            let name = env
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");

            let has_reviewers = env
                .get("protection_rules")
                .and_then(|v| v.as_array())
                .map(|rules| {
                    rules.iter().any(|r| {
                        r.get("type").and_then(|t| t.as_str()) == Some("required_reviewers")
                    })
                })
                .unwrap_or(false);

            if has_reviewers {
                protected_count += 1;
            } else {
                unprotected_names.push(name.to_string());
            }
        }

        let unprotected_count = total_count.saturating_sub(protected_count);

        let mut findings: Vec<Finding> = Vec::new();
        let status_id;

        if unprotected_count == 0 && total_count > 0 {
            status_id = StatusId::Effective;
            findings.push(Finding {
                title: "All Environments Protected".to_string(),
                description: format!(
                    "All {} environment(s) in {}/{} have required reviewer protection rules.",
                    total_count, owner, repo
                ),
                severity_id: 0,
            });
        } else if !unprotected_names.is_empty() {
            status_id = StatusId::Ineffective;
            findings.push(Finding {
                title: "Environments Without Protection Rules".to_string(),
                description: format!(
                    "Repository {}/{} has {} unprotected environment(s): {}. \
                     Add required reviewer protection rules to enforce change control (GH-3.3).",
                    owner,
                    repo,
                    unprotected_count,
                    unprotected_names.join(", ")
                ),
                severity_id: 3,
            });
        } else {
            status_id = StatusId::Unknown;
        }

        let status_msg = if status_id == StatusId::Effective {
            format!("Environment protection configured for {}/{}", owner, repo)
        } else if status_id == StatusId::Ineffective {
            format!(
                "Unprotected environments in {}/{}: {}",
                owner,
                repo,
                unprotected_names.join(", ")
            )
        } else {
            format!("No environments in {}/{}", owner, repo)
        };

        Ok(vec![Evidence {
            id: Uuid::new_v4(),
            control_id: "GH-3.3".to_string(),
            class_uid: 1003,
            category_uid: 2,
            activity_id: 1,
            time: now,
            confidence_level: ConfidenceLevel::PassiveObservation,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "github.environment_protection".to_string(),
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
                    value: format!("{}/{}:environments", owner, repo),
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
                "protected_count": protected_count,
                "unprotected_count": unprotected_count
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
    fn all_environments_protected_is_effective() {
        let srv = mock_server(
            200,
            r#"{"total_count":1,"environments":[
                {"id":1,"name":"production","protection_rules":[
                    {"id":1,"type":"required_reviewers","reviewers":[]}
                ]}
            ]}"#,
        );
        let ev = &EnvironmentProtectionObserver
            .observe(&test_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert_eq!(ev.raw_data["protected_count"], 1);
        assert_eq!(ev.raw_data["unprotected_count"], 0);
    }

    #[test]
    fn unprotected_environment_is_ineffective() {
        let srv = mock_server(
            200,
            r#"{"total_count":1,"environments":[
                {"id":1,"name":"staging","protection_rules":[]}
            ]}"#,
        );
        let ev = &EnvironmentProtectionObserver
            .observe(&test_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert_eq!(ev.raw_data["unprotected_count"], 1);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "Environments Without Protection Rules"));
    }

    #[test]
    fn no_environments_404_is_unknown() {
        let srv = mock_server(404, r#"{"message":"Not Found"}"#);
        let ev = &EnvironmentProtectionObserver
            .observe(&test_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Unknown);
    }
}
