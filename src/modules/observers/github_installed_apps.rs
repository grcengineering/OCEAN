use std::collections::HashMap;

use anyhow::{anyhow, Result};
use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

use crate::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId,
};
use crate::module::{observer::Observer, CredentialReq, Module};
use crate::modules::github_common::{github_get, DEFAULT_GITHUB_API};

// ─── InstalledAppsObserver ───────────────────────────────────────────────────

/// Checks the number of GitHub Apps installed in the organization. A small
/// number of installed apps indicates a well-governed third-party access
/// posture (GH-4.2). More than 10 apps is flagged as ineffective.
///
/// Required config: `GITHUB_TOKEN`, `GITHUB_ORG`.
/// Optional: `GITHUB_API_URL` (test override).
pub struct InstalledAppsObserver;

impl Module for InstalledAppsObserver {
    fn id(&self) -> &str {
        "github.installed_apps"
    }
    fn name(&self) -> &str {
        "GitHub Installed Apps Observer"
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
                description: "GitHub PAT with admin:org scope for reading installed apps"
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

impl Observer for InstalledAppsObserver {
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
        let path = format!("/orgs/{}/installations", org);
        let endpoint = format!("{}{}", base_url.trim_end_matches('/'), &path);

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
            .unwrap_or(0) as usize;

        let app_slugs: Vec<serde_json::Value> = body
            .get("installations")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|app| {
                        app.get("app_slug")
                            .and_then(|s| s.as_str())
                            .map(|s| serde_json::Value::String(s.to_string()))
                    })
                    .collect()
            })
            .unwrap_or_default();

        let raw_data = json!({
            "total_apps": total_count,
            "apps": app_slugs,
        });

        let (status_id, findings) = if total_count <= 5 {
            (
                StatusId::Effective,
                vec![Finding {
                    title: "Low App Count".to_string(),
                    description: format!(
                        "Organization {} has {} installed GitHub App(s), within the vetted \
                         threshold of 5. Third-party app access appears well-governed (GH-4.2).",
                        org, total_count
                    ),
                    severity_id: 0,
                }],
            )
        } else if total_count <= 10 {
            (
                StatusId::Effective,
                vec![Finding {
                    title: "Moderate App Count".to_string(),
                    description: format!(
                        "Organization {} has {} installed GitHub App(s). This is within acceptable \
                         range but consider reviewing apps for necessity (GH-4.2).",
                        org, total_count
                    ),
                    severity_id: 1,
                }],
            )
        } else {
            (
                StatusId::Ineffective,
                vec![Finding {
                    title: "High App Count".to_string(),
                    description: format!(
                        "Organization {} has {} installed GitHub App(s), exceeding the threshold \
                         of 10. Review and remove unnecessary third-party apps to satisfy GH-4.2.",
                        org, total_count
                    ),
                    severity_id: 2,
                }],
            )
        };

        let status_msg = if status_id == StatusId::Effective {
            format!(
                "Installed app count ({}) is within acceptable limits for organization {}",
                total_count, org
            )
        } else {
            format!(
                "Installed app count ({}) exceeds threshold for organization {}",
                total_count, org
            )
        };

        Ok(vec![Evidence {
            id: Uuid::new_v4(),
            control_id: "GH-4.2".to_string(),
            class_uid: 1003,
            category_uid: 2,
            activity_id: 1,
            time: now,
            confidence_level: ConfidenceLevel::PassiveObservation,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "github.installed_apps".to_string(),
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
                    value: format!("{}:installed_apps", org),
                    name: String::new(),
                },
                Observable {
                    obs_type: "count".to_string(),
                    value: total_count.to_string(),
                    name: "installed_apps".to_string(),
                },
            ],
            status_id,
            status: status_msg,
            raw_data,
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
    fn two_apps_is_effective() {
        let srv = mock_server(
            200,
            r#"{"total_count":2,"installations":[{"app_slug":"dependabot"},{"app_slug":"codecov"}]}"#,
        );
        let ev = &InstalledAppsObserver
            .observe(&test_config_with_org(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert_eq!(ev.raw_data["total_apps"], 2);
        assert!(ev.observables.iter().any(|o| o.obs_type == "count"
            && o.name == "installed_apps"
            && o.value == "2"));
    }

    #[test]
    fn eleven_apps_is_ineffective_with_finding() {
        let apps: Vec<serde_json::Value> = (0..11)
            .map(|i| json!({"app_slug": format!("app-{}", i)}))
            .collect();
        let body = json!({"total_count": 11, "installations": apps}).to_string();
        let srv = mock_server(200, &body);
        let ev = &InstalledAppsObserver
            .observe(&test_config_with_org(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev.findings.iter().any(|f| f.title == "High App Count"));
        assert_eq!(ev.raw_data["total_apps"], 11);
    }

    #[test]
    fn five_apps_boundary_is_effective() {
        let apps: Vec<serde_json::Value> = (0..5)
            .map(|i| json!({"app_slug": format!("app-{}", i)}))
            .collect();
        let body = json!({"total_count": 5, "installations": apps}).to_string();
        let srv = mock_server(200, &body);
        let ev = &InstalledAppsObserver
            .observe(&test_config_with_org(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert_eq!(ev.raw_data["total_apps"], 5);
    }
}
