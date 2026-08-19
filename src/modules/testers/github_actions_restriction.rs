use std::collections::HashMap;

use anyhow::{anyhow, Result};
use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

use crate::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId,
    TranscriptRecorder, EVIDENCE_SCHEMA_VERSION,
};
use crate::module::{
    tester::Tester, CredentialReq, EnvironmentScope, Module, SafetyClassification,
};
use crate::modules::github_common::{github_get, DEFAULT_GITHUB_API};

// ─── ActionsRestrictionTester ─────────────────────────────────────────────────

/// Actively verifies that GitHub Actions are restricted at the organization level.
/// Reads the `allowed_actions` field from the Actions permissions API and checks
/// whether it is set to `selected` or `local_only` (effective) vs `all` (ineffective).
///
/// Required config: `GITHUB_TOKEN`, `GITHUB_ORG`.
/// Optional: `GITHUB_API_URL` (test override — defaults to `https://api.github.com`).
pub struct ActionsRestrictionTester;

impl Module for ActionsRestrictionTester {
    fn id(&self) -> &str {
        "github.actions_restriction"
    }
    fn name(&self) -> &str {
        "GitHub Actions Restriction Tester"
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
                description:
                    "GitHub PAT with admin:org read access for reading actions permissions"
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

impl Tester for ActionsRestrictionTester {
    fn safety_class(&self) -> SafetyClassification {
        SafetyClassification::Observable
    }

    fn environment_scope(&self) -> EnvironmentScope {
        EnvironmentScope::Production
    }

    fn pre_flight_checks(&self) -> Vec<String> {
        vec![
            "Verify GITHUB_TOKEN has admin:org read access".to_string(),
            "Verify GITHUB_ORG is set".to_string(),
        ]
    }

    fn cleanup_procedures(&self) -> Vec<String> {
        vec![]
    }

    fn test(&self, config: &HashMap<String, String>) -> Result<Vec<Evidence>> {
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
        let mut recorder = TranscriptRecorder::new();
        let safety_class = "observable".to_string();

        let path = format!("/orgs/{}/actions/permissions", org);
        let endpoint = format!("{}{}", base_url.trim_end_matches('/'), path);

        recorder.record_action(
            "read organization actions permissions via GitHub API",
            Some(json!({
                "org": org,
                "endpoint": path,
            })),
        );

        let (body, status) = github_get(token, base_url, &path)?;

        if status == 403 {
            return Err(anyhow!(
                "GitHub API returned status 403 (Forbidden) for {}. \
                 Verify GITHUB_TOKEN has admin:org read access.",
                path
            ));
        }

        if status != 200 {
            return Err(anyhow!(
                "GitHub API returned status {} for {}",
                status,
                path
            ));
        }

        let allowed_actions = body
            .get("allowed_actions")
            .and_then(|v| v.as_str())
            .unwrap_or("all");

        let (status_id, status_text, findings) = if allowed_actions == "all" {
            recorder
                .record_observation("allowed_actions is 'all' — actions are unrestricted", false);
            (
                StatusId::Ineffective,
                format!(
                    "GitHub Actions are unrestricted for organization {}; allowed_actions = 'all'",
                    org
                ),
                vec![Finding {
                    title: "Actions Not Restricted".to_string(),
                    description: format!(
                        "Organization {} has GitHub Actions set to 'all', meaning any action from \
                         any repository can be used. Consider restricting to 'selected' or \
                         'local_only' to reduce supply-chain risk.",
                        org
                    ),
                    severity_id: 3,
                }],
            )
        } else {
            recorder.record_observation(
                format!(
                    "allowed_actions is '{}' — actions are restricted",
                    allowed_actions
                ),
                true,
            );
            (
                StatusId::Effective,
                format!(
                    "GitHub Actions are restricted for organization {}; allowed_actions = '{}'",
                    org, allowed_actions
                ),
                vec![Finding {
                    title: "Actions Restricted".to_string(),
                    description: format!(
                        "Organization {} restricts GitHub Actions to '{}' mode. \
                         The control GH-3.1 is operating effectively.",
                        org, allowed_actions
                    ),
                    severity_id: 0,
                }],
            )
        };

        recorder.record_cleanup("no cleanup required (read-only operation)", true);
        let transcript = recorder.finalize();

        Ok(vec![Evidence {
            schema_version: EVIDENCE_SCHEMA_VERSION.to_string(),
            connected_account: None,
            population: None,
            evaluation: None,
            id: Uuid::new_v4(),
            control_id: "GH-3.1".to_string(),
            class_uid: 1003,
            category_uid: 2,
            activity_id: 2,
            time: now,
            confidence_level: ConfidenceLevel::ActiveVerification,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "github.actions_restriction".to_string(),
                    version: "0.1.0".to_string(),
                    module_type: "tester".to_string(),
                },
                source: SourceInfo {
                    system: "github".to_string(),
                    api_version: "v3".to_string(),
                    endpoint,
                },
                original_time: None,
                processed_time: now,
                safety_classification: Some(safety_class),
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
            status: status_text,
            raw_data: body,
            findings,
            test_transcript: Some(transcript),
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
    fn actions_restriction_tester_id() {
        assert_eq!(ActionsRestrictionTester.id(), "github.actions_restriction");
    }

    #[test]
    fn actions_restriction_tester_name() {
        assert_eq!(
            ActionsRestrictionTester.name(),
            "GitHub Actions Restriction Tester"
        );
    }

    #[test]
    fn actions_restriction_tester_safety_class() {
        assert_eq!(
            ActionsRestrictionTester.safety_class(),
            SafetyClassification::Observable
        );
    }

    #[test]
    fn actions_restriction_tester_environment_scope() {
        assert_eq!(
            ActionsRestrictionTester.environment_scope(),
            EnvironmentScope::Production
        );
    }

    #[test]
    fn actions_restriction_tester_pre_flight_nonempty() {
        assert!(!ActionsRestrictionTester.pre_flight_checks().is_empty());
    }

    #[test]
    fn actions_restriction_tester_cleanup_empty() {
        assert!(ActionsRestrictionTester.cleanup_procedures().is_empty());
    }

    #[test]
    fn actions_restricted_selected_is_effective() {
        let srv = mock_server(
            200,
            r#"{"enabled_repositories":"all","allowed_actions":"selected"}"#,
        );
        let ev = &ActionsRestrictionTester
            .test(&test_config_with_org(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert!(ev.findings.iter().any(|f| f.title == "Actions Restricted"));
        assert_eq!(ev.control_id, "GH-3.1");
        assert_eq!(ev.confidence_level, ConfidenceLevel::ActiveVerification);
    }

    #[test]
    fn actions_unrestricted_all_is_ineffective_with_finding() {
        let srv = mock_server(
            200,
            r#"{"enabled_repositories":"all","allowed_actions":"all"}"#,
        );
        let ev = &ActionsRestrictionTester
            .test(&test_config_with_org(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "Actions Not Restricted"));
        assert_eq!(
            ev.findings
                .iter()
                .find(|f| f.title == "Actions Not Restricted")
                .unwrap()
                .severity_id,
            3
        );
    }

    #[test]
    fn actions_restriction_403_returns_err() {
        let srv = mock_server(403, r#"{"message":"Forbidden"}"#);
        let result = ActionsRestrictionTester.test(&test_config_with_org(&srv));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("403"));
    }
}
