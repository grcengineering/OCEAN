use std::collections::HashMap;

use anyhow::{anyhow, Result};
use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

use crate::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId,
    TranscriptRecorder,
};
use crate::module::{
    tester::Tester, CredentialReq, EnvironmentScope, Module, SafetyClassification,
};
use crate::modules::github_common::{github_get, DEFAULT_GITHUB_API};

// ─── UnsignedCommitTester ─────────────────────────────────────────────────────

/// Verifies that unsigned commits are rejected by checking whether required
/// commit signing is enforced on the target branch via the branch protection API.
///
/// Required config: `GITHUB_TOKEN`, `GITHUB_OWNER`, `GITHUB_REPO`.
/// Optional: `GITHUB_BRANCH` (defaults to `main`), `GITHUB_API_URL` (test override).
pub struct UnsignedCommitTester;

impl Module for UnsignedCommitTester {
    fn id(&self) -> &str {
        "github.unsigned_commit"
    }
    fn name(&self) -> &str {
        "GitHub Unsigned Commit Tester"
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
                description: "GitHub PAT with repo access for reading branch protection rules"
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

impl Tester for UnsignedCommitTester {
    fn safety_class(&self) -> SafetyClassification {
        SafetyClassification::Observable
    }

    fn environment_scope(&self) -> EnvironmentScope {
        EnvironmentScope::Production
    }

    fn pre_flight_checks(&self) -> Vec<String> {
        vec![
            "Verify GITHUB_TOKEN has repo access".to_string(),
            "Verify GITHUB_OWNER and GITHUB_REPO are set".to_string(),
        ]
    }

    fn cleanup_procedures(&self) -> Vec<String> {
        vec![]
    }

    fn test(&self, config: &HashMap<String, String>) -> Result<Vec<Evidence>> {
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
        let mut recorder = TranscriptRecorder::new();
        let safety_class = "observable".to_string();

        let path = format!(
            "/repos/{}/{}/branches/{}/protection/required_signatures",
            owner, repo, branch
        );
        let endpoint = format!("{}{}", base_url.trim_end_matches('/'), path);

        recorder.record_action(
            "read branch protection required signatures via GitHub API",
            Some(json!({
                "owner": owner,
                "repo": repo,
                "branch": branch,
                "endpoint": path,
            })),
        );

        let (body, status) = github_get(token, base_url, &path)?;

        if status == 403 {
            return Err(anyhow!(
                "GitHub API returned status 403 (Forbidden) for {}. \
                 Verify GITHUB_TOKEN has repo access.",
                path
            ));
        }

        let (status_id, status_text, findings) = if status == 200 {
            let enabled = body
                .get("enabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            if enabled {
                recorder.record_observation(
                    "required_signatures.enabled is true — commit signing enforced",
                    true,
                );
                (
                    StatusId::Effective,
                    format!(
                        "Commit signing is enforced on branch '{}' of {}/{}",
                        branch, owner, repo
                    ),
                    vec![Finding {
                        title: "Commit Signing Enforced".to_string(),
                        description: format!(
                            "Branch '{}' of {}/{} requires signed commits. \
                             Unsigned commits will be rejected. Control GH-2.4 is operating effectively.",
                            branch, owner, repo
                        ),
                        severity_id: 0,
                    }],
                )
            } else {
                recorder.record_observation(
                    "required_signatures.enabled is false — commit signing not enforced",
                    false,
                );
                (
                    StatusId::Ineffective,
                    format!(
                        "Commit signing is NOT enforced on branch '{}' of {}/{}",
                        branch, owner, repo
                    ),
                    vec![Finding {
                        title: "Commit Signing Not Enforced".to_string(),
                        description: format!(
                            "Branch '{}' of {}/{} does not require signed commits. \
                             Unsigned commits are accepted, which cannot guarantee commit authorship integrity.",
                            branch, owner, repo
                        ),
                        severity_id: 3,
                    }],
                )
            }
        } else if status == 404 {
            // 404 means required signatures are not configured at all.
            recorder.record_observation(
                "required signatures endpoint returned 404 — signing not configured",
                false,
            );
            (
                StatusId::Ineffective,
                format!(
                    "Required commit signing is not configured on branch '{}' of {}/{}",
                    branch, owner, repo
                ),
                vec![Finding {
                    title: "Commit Signing Not Configured".to_string(),
                    description: format!(
                        "Branch '{}' of {}/{} has no required signatures protection rule. \
                         Unsigned commits are accepted, which cannot guarantee commit authorship integrity.",
                        branch, owner, repo
                    ),
                    severity_id: 3,
                }],
            )
        } else {
            return Err(anyhow!(
                "GitHub API returned unexpected status {} for {}",
                status,
                path
            ));
        };

        recorder.record_cleanup("no cleanup required (read-only operation)", true);
        let transcript = recorder.finalize();

        let raw_data = json!({
            "owner": owner,
            "repo": repo,
            "branch": branch,
            "http_status": status,
            "signing_enforced": status_id == StatusId::Effective,
            "api_response": body,
        });

        Ok(vec![Evidence {
            id: Uuid::new_v4(),
            control_id: "GH-2.4".to_string(),
            class_uid: 1003,
            category_uid: 2,
            activity_id: 2,
            time: now,
            confidence_level: ConfidenceLevel::ActiveVerification,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "github.unsigned_commit".to_string(),
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
            status: status_text,
            raw_data,
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
    use crate::modules::github_common::{mock_server, test_config};

    #[test]
    fn unsigned_commit_tester_id() {
        assert_eq!(UnsignedCommitTester.id(), "github.unsigned_commit");
    }

    #[test]
    fn unsigned_commit_tester_name() {
        assert_eq!(UnsignedCommitTester.name(), "GitHub Unsigned Commit Tester");
    }

    #[test]
    fn unsigned_commit_tester_safety_class() {
        assert_eq!(
            UnsignedCommitTester.safety_class(),
            SafetyClassification::Observable
        );
    }

    #[test]
    fn unsigned_commit_tester_environment_scope() {
        assert_eq!(
            UnsignedCommitTester.environment_scope(),
            EnvironmentScope::Production
        );
    }

    #[test]
    fn unsigned_commit_tester_pre_flight_nonempty() {
        assert!(!UnsignedCommitTester.pre_flight_checks().is_empty());
    }

    #[test]
    fn unsigned_commit_tester_cleanup_empty() {
        assert!(UnsignedCommitTester.cleanup_procedures().is_empty());
    }

    #[test]
    fn signing_enabled_is_effective() {
        let srv = mock_server(
            200,
            r#"{"enabled":true,"url":"https://api.github.com/repos/acme/app/branches/main/protection/required_signatures"}"#,
        );
        let ev = &UnsignedCommitTester.test(&test_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "Commit Signing Enforced"));
        assert_eq!(ev.control_id, "GH-2.4");
        assert_eq!(ev.confidence_level, ConfidenceLevel::ActiveVerification);
    }

    #[test]
    fn signing_not_configured_404_is_ineffective_with_finding() {
        let srv = mock_server(404, r#"{"message":"Branch not protected"}"#);
        let ev = &UnsignedCommitTester.test(&test_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "Commit Signing Not Configured"));
        assert!(
            ev.findings
                .iter()
                .find(|f| f.title == "Commit Signing Not Configured")
                .unwrap()
                .severity_id
                > 0
        );
    }

    #[test]
    fn signing_403_returns_err() {
        let srv = mock_server(403, r#"{"message":"Forbidden"}"#);
        let result = UnsignedCommitTester.test(&test_config(&srv));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("403"));
    }

    #[test]
    fn missing_token_errors() {
        let config = HashMap::from([
            ("GITHUB_OWNER".to_string(), "org".to_string()),
            ("GITHUB_REPO".to_string(), "repo".to_string()),
        ]);
        let err = UnsignedCommitTester.test(&config).unwrap_err();
        assert!(err.to_string().contains("GITHUB_TOKEN"));
    }

    #[test]
    fn missing_owner_errors() {
        let config = HashMap::from([
            ("GITHUB_TOKEN".to_string(), "tok".to_string()),
            ("GITHUB_REPO".to_string(), "repo".to_string()),
        ]);
        let err = UnsignedCommitTester.test(&config).unwrap_err();
        assert!(err.to_string().contains("GITHUB_OWNER"));
    }

    #[test]
    fn missing_repo_errors() {
        let config = HashMap::from([
            ("GITHUB_TOKEN".to_string(), "tok".to_string()),
            ("GITHUB_OWNER".to_string(), "org".to_string()),
        ]);
        let err = UnsignedCommitTester.test(&config).unwrap_err();
        assert!(err.to_string().contains("GITHUB_REPO"));
    }

    #[test]
    fn signing_disabled_200_is_ineffective() {
        let srv = mock_server(200, r#"{"enabled":false,"url":"..."}"#);
        let ev = &UnsignedCommitTester.test(&test_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "Commit Signing Not Enforced"));
        assert!(
            ev.findings
                .iter()
                .find(|f| f.title == "Commit Signing Not Enforced")
                .unwrap()
                .severity_id
                > 0
        );
    }

    #[test]
    fn unexpected_status_returns_err() {
        // Any status besides 200, 403, 404 should return Err.
        let srv = mock_server(500, r#"{"message":"Internal Server Error"}"#);
        let result = UnsignedCommitTester.test(&test_config(&srv));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("500"));
    }

    #[test]
    fn custom_branch_used_in_endpoint() {
        let srv = mock_server(200, r#"{"enabled":true}"#);
        let mut cfg = test_config(&srv);
        cfg.insert("GITHUB_BRANCH".to_string(), "develop".to_string());
        let ev = &UnsignedCommitTester.test(&cfg).unwrap()[0];
        // Effective result still returned; branch was used.
        assert_eq!(ev.status_id, StatusId::Effective);
        // The status text should mention the branch.
        assert!(ev.status.contains("develop"));
    }

    #[test]
    fn metadata_complete() {
        use crate::module::Module;
        use crate::module::Tester;
        let t = UnsignedCommitTester;
        assert_eq!(t.id(), "github.unsigned_commit");
        assert!(!t.name().is_empty());
        assert_eq!(t.version(), "0.1.0");
        assert_eq!(t.source_system(), "github");
        assert!(!t.evidence_types().is_empty());
        let creds = t.credential_requirements();
        assert!(!creds.is_empty());
        assert!(creds.iter().any(|c| c.name == "GITHUB_TOKEN"));
        assert!(creds.iter().any(|c| c.name == "GITHUB_OWNER"));
        assert!(creds.iter().any(|c| c.name == "GITHUB_REPO"));
        // Tester trait methods
        let _safety = t.safety_class();
        let _scope = t.environment_scope();
        let _pre = t.pre_flight_checks();
        let _cleanup = t.cleanup_procedures();
    }
}
