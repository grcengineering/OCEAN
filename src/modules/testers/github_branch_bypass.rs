use std::collections::HashMap;

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::Utc;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId,
    TranscriptRecorder, EVIDENCE_SCHEMA_VERSION,
};
use crate::module::{
    tester::Tester, CredentialReq, EnvironmentScope, Module, SafetyClassification,
};

// ─── Constants ────────────────────────────────────────────────────────────────

const TEST_FILE_PATH: &str = ".ocean-test/branch-bypass-test.txt";

// ─── BranchBypassTester ─────────────────────────────────────────────────────

/// Attempts to push a file directly to the default branch of a GitHub
/// repository via the Contents API. Records whether branch protection
/// blocks the attempt. Classified as Observable because it creates audit
/// trail entries but causes no lasting damage when protection is active.
///
/// Required config: `GITHUB_TOKEN`, `GITHUB_OWNER`, `GITHUB_REPO`.
/// Optional: `GITHUB_API_URL` (test override — defaults to `https://api.github.com`).
pub struct BranchBypassTester;

impl Module for BranchBypassTester {
    fn id(&self) -> &str {
        "github.branch_bypass"
    }
    fn name(&self) -> &str {
        "GitHub Branch Protection Bypass Test"
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
                description: "GitHub personal access token with repo scope for creating and deleting files via Contents API".to_string(),
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
                description: "GitHub repository name (must be a test/staging repository)".to_string(),
                required: true,
            },
        ]
    }
}

impl Tester for BranchBypassTester {
    fn safety_class(&self) -> SafetyClassification {
        SafetyClassification::Observable
    }
    fn environment_scope(&self) -> EnvironmentScope {
        EnvironmentScope::Staging
    }

    fn pre_flight_checks(&self) -> Vec<String> {
        vec![
            "verify GitHub token has write access".to_string(),
            "verify repository is a test/staging repository".to_string(),
            "document: this test creates audit trail entries in GitHub".to_string(),
        ]
    }

    fn cleanup_procedures(&self) -> Vec<String> {
        vec!["delete test file if created".to_string()]
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
        let base_url = config
            .get("GITHUB_API_URL")
            .map(|s| s.trim_end_matches('/').to_string())
            .unwrap_or_else(|| "https://api.github.com".to_string());

        let now = Utc::now();
        let mut recorder = TranscriptRecorder::new();
        let safety_class = "observable".to_string();

        let endpoint = format!("/repos/{}/{}/contents/{}", owner, repo, TEST_FILE_PATH);
        let url = format!("{}{}", base_url, endpoint);

        recorder.record_action(
            "attempt to create file directly on default branch via Contents API",
            Some(json!({
                "owner": owner,
                "repo": repo,
                "path": TEST_FILE_PATH,
                "endpoint": endpoint,
            })),
        );

        // Encode test file content as base64 (GitHub Contents API requirement).
        let file_content =
            "# OCEAN Branch Protection Test\n# Testing direct push to default branch\n";
        let encoded_content = BASE64.encode(file_content.as_bytes());

        let create_resp = ureq::put(&url)
            .set("Authorization", &format!("Bearer {}", token))
            .set("Accept", "application/vnd.github+json")
            .set("X-GitHub-Api-Version", "2022-11-28")
            .send_json(json!({
                "message": "ocean: branch protection bypass test (will be cleaned up)",
                "content": encoded_content,
            }));

        let (status_code, resp_body): (u16, Value) = match create_resp {
            Ok(r) => {
                let code = r.status();
                let body = r.into_json().unwrap_or(json!({}));
                (code, body)
            }
            Err(ureq::Error::Status(code, r)) => {
                let body = r.into_json().unwrap_or(json!({}));
                (code, body)
            }
            Err(e) => return Err(anyhow!("GitHub API request failed: {}", e)),
        };

        let mut file_sha: Option<String> = None;

        let (status_id, status_text, mut findings) = match status_code {
            403 => {
                recorder.record_observation(
                    "branch protection blocked the direct push with HTTP 403",
                    true,
                );
                (
                    StatusId::Effective,
                    "GitHub branch protection correctly blocked a direct push to the default branch"
                        .to_string(),
                    vec![Finding {
                        title: "Direct Push Blocked".to_string(),
                        description: format!(
                            "GitHub branch protection blocked an attempt to push a file directly \
                             to the default branch of {}/{} with HTTP 403. \
                             The control is operating effectively.",
                            owner, repo
                        ),
                        severity_id: 0,
                    }],
                )
            }
            422 => {
                recorder.record_observation(
                    "branch protection blocked the direct push with HTTP 422",
                    true,
                );
                (
                    StatusId::Effective,
                    "GitHub branch protection correctly blocked a direct push to the default branch"
                        .to_string(),
                    vec![Finding {
                        title: "Direct Push Blocked".to_string(),
                        description: format!(
                            "GitHub branch protection blocked an attempt to push a file directly \
                             to the default branch of {}/{} with HTTP 422. \
                             The control is operating effectively.",
                            owner, repo
                        ),
                        severity_id: 0,
                    }],
                )
            }
            201 => {
                recorder.record_observation(
                    "direct push to default branch was NOT blocked, file was created successfully",
                    false,
                );
                // Extract SHA for cleanup.
                file_sha = resp_body
                    .get("content")
                    .and_then(|c| c.get("sha"))
                    .and_then(|s| s.as_str())
                    .map(|s| s.to_string());
                (
                    StatusId::Ineffective,
                    format!(
                        "GitHub branch protection did NOT block a direct push to the default branch of {}/{}",
                        owner, repo
                    ),
                    vec![Finding {
                        title: "Direct Push Not Blocked".to_string(),
                        description: format!(
                            "A file was successfully pushed directly to the default branch of \
                             {}/{}. Branch protection is either disabled or not enforced. \
                             The test file will be cleaned up.",
                            owner, repo
                        ),
                        severity_id: 4,
                    }],
                )
            }
            other => {
                recorder.record_observation(
                    format!("unexpected HTTP status {} from Contents API", other),
                    false,
                );
                (
                    StatusId::Unknown,
                    format!(
                        "Unexpected response (HTTP {}) when testing branch protection on {}/{}",
                        other, owner, repo
                    ),
                    vec![Finding {
                        title: "Unexpected API Response".to_string(),
                        description: format!(
                            "The GitHub Contents API returned HTTP {} when attempting to push \
                             a file directly to the default branch. This may indicate insufficient \
                             permissions, a nonexistent repository, or an API error.",
                            other
                        ),
                        severity_id: 2,
                    }],
                )
            }
        };

        // Cleanup: delete the test file if it was created.
        let file_created = file_sha.is_some();
        if let Some(ref sha) = file_sha {
            recorder.record_action(
                "delete test file created during branch protection bypass test",
                Some(json!({ "path": TEST_FILE_PATH, "sha": sha })),
            );

            let delete_resp = ureq::delete(&url)
                .set("Authorization", &format!("Bearer {}", token))
                .set("Accept", "application/vnd.github+json")
                .set("X-GitHub-Api-Version", "2022-11-28")
                .send_json(json!({
                    "message": "ocean: clean up branch protection bypass test file",
                    "sha": sha,
                }));

            let delete_ok = match delete_resp {
                Ok(r) => r.status() == 200 || r.status() == 204,
                Err(ureq::Error::Status(code, _)) => code == 200 || code == 204,
                Err(_) => false,
            };

            if delete_ok {
                recorder.record_cleanup("delete test file if created", true);
            } else {
                recorder.record_cleanup("delete test file if created", false);
                findings.push(Finding {
                    title: "Cleanup Failed".to_string(),
                    description: format!(
                        "Failed to delete the test file {} from {}/{}. Manual cleanup may be required.",
                        TEST_FILE_PATH, owner, repo
                    ),
                    severity_id: 2,
                });
            }
        } else {
            // No file was created — cleanup is a no-op.
            recorder.record_cleanup("delete test file if created", true);
        }

        let transcript = recorder.finalize();
        let raw_data = json!({
            "test_scenario": "branch_protection_bypass",
            "target_repo": format!("{}/{}", owner, repo),
            "test_file_path": TEST_FILE_PATH,
            "http_status": status_code,
            "push_blocked": status_id == StatusId::Effective,
            "file_created": file_created,
        });

        Ok(vec![Evidence {
            schema_version: EVIDENCE_SCHEMA_VERSION.to_string(),
            connected_account: None,
            population: None,
            evaluation: None,
            id: Uuid::new_v4(),
            control_id: "scm.branch_protection".to_string(),
            class_uid: 1003,
            category_uid: 2,
            activity_id: 2,
            time: now,
            confidence_level: ConfidenceLevel::ActiveVerification,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "github.branch_bypass".to_string(),
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
                    value: format!("{}/{}:{}", owner, repo, TEST_FILE_PATH),
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

    /// Mock server that handles sequential connections, returning the
    /// responses in order. Each response is `(status_code, body)`.
    fn mock_server(responses: Vec<(u16, &'static str)>) -> String {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let responses: Vec<(u16, String)> = responses
            .into_iter()
            .map(|(s, b)| (s, b.to_string()))
            .collect();

        thread::spawn(move || {
            for (status, body) in responses {
                if let Ok((mut stream, _)) = listener.accept() {
                    let mut buf = [0u8; 16384];
                    let _ = stream.read(&mut buf);
                    let resp = format!(
                        "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n\
                         Content-Length: {len}\r\nConnection: close\r\n\r\n{body}",
                        len = body.len()
                    );
                    let _ = stream.write_all(resp.as_bytes());
                    let _ = stream.shutdown(std::net::Shutdown::Write);
                    let mut drain = [0u8; 256];
                    while matches!(stream.read(&mut drain), Ok(n) if n > 0) {}
                }
            }
        });

        format!("http://127.0.0.1:{}", addr.port())
    }

    fn base_config(api_url: &str) -> HashMap<String, String> {
        HashMap::from([
            ("GITHUB_TOKEN".to_string(), "ghp_test".to_string()),
            ("GITHUB_OWNER".to_string(), "test-org".to_string()),
            ("GITHUB_REPO".to_string(), "test-repo".to_string()),
            ("GITHUB_API_URL".to_string(), api_url.to_string()),
        ])
    }

    // ── Metadata ─────────────────────────────────────────────────────────────

    #[test]
    fn branch_bypass_tester_id() {
        assert_eq!(BranchBypassTester.id(), "github.branch_bypass");
    }

    #[test]
    fn branch_bypass_tester_name() {
        assert_eq!(
            BranchBypassTester.name(),
            "GitHub Branch Protection Bypass Test"
        );
    }

    #[test]
    fn branch_bypass_tester_version() {
        assert_eq!(BranchBypassTester.version(), "0.1.0");
    }

    #[test]
    fn branch_bypass_tester_source_system() {
        assert_eq!(BranchBypassTester.source_system(), "github");
    }

    // ── Safety / Scope ───────────────────────────────────────────────────────

    #[test]
    fn branch_bypass_tester_safety_class() {
        assert_eq!(
            BranchBypassTester.safety_class(),
            SafetyClassification::Observable
        );
    }

    #[test]
    fn branch_bypass_tester_environment_scope() {
        assert_eq!(
            BranchBypassTester.environment_scope(),
            EnvironmentScope::Staging
        );
    }

    // ── Config validation ────────────────────────────────────────────────────

    #[test]
    fn missing_token_errors() {
        let config = HashMap::from([
            ("GITHUB_OWNER".to_string(), "org".to_string()),
            ("GITHUB_REPO".to_string(), "repo".to_string()),
        ]);
        let err = BranchBypassTester.test(&config).unwrap_err();
        assert!(err.to_string().contains("GITHUB_TOKEN"));
    }

    #[test]
    fn missing_owner_errors() {
        let config = HashMap::from([
            ("GITHUB_TOKEN".to_string(), "tok".to_string()),
            ("GITHUB_REPO".to_string(), "repo".to_string()),
        ]);
        let err = BranchBypassTester.test(&config).unwrap_err();
        assert!(err.to_string().contains("GITHUB_OWNER"));
    }

    #[test]
    fn missing_repo_errors() {
        let config = HashMap::from([
            ("GITHUB_TOKEN".to_string(), "tok".to_string()),
            ("GITHUB_OWNER".to_string(), "org".to_string()),
        ]);
        let err = BranchBypassTester.test(&config).unwrap_err();
        assert!(err.to_string().contains("GITHUB_REPO"));
    }

    // ── HTTP integration ─────────────────────────────────────────────────────

    const BLOCKED_BODY: &str = r#"{"message":"Branch protection rule violation"}"#;

    const CREATED_BODY: &str =
        r#"{"content":{"sha":"abc123def456","name":"branch-bypass-test.txt"},"commit":{}}"#;

    const DELETE_OK_BODY: &str = r#"{"commit":{"sha":"xyz789"}}"#;

    #[test]
    fn push_403_is_effective() {
        let srv = mock_server(vec![(403, BLOCKED_BODY)]);
        let ev = &BranchBypassTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert!(ev.findings.iter().any(|f| f.title == "Direct Push Blocked"));
        assert_eq!(ev.class_uid, 1003);
        assert_eq!(ev.control_id, "scm.branch_protection");
    }

    #[test]
    fn push_422_is_effective() {
        let srv = mock_server(vec![(422, BLOCKED_BODY)]);
        let ev = &BranchBypassTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert!(ev.findings.iter().any(|f| f.title == "Direct Push Blocked"));
    }

    #[test]
    fn push_201_is_ineffective_and_cleanup_succeeds() {
        // Two responses: 201 for create, 200 for delete.
        let srv = mock_server(vec![(201, CREATED_BODY), (200, DELETE_OK_BODY)]);
        let ev = &BranchBypassTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "Direct Push Not Blocked"));
        // No cleanup failure finding.
        assert!(!ev.findings.iter().any(|f| f.title == "Cleanup Failed"));
    }

    #[test]
    fn push_201_cleanup_failure_recorded() {
        // Two responses: 201 for create, 500 for failed delete.
        let srv = mock_server(vec![
            (201, CREATED_BODY),
            (500, r#"{"message":"Internal Server Error"}"#),
        ]);
        let ev = &BranchBypassTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev.findings.iter().any(|f| f.title == "Cleanup Failed"));
    }

    #[test]
    fn push_500_is_unknown() {
        let srv = mock_server(vec![(500, r#"{"message":"Internal Server Error"}"#)]);
        let ev = &BranchBypassTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Unknown);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "Unexpected API Response"));
    }
}
