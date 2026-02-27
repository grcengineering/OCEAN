use std::collections::HashMap;

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::Utc;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId,
    TranscriptRecorder,
};
use crate::module::{
    tester::Tester, CredentialReq, EnvironmentScope, Module, SafetyClassification,
};

// ─── Constants ────────────────────────────────────────────────────────────────

const TEST_FILE_PATH: &str = ".ocean-test/secret-push-test.txt";

/// A well-known test secret in GitHub PAT format that push protection detects.
const TEST_SECRET: &str = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef01";

// ─── SecretPushTester ─────────────────────────────────────────────────────────

/// Attempts to push a file containing a known test secret string to a GitHub
/// repository via the Contents API. Records whether GitHub's push protection
/// blocks the attempt. Classified as Observable because it creates audit trail
/// entries in GitHub; when push protection works the file is never committed.
///
/// Required config: `GITHUB_TOKEN`, `GITHUB_OWNER`, `GITHUB_REPO`.
/// Optional: `GITHUB_API_URL` (test override — defaults to `https://api.github.com`).
pub struct SecretPushTester;

impl Module for SecretPushTester {
    fn id(&self) -> &str { "github.secret_push" }
    fn name(&self) -> &str { "GitHub Secret Push Protection Test" }
    fn version(&self) -> &str { "0.1.0" }
    fn source_system(&self) -> &str { "github" }
    fn evidence_types(&self) -> &[i32] { &[1003] }

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

impl Tester for SecretPushTester {
    fn safety_class(&self) -> SafetyClassification { SafetyClassification::Observable }
    fn environment_scope(&self) -> EnvironmentScope { EnvironmentScope::Staging }

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
            "attempt to create file containing test secret via Contents API",
            Some(json!({
                "owner": owner,
                "repo": repo,
                "path": TEST_FILE_PATH,
                "secret": "ghp_ABCDEFGHIJ... (GitHub PAT format test string)",
                "endpoint": endpoint,
            })),
        );

        // Encode test secret content as base64 (GitHub Contents API requirement).
        let file_content = format!(
            "# OCEAN Secret Push Protection Test\n\
             # This file is created by the ocean github.secret_push tester.\n\
             # It will be automatically cleaned up.\n\n\
             TEST_TOKEN={}\n",
            TEST_SECRET
        );
        let encoded_content = BASE64.encode(file_content.as_bytes());

        let create_resp = ureq::put(&url)
            .set("Authorization", &format!("Bearer {}", token))
            .set("Accept", "application/vnd.github+json")
            .set("X-GitHub-Api-Version", "2022-11-28")
            .send_json(json!({
                "message": "ocean: secret push protection test (will be cleaned up)",
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
            409 => {
                recorder.record_observation(
                    "push protection blocked the secret push with HTTP 409",
                    true,
                );
                (
                    StatusId::Effective,
                    "GitHub push protection correctly blocked a test secret push".to_string(),
                    vec![Finding {
                        title: "Secret Push Blocked".to_string(),
                        description: format!(
                            "GitHub push protection blocked an attempt to push a file containing \
                             a test secret (GitHub PAT format) to {}/{} with HTTP 409. \
                             The control is operating effectively.",
                            owner, repo
                        ),
                        severity_id: 0,
                    }],
                )
            }
            422 => {
                recorder.record_observation(
                    "push protection blocked the secret push with HTTP 422",
                    true,
                );
                (
                    StatusId::Effective,
                    "GitHub push protection correctly blocked a test secret push".to_string(),
                    vec![Finding {
                        title: "Secret Push Blocked".to_string(),
                        description: format!(
                            "GitHub push protection blocked an attempt to push a file containing \
                             a test secret to {}/{} with HTTP 422. \
                             The control is operating effectively.",
                            owner, repo
                        ),
                        severity_id: 0,
                    }],
                )
            }
            201 => {
                recorder.record_observation(
                    "secret push was NOT blocked, file was created successfully",
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
                        "GitHub push protection did NOT block a test secret push to {}/{}",
                        owner, repo
                    ),
                    vec![Finding {
                        title: "Secret Push Not Blocked".to_string(),
                        description: format!(
                            "A file containing a test secret (GitHub PAT format) was successfully \
                             pushed to {}/{}. Push protection is either disabled or not detecting \
                             this secret pattern. The test file will be cleaned up.",
                            owner, repo
                        ),
                        severity_id: 4,
                    }],
                )
            }
            other => {
                recorder.record_observation(
                    &format!("unexpected HTTP status {} from Contents API", other),
                    false,
                );
                (
                    StatusId::Unknown,
                    format!(
                        "Unexpected response (HTTP {}) when testing push protection on {}/{}",
                        other, owner, repo
                    ),
                    vec![Finding {
                        title: "Unexpected API Response".to_string(),
                        description: format!(
                            "The GitHub Contents API returned HTTP {} when attempting to push \
                             a test secret. This may indicate insufficient permissions, a \
                             nonexistent repository, or an API error.",
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
                "delete test file created during secret push test",
                Some(json!({ "path": TEST_FILE_PATH, "sha": sha })),
            );

            let delete_resp = ureq::delete(&url)
                .set("Authorization", &format!("Bearer {}", token))
                .set("Accept", "application/vnd.github+json")
                .set("X-GitHub-Api-Version", "2022-11-28")
                .send_json(json!({
                    "message": "ocean: clean up secret push protection test file",
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
            "test_scenario": "secret_push_protection",
            "target_repo": format!("{}/{}", owner, repo),
            "test_file_path": TEST_FILE_PATH,
            "secret_pattern": "github_pat_format",
            "http_status": status_code,
            "push_blocked": status_id == StatusId::Effective,
            "file_created": file_created,
        });

        Ok(vec![Evidence {
            id: Uuid::new_v4(),
            control_id: "scm.secret_push_protection".to_string(),
            class_uid: 1003,
            category_uid: 2,
            activity_id: 2,
            time: now,
            confidence_level: ConfidenceLevel::ActiveVerification,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "github.secret_push".to_string(),
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
                },
                Observable {
                    obs_type: "domain".to_string(),
                    value: "github.com".to_string(),
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

    /// Mock server that handles `n_requests` sequential connections, returning
    /// the responses in order. Each response is `(status_code, body)`.
    fn mock_server(responses: Vec<(u16, &'static str)>) -> String {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let responses: Vec<(u16, String)> =
            responses.into_iter().map(|(s, b)| (s, b.to_string())).collect();

        thread::spawn(move || {
            for (status, body) in responses {
                if let Ok((mut stream, _)) = listener.accept() {
                    // Drain the full request to avoid Windows TCP RST on close.
                    let mut buf = [0u8; 16384];
                    let _ = stream.read(&mut buf);
                    let resp = format!(
                        "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n\
                         Content-Length: {len}\r\nConnection: close\r\n\r\n{body}",
                        len = body.len()
                    );
                    let _ = stream.write_all(resp.as_bytes());
                    // Graceful shutdown: send FIN, drain remaining data, then drop.
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
    fn secret_push_tester_id() { assert_eq!(SecretPushTester.id(), "github.secret_push"); }

    #[test]
    fn secret_push_tester_name() {
        assert_eq!(SecretPushTester.name(), "GitHub Secret Push Protection Test");
    }

    #[test]
    fn secret_push_tester_version() { assert_eq!(SecretPushTester.version(), "0.1.0"); }

    #[test]
    fn secret_push_tester_source_system() {
        assert_eq!(SecretPushTester.source_system(), "github");
    }

    #[test]
    fn secret_push_tester_evidence_types() {
        assert_eq!(SecretPushTester.evidence_types(), &[1003]);
    }

    #[test]
    fn secret_push_tester_credential_requirements() {
        let reqs = SecretPushTester.credential_requirements();
        assert_eq!(reqs.len(), 3);
        assert!(reqs.iter().any(|r| r.name == "GITHUB_TOKEN" && r.required));
        assert!(reqs.iter().any(|r| r.name == "GITHUB_OWNER" && r.required));
        assert!(reqs.iter().any(|r| r.name == "GITHUB_REPO" && r.required));
    }

    #[test]
    fn secret_push_tester_safety_class() {
        assert_eq!(SecretPushTester.safety_class(), SafetyClassification::Observable);
    }

    #[test]
    fn secret_push_tester_environment_scope() {
        assert_eq!(SecretPushTester.environment_scope(), EnvironmentScope::Staging);
    }

    #[test]
    fn secret_push_tester_pre_flight_nonempty() {
        assert!(!SecretPushTester.pre_flight_checks().is_empty());
    }

    #[test]
    fn secret_push_tester_cleanup_nonempty() {
        assert!(!SecretPushTester.cleanup_procedures().is_empty());
    }

    // ── Config validation ────────────────────────────────────────────────────

    #[test]
    fn missing_token_errors() {
        let config = HashMap::from([
            ("GITHUB_OWNER".to_string(), "org".to_string()),
            ("GITHUB_REPO".to_string(), "repo".to_string()),
        ]);
        let err = SecretPushTester.test(&config).unwrap_err();
        assert!(err.to_string().contains("GITHUB_TOKEN"));
    }

    #[test]
    fn missing_owner_errors() {
        let config = HashMap::from([
            ("GITHUB_TOKEN".to_string(), "tok".to_string()),
            ("GITHUB_REPO".to_string(), "repo".to_string()),
        ]);
        let err = SecretPushTester.test(&config).unwrap_err();
        assert!(err.to_string().contains("GITHUB_OWNER"));
    }

    #[test]
    fn missing_repo_errors() {
        let config = HashMap::from([
            ("GITHUB_TOKEN".to_string(), "tok".to_string()),
            ("GITHUB_OWNER".to_string(), "org".to_string()),
        ]);
        let err = SecretPushTester.test(&config).unwrap_err();
        assert!(err.to_string().contains("GITHUB_REPO"));
    }

    // ── HTTP integration ─────────────────────────────────────────────────────

    const BLOCKED_BODY: &str =
        r#"{"message":"Secret scanning push protection prevented this push"}"#;

    const CREATED_BODY: &str =
        r#"{"content":{"sha":"abc123def456","name":"secret-push-test.txt"},"commit":{}}"#;

    const DELETE_OK_BODY: &str = r#"{"commit":{"sha":"xyz789"}}"#;

    #[test]
    fn push_409_is_effective() {
        let srv = mock_server(vec![(409, BLOCKED_BODY)]);
        let ev = &SecretPushTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert!(ev.findings.iter().any(|f| f.title == "Secret Push Blocked"));
        assert_eq!(ev.class_uid, 1003);
        assert_eq!(ev.control_id, "scm.secret_push_protection");
    }

    #[test]
    fn push_422_is_effective() {
        let srv = mock_server(vec![(422, BLOCKED_BODY)]);
        let ev = &SecretPushTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert!(ev.findings.iter().any(|f| f.title == "Secret Push Blocked"));
    }

    #[test]
    fn push_201_is_ineffective_and_triggers_cleanup() {
        // Two responses: 201 for create, 200 for delete.
        let srv = mock_server(vec![(201, CREATED_BODY), (200, DELETE_OK_BODY)]);
        let ev = &SecretPushTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev.findings.iter().any(|f| f.title == "Secret Push Not Blocked"));
        assert_eq!(ev.findings.iter().find(|f| f.title == "Secret Push Not Blocked").unwrap().severity_id, 4);
    }

    #[test]
    fn push_201_raw_data_file_created_true() {
        let srv = mock_server(vec![(201, CREATED_BODY), (200, DELETE_OK_BODY)]);
        let ev = &SecretPushTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.raw_data["file_created"].as_bool(), Some(true));
        assert_eq!(ev.raw_data["push_blocked"].as_bool(), Some(false));
    }

    #[test]
    fn push_500_is_unknown() {
        let srv = mock_server(vec![(500, r#"{"message":"Internal Server Error"}"#)]);
        let ev = &SecretPushTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Unknown);
        assert!(ev.findings.iter().any(|f| f.title == "Unexpected API Response"));
    }

    #[test]
    fn push_has_transcript() {
        let srv = mock_server(vec![(409, BLOCKED_BODY)]);
        let ev = &SecretPushTester.test(&base_config(&srv)).unwrap()[0];
        let t = ev.test_transcript.as_ref().unwrap();
        assert!(!t.actions_attempted.is_empty());
        assert!(!t.observations.is_empty());
    }

    #[test]
    fn push_raw_data_has_expected_keys() {
        let srv = mock_server(vec![(409, BLOCKED_BODY)]);
        let ev = &SecretPushTester.test(&base_config(&srv)).unwrap()[0];
        assert!(ev.raw_data.get("test_scenario").is_some());
        assert!(ev.raw_data.get("target_repo").is_some());
        assert!(ev.raw_data.get("http_status").is_some());
        assert!(ev.raw_data.get("push_blocked").is_some());
    }

    #[test]
    fn push_safety_classification_observable() {
        let srv = mock_server(vec![(409, BLOCKED_BODY)]);
        let ev = &SecretPushTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(
            ev.metadata.safety_classification.as_deref(),
            Some("observable")
        );
    }

    #[test]
    fn push_has_two_observables() {
        let srv = mock_server(vec![(409, BLOCKED_BODY)]);
        let ev = &SecretPushTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.observables.len(), 2);
        assert!(ev.observables.iter().any(|o| o.obs_type == "resource"));
        assert!(ev.observables.iter().any(|o| o.obs_type == "domain"));
    }

    #[test]
    fn push_409_raw_data_push_blocked_true() {
        let srv = mock_server(vec![(409, BLOCKED_BODY)]);
        let ev = &SecretPushTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.raw_data["push_blocked"].as_bool(), Some(true));
        assert_eq!(ev.raw_data["file_created"].as_bool(), Some(false));
    }

    #[test]
    fn push_unique_ids() {
        let srv1 = mock_server(vec![(409, BLOCKED_BODY)]);
        let srv2 = mock_server(vec![(409, BLOCKED_BODY)]);
        let id1 = SecretPushTester.test(&base_config(&srv1)).unwrap()[0].id;
        let id2 = SecretPushTester.test(&base_config(&srv2)).unwrap()[0].id;
        assert_ne!(id1, id2);
    }

    #[test]
    fn push_confidence_active_verification() {
        let srv = mock_server(vec![(409, BLOCKED_BODY)]);
        let ev = &SecretPushTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.confidence_level, ConfidenceLevel::ActiveVerification);
    }
}
