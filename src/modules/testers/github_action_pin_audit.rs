use std::collections::HashMap;

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

use crate::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId,
    TranscriptRecorder,
};
use crate::module::{tester::Tester, CredentialReq, EnvironmentScope, Module, SafetyClassification};
use crate::modules::github_common::{github_get, DEFAULT_GITHUB_API};

// ─── ActionPinAuditTester ─────────────────────────────────────────────────────

/// Audits GitHub Actions workflow files to verify that all third-party actions
/// are pinned to a full commit SHA rather than a mutable tag or branch reference.
/// Pinning to a SHA prevents supply-chain attacks via tag mutation.
///
/// Required config: `GITHUB_TOKEN`, `GITHUB_OWNER`, `GITHUB_REPO`.
/// Optional: `GITHUB_API_URL` (test override — defaults to `https://api.github.com`).
pub struct ActionPinAuditTester;

impl Module for ActionPinAuditTester {
    fn id(&self) -> &str {
        "github.action_pin_audit"
    }
    fn name(&self) -> &str {
        "GitHub Action Pin Audit Tester"
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
                description: "GitHub PAT with repo read access for reading workflow files"
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

/// Returns true if the `@ref` portion of a `uses:` line is a full 40-char hex SHA.
/// Local actions (`./`) and Docker actions (`docker://`) are excluded from the check.
fn is_sha_pinned(uses_value: &str) -> bool {
    // Skip local actions and docker image references.
    if uses_value.starts_with("./") || uses_value.starts_with("docker://") {
        return true;
    }
    // Extract the ref after `@`.
    if let Some(at_pos) = uses_value.rfind('@') {
        let ref_part = &uses_value[at_pos + 1..];
        // A full SHA is exactly 40 lowercase hex characters.
        ref_part.len() == 40 && ref_part.chars().all(|c| c.is_ascii_hexdigit())
    } else {
        // No `@` at all — unpinned.
        false
    }
}

/// Extract all `uses:` values from a workflow YAML string.
/// Handles both `uses: ...` and `- uses: ...` (list item) forms.
fn extract_uses_lines(content: &str) -> Vec<String> {
    content
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            // Handle `uses: value` and `- uses: value`
            let rest = if let Some(r) = trimmed.strip_prefix("uses:") {
                r
            } else if let Some(r) = trimmed.strip_prefix("- uses:") {
                r
            } else {
                return None;
            };
            Some(rest.trim().to_string())
        })
        .collect()
}

impl Tester for ActionPinAuditTester {
    fn safety_class(&self) -> SafetyClassification {
        SafetyClassification::Safe
    }

    fn environment_scope(&self) -> EnvironmentScope {
        EnvironmentScope::Production
    }

    fn pre_flight_checks(&self) -> Vec<String> {
        vec!["Verify GITHUB_TOKEN has repo read access".to_string()]
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
        let base_url = config
            .get("GITHUB_API_URL")
            .map(|s| s.as_str())
            .unwrap_or(DEFAULT_GITHUB_API);

        let now = Utc::now();
        let mut recorder = TranscriptRecorder::new();
        let safety_class = "safe".to_string();

        let workflows_path = format!("/repos/{}/{}/contents/.github/workflows", owner, repo);
        let endpoint = format!(
            "{}{}",
            base_url.trim_end_matches('/'),
            &workflows_path
        );

        recorder.record_action(
            "list workflow files in .github/workflows via GitHub API",
            Some(json!({
                "owner": owner,
                "repo": repo,
                "endpoint": workflows_path,
            })),
        );

        let (list_body, list_status) = github_get(token, base_url, &workflows_path)?;

        // No workflows directory — nothing unpinned, passes trivially.
        if list_status == 404 {
            recorder.record_observation(
                "workflows directory not found (404) — no actions to audit",
                true,
            );
            recorder.record_cleanup("no cleanup required (read-only operation)", true);
            let transcript = recorder.finalize();

            return Ok(vec![Evidence {
                id: Uuid::new_v4(),
                control_id: "GH-3.10".to_string(),
                class_uid: 1003,
                category_uid: 2,
                activity_id: 2,
                time: now,
                confidence_level: ConfidenceLevel::ActiveVerification,
                metadata: Metadata {
                    module: ModuleInfo {
                        name: "github.action_pin_audit".to_string(),
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
                        value: format!("{}/{}:.github/workflows", owner, repo),
                        name: String::new(),
                    },
                    Observable {
                        obs_type: "domain".to_string(),
                        value: "github.com".to_string(),
                        name: String::new(),
                    },
                ],
                status_id: StatusId::Effective,
                status: format!(
                    "No workflow files found in {}/{} — no action pin audit required",
                    owner, repo
                ),
                raw_data: json!({
                    "workflows_checked": 0,
                    "unpinned_actions": [],
                }),
                findings: vec![],
                test_transcript: Some(transcript),
                enrichments: vec![],
            }]);
        }

        if list_status != 200 {
            return Err(anyhow!(
                "GitHub API returned status {} for {}",
                list_status,
                workflows_path
            ));
        }

        let workflow_files: Vec<String> = list_body
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|f| {
                let name = f.get("name")?.as_str()?;
                if name.ends_with(".yml") || name.ends_with(".yaml") {
                    Some(name.to_string())
                } else {
                    None
                }
            })
            .collect();

        recorder.record_observation(
            format!("found {} workflow file(s) to audit", workflow_files.len()),
            true,
        );

        let mut unpinned_actions: Vec<String> = Vec::new();
        let mut workflows_checked = 0usize;

        for filename in &workflow_files {
            let file_path = format!(
                "/repos/{}/{}/contents/.github/workflows/{}",
                owner, repo, filename
            );

            recorder.record_action(
                format!("fetch and audit action pins in: {}", filename),
                Some(json!({ "file": filename, "path": file_path })),
            );

            let (file_body, file_status) = github_get(token, base_url, &file_path)?;

            if file_status != 200 {
                continue;
            }

            workflows_checked += 1;

            let raw_content = file_body
                .get("content")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let cleaned = raw_content.replace('\n', "").replace('\r', "");
            let decoded = BASE64.decode(cleaned.as_bytes()).unwrap_or_default();
            let content = String::from_utf8_lossy(&decoded);

            let uses_lines = extract_uses_lines(&content);
            for uses_val in &uses_lines {
                if !is_sha_pinned(uses_val) {
                    recorder.record_observation(
                        format!("unpinned action '{}' in {}", uses_val, filename),
                        false,
                    );
                    unpinned_actions.push(format!("{}: {}", filename, uses_val));
                }
            }

            if uses_lines.iter().all(|u| is_sha_pinned(u)) && !uses_lines.is_empty() {
                recorder.record_observation(
                    format!("all actions in {} are SHA-pinned", filename),
                    true,
                );
            }
        }

        let (status_id, status_text, findings) = if unpinned_actions.is_empty() {
            (
                StatusId::Effective,
                format!(
                    "All third-party actions in {}/{} are pinned to commit SHA ({} workflow(s) checked)",
                    owner, repo, workflows_checked
                ),
                vec![],
            )
        } else {
            (
                StatusId::Ineffective,
                format!(
                    "Unpinned third-party actions found in {}/{}: {} action reference(s) use tags or branches",
                    owner, repo, unpinned_actions.len()
                ),
                vec![Finding {
                    title: "Unpinned Third-Party Actions Detected".to_string(),
                    description: format!(
                        "The following action references in {}/{} are not pinned to a full commit SHA, \
                         making them vulnerable to tag mutation supply-chain attacks: {}. \
                         Pin each action to a specific commit SHA (e.g. `owner/action@abc123...`).",
                        owner,
                        repo,
                        unpinned_actions.join("; ")
                    ),
                    severity_id: 4,
                }],
            )
        };

        recorder.record_cleanup("no cleanup required (read-only operation)", true);
        let transcript = recorder.finalize();

        let raw_data = json!({
            "workflows_checked": workflows_checked,
            "unpinned_actions": unpinned_actions,
        });

        Ok(vec![Evidence {
            id: Uuid::new_v4(),
            control_id: "GH-3.10".to_string(),
            class_uid: 1003,
            category_uid: 2,
            activity_id: 2,
            time: now,
            confidence_level: ConfidenceLevel::ActiveVerification,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "github.action_pin_audit".to_string(),
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
                    value: format!("{}/{}:.github/workflows", owner, repo),
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
    use crate::modules::github_common::test_config;

    fn mock_server_multi(responses: Vec<(u16, &'static str)>) -> String {
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
                    let mut buf = [0u8; 8192];
                    let _ = stream.read(&mut buf);
                    let resp = format!(
                        "HTTP/1.1 {status} OK\r\nContent-Length: {len}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}",
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

    fn workflow_file_body(yaml_content: &str) -> String {
        let encoded = BASE64.encode(yaml_content.as_bytes());
        format!(
            r#"{{"name":"ci.yml","path":".github/workflows/ci.yml","content":"{}","encoding":"base64"}}"#,
            encoded
        )
    }

    // ── Unit tests for helpers ────────────────────────────────────────────────

    #[test]
    fn sha_pinned_returns_true_for_40_char_hex() {
        assert!(is_sha_pinned(
            "actions/checkout@abc123def456abc123def456abc123def456abc1"
        ));
    }

    #[test]
    fn tag_ref_returns_false() {
        assert!(!is_sha_pinned("actions/checkout@v4"));
        assert!(!is_sha_pinned("actions/setup-node@v3.1.0"));
    }

    #[test]
    fn local_action_returns_true() {
        assert!(is_sha_pinned("./my-local-action"));
    }

    #[test]
    fn no_at_sign_returns_false() {
        assert!(!is_sha_pinned("actions/checkout"));
    }

    // ── Module metadata ───────────────────────────────────────────────────────

    #[test]
    fn action_pin_audit_tester_id() {
        assert_eq!(ActionPinAuditTester.id(), "github.action_pin_audit");
    }

    #[test]
    fn action_pin_audit_tester_safety_class() {
        assert_eq!(
            ActionPinAuditTester.safety_class(),
            SafetyClassification::Safe
        );
    }

    #[test]
    fn action_pin_audit_tester_environment_scope() {
        assert_eq!(
            ActionPinAuditTester.environment_scope(),
            EnvironmentScope::Production
        );
    }

    // ── Integration tests ─────────────────────────────────────────────────────

    #[test]
    fn all_actions_sha_pinned_is_effective() {
        let pinned_yaml = "on: [push]\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@abc123def456abc123def456abc123def456abc1\n";
        let file_resp = workflow_file_body(pinned_yaml);
        let file_resp_static: &'static str = Box::leak(file_resp.into_boxed_str());
        let list_resp: &'static str =
            r#"[{"name":"ci.yml","type":"file","path":".github/workflows/ci.yml"}]"#;

        let srv = mock_server_multi(vec![(200, list_resp), (200, file_resp_static)]);
        let ev = &ActionPinAuditTester.test(&test_config(&srv)).unwrap()[0];

        assert_eq!(ev.status_id, StatusId::Effective);
        assert_eq!(ev.raw_data["workflows_checked"].as_u64(), Some(1));
        assert_eq!(
            ev.raw_data["unpinned_actions"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
        assert_eq!(ev.control_id, "GH-3.10");
        assert_eq!(ev.confidence_level, ConfidenceLevel::ActiveVerification);
    }

    #[test]
    fn action_with_tag_ref_is_ineffective_with_finding() {
        let unpinned_yaml =
            "on: [push]\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n";
        let file_resp = workflow_file_body(unpinned_yaml);
        let file_resp_static: &'static str = Box::leak(file_resp.into_boxed_str());
        let list_resp: &'static str =
            r#"[{"name":"ci.yml","type":"file","path":".github/workflows/ci.yml"}]"#;

        let srv = mock_server_multi(vec![(200, list_resp), (200, file_resp_static)]);
        let ev = &ActionPinAuditTester.test(&test_config(&srv)).unwrap()[0];

        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "Unpinned Third-Party Actions Detected"));
        assert!(!ev.raw_data["unpinned_actions"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn no_workflow_files_is_effective() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 8192];
                let _ = stream.read(&mut buf);
                let body = r#"{"message":"Not Found"}"#;
                let resp = format!(
                    "HTTP/1.1 404 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
                    body.len(), body
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.shutdown(std::net::Shutdown::Write);
                let mut drain = [0u8; 256];
                while matches!(stream.read(&mut drain), Ok(n) if n > 0) {}
            }
        });
        let srv = format!("http://127.0.0.1:{}", addr.port());

        let ev = &ActionPinAuditTester.test(&test_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert_eq!(ev.raw_data["workflows_checked"].as_u64(), Some(0));
        assert!(ev.findings.is_empty());
    }
}
