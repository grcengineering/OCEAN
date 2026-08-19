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
use crate::module::{
    tester::Tester, CredentialReq, EnvironmentScope, Module, SafetyClassification,
};
use crate::modules::github_common::{github_get, DEFAULT_GITHUB_API};

// ─── WorkflowInjectionTester ──────────────────────────────────────────────────

/// Performs static analysis of GitHub Actions workflow files to detect potential
/// workflow injection vulnerabilities. Checks for usage of untrusted user-controlled
/// inputs (e.g. `github.event.issue.title`) directly in `run:` steps.
///
/// Required config: `GITHUB_TOKEN`, `GITHUB_OWNER`, `GITHUB_REPO`.
/// Optional: `GITHUB_API_URL` (test override — defaults to `https://api.github.com`).
pub struct WorkflowInjectionTester;

impl Module for WorkflowInjectionTester {
    fn id(&self) -> &str {
        "github.workflow_injection"
    }
    fn name(&self) -> &str {
        "GitHub Workflow Injection Tester"
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

/// Returns true if the workflow YAML content contains a potential injection pattern:
/// a `${{ github.event.` expression appearing in proximity to a `run:` step.
/// Simplified heuristic: scan for both patterns anywhere in the file.
fn has_injection_pattern(content: &str) -> bool {
    // Look for ${{ github.event. anywhere — if a run: step also exists, that's a risk.
    // Simplified: flag any file that has both `run:` and `${{ github.event.`
    let has_run = content.contains("run:");
    let has_event_expr = content.contains("${{ github.event.")
        || content.contains("${{ github.head_ref")
        || content.contains("${{github.event.")
        || content.contains("${{github.head_ref");
    has_run && has_event_expr
}

impl Tester for WorkflowInjectionTester {
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
        let endpoint = format!("{}{}", base_url.trim_end_matches('/'), workflows_path);

        recorder.record_action(
            "list workflow files in .github/workflows via GitHub API",
            Some(json!({
                "owner": owner,
                "repo": repo,
                "endpoint": workflows_path,
            })),
        );

        let (list_body, list_status) = github_get(token, base_url, &workflows_path)?;

        // 404 on the workflows directory means no workflows exist — nothing to check.
        if list_status == 404 {
            recorder.record_observation(
                "workflows directory not found (404) — no workflows to check",
                true,
            );
            recorder.record_cleanup("no cleanup required (read-only operation)", true);
            let transcript = recorder.finalize();

            return Ok(vec![Evidence {
                id: Uuid::new_v4(),
                control_id: "GH-3.8".to_string(),
                class_uid: 1003,
                category_uid: 2,
                activity_id: 2,
                time: now,
                confidence_level: ConfidenceLevel::ActiveVerification,
                metadata: Metadata {
                    module: ModuleInfo {
                        name: "github.workflow_injection".to_string(),
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
                    "No workflow files found in {}/{} — no injection risk to assess",
                    owner, repo
                ),
                raw_data: json!({
                    "workflows_checked": 0,
                    "injection_risks": [],
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

        // Collect workflow filenames.
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
            format!("found {} workflow file(s) to scan", workflow_files.len()),
            true,
        );

        let mut injection_risks: Vec<String> = Vec::new();
        let mut workflows_checked = 0usize;

        for filename in &workflow_files {
            let file_path = format!(
                "/repos/{}/{}/contents/.github/workflows/{}",
                owner, repo, filename
            );

            recorder.record_action(
                format!("fetch and analyse workflow file: {}", filename),
                Some(json!({ "file": filename, "path": file_path })),
            );

            let (file_body, file_status) = github_get(token, base_url, &file_path)?;

            if file_status != 200 {
                continue;
            }

            workflows_checked += 1;

            // Decode base64 content (GitHub API returns file content as base64).
            let raw_content = file_body
                .get("content")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            // GitHub wraps base64 in newlines — strip them before decoding.
            let cleaned = raw_content.replace(['\n', '\r'], "");
            let decoded = BASE64.decode(cleaned.as_bytes()).unwrap_or_default();
            let content = String::from_utf8_lossy(&decoded);

            if has_injection_pattern(&content) {
                recorder.record_observation(
                    format!("injection pattern detected in {}", filename),
                    false,
                );
                injection_risks.push(filename.clone());
            } else {
                recorder.record_observation(format!("no injection pattern in {}", filename), true);
            }
        }

        let (status_id, status_text, findings) = if injection_risks.is_empty() {
            (
                StatusId::Effective,
                format!(
                    "No workflow injection patterns found in {}/{} ({} workflow(s) checked)",
                    owner, repo, workflows_checked
                ),
                vec![],
            )
        } else {
            (
                StatusId::Ineffective,
                format!(
                    "Workflow injection risk detected in {}/{}: {} file(s) use untrusted input in run steps",
                    owner, repo, injection_risks.len()
                ),
                vec![Finding {
                    title: "Workflow Injection Risk Detected".to_string(),
                    description: format!(
                        "The following workflow file(s) in {}/{} use `${{{{ github.event.` or \
                         similar untrusted expressions directly in `run:` steps, which may allow \
                         script injection: {}. Refactor to use intermediate environment variables.",
                        owner,
                        repo,
                        injection_risks.join(", ")
                    ),
                    severity_id: 4,
                }],
            )
        };

        recorder.record_cleanup("no cleanup required (read-only operation)", true);
        let transcript = recorder.finalize();

        let raw_data = json!({
            "workflows_checked": workflows_checked,
            "injection_risks": injection_risks,
        });

        Ok(vec![Evidence {
            id: Uuid::new_v4(),
            control_id: "GH-3.8".to_string(),
            class_uid: 1003,
            category_uid: 2,
            activity_id: 2,
            time: now,
            confidence_level: ConfidenceLevel::ActiveVerification,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "github.workflow_injection".to_string(),
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

    /// Build a base64-encoded workflow YAML content response body.
    fn workflow_file_body(yaml_content: &str) -> String {
        let encoded = BASE64.encode(yaml_content.as_bytes());
        format!(
            r#"{{"name":"ci.yml","path":".github/workflows/ci.yml","content":"{}","encoding":"base64"}}"#,
            encoded
        )
    }

    #[test]
    fn workflow_injection_tester_id() {
        assert_eq!(WorkflowInjectionTester.id(), "github.workflow_injection");
    }

    #[test]
    fn workflow_injection_tester_safety_class() {
        assert_eq!(
            WorkflowInjectionTester.safety_class(),
            SafetyClassification::Safe
        );
    }

    #[test]
    fn workflow_injection_tester_environment_scope() {
        assert_eq!(
            WorkflowInjectionTester.environment_scope(),
            EnvironmentScope::Production
        );
    }

    #[test]
    fn safe_workflow_content_is_effective() {
        // Safe workflow with no untrusted input in run steps.
        let safe_yaml = "on: [push]\njobs:\n  build:\n    steps:\n      - run: echo hello\n";
        let file_resp = workflow_file_body(safe_yaml);

        // Leak the String into a &'static str for the mock (acceptable in tests).
        let file_resp_static: &'static str = Box::leak(file_resp.into_boxed_str());
        let list_resp: &'static str =
            r#"[{"name":"ci.yml","type":"file","path":".github/workflows/ci.yml"}]"#;

        let srv = mock_server_multi(vec![(200, list_resp), (200, file_resp_static)]);
        let ev = &WorkflowInjectionTester.test(&test_config(&srv)).unwrap()[0];

        assert_eq!(ev.status_id, StatusId::Effective);
        assert_eq!(ev.raw_data["workflows_checked"].as_u64(), Some(1));
        assert_eq!(ev.raw_data["injection_risks"].as_array().unwrap().len(), 0);
        assert_eq!(ev.control_id, "GH-3.8");
        assert_eq!(ev.confidence_level, ConfidenceLevel::ActiveVerification);
    }

    #[test]
    fn workflow_with_injection_pattern_is_ineffective_with_finding() {
        let risky_yaml = "on: [issues]\njobs:\n  triage:\n    steps:\n      - run: echo ${{ github.event.issue.title }}\n";
        let file_resp = workflow_file_body(risky_yaml);
        let file_resp_static: &'static str = Box::leak(file_resp.into_boxed_str());
        let list_resp: &'static str =
            r#"[{"name":"ci.yml","type":"file","path":".github/workflows/ci.yml"}]"#;

        let srv = mock_server_multi(vec![(200, list_resp), (200, file_resp_static)]);
        let ev = &WorkflowInjectionTester.test(&test_config(&srv)).unwrap()[0];

        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "Workflow Injection Risk Detected"));
        assert!(ev.raw_data["injection_risks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str() == Some("ci.yml")));
    }

    #[test]
    fn no_workflows_directory_is_effective() {
        // Single mock server — 404 on the directory listing.
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

        let ev = &WorkflowInjectionTester.test(&test_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert_eq!(ev.raw_data["workflows_checked"].as_u64(), Some(0));
    }
}
