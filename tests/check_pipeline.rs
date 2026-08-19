// Integration test: load + execute GH-1.01 check end-to-end (mocked HTTP).
//
// Verifies the full .check.yaml pipeline: loader → interpreter → evidence output.
// Uses a mock HTTP server to simulate GitHub API responses for both
// the pass case (MFA enforced, no non-compliant members) and the fail case
// (MFA not enforced, non-compliant members found).

use std::collections::HashMap;
use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use ocean::check::{load_check_file, register_check};
use ocean::evidence::StatusId;
use ocean::module::{Executor, Registry};

/// Minimal mock HTTP server for integration tests.
///
/// Serves a queue of `(status_code, body)` responses in order on an ephemeral port.
struct MockHTTPServer {
    base_url: String,
}

impl MockHTTPServer {
    fn new(responses: Vec<(u16, String)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock HTTP server");
        let addr = listener.local_addr().expect("local addr");
        let queue = Arc::new(Mutex::new(responses));

        std::thread::spawn(move || loop {
            let resp = {
                let mut q = queue.lock().unwrap();
                if q.is_empty() {
                    break;
                }
                q.remove(0)
            };
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 8192];
                let _ = stream.read(&mut buf);
                let (status, body) = resp;
                let raw = format!(
                        "HTTP/1.1 {status} OK\r\nContent-Length: {len}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}",
                        len = body.len()
                    );
                let _ = stream.write_all(raw.as_bytes());
            }
        });

        Self {
            base_url: format!("http://127.0.0.1:{}", addr.port()),
        }
    }

    fn url(&self) -> &str {
        &self.base_url
    }
}

/// Path to the real bundled GH-1.01 check file.
fn gh101_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("checks/github/GH-1.01-org-mfa.check.yaml")
}

/// Create a modified GH-1.01 check definition that points at a mock server.
///
/// Rewrites the step URLs from `https://api.github.com/orgs/{{org}}` to
/// `{base_url}/orgs/{{org}}` so we can intercept with MockHTTPServer.
fn load_check_with_mock_urls(mock_base: &str) -> ocean::check::CheckDefinition {
    let content = std::fs::read_to_string(gh101_path()).expect("read GH-1.01 check file");
    let rewritten = content.replace("https://api.github.com", mock_base);
    serde_yaml::from_str(&rewritten).expect("parse rewritten GH-1.01")
}

/// Build config with required env vars for GH-1.01 (org name, token).
fn test_config() -> HashMap<String, String> {
    let mut cfg = HashMap::new();
    cfg.insert("GITHUB_TOKEN".to_string(), "ghp_test_token".to_string());
    cfg.insert("GITHUB_ORG".to_string(), "test-org".to_string());
    cfg
}

// ---------------------------------------------------------------------------
// Pass case: MFA enforced, zero non-compliant members
// ---------------------------------------------------------------------------

#[test]
fn gh101_pass_mfa_enforced_no_noncompliant() {
    let org_response = serde_json::json!({
        "login": "test-org",
        "two_factor_requirement_enabled": true,
        "default_repository_permission": "read"
    });
    let members_response = serde_json::json!([]);

    let server = MockHTTPServer::new(vec![
        (200, org_response.to_string()),
        (200, members_response.to_string()),
    ]);

    let def = load_check_with_mock_urls(server.url());
    let registry = Arc::new(Registry::new());
    register_check(&registry, def);

    let executor = Executor::new(Arc::clone(&registry));
    let evidence = executor
        .execute_observer("GH-1.01", &test_config())
        .expect("execute GH-1.01 observer");

    // GH-1.01 has 2 assertions → 2 evidence items.
    assert_eq!(
        evidence.len(),
        2,
        "expected 2 evidence items (one per assertion)"
    );

    // Both should pass (Effective).
    for ev in &evidence {
        assert_eq!(ev.control_id, "GH-1.01");
        assert_eq!(
            ev.status_id,
            StatusId::Effective,
            "expected Effective for pass case, got {:?} — status: {}",
            ev.status_id,
            ev.status,
        );
        assert!(ev.findings.is_empty(), "pass case should have no findings");
    }

    // Verify metadata.
    let first = &evidence[0];
    assert_eq!(
        first.metadata.module.name,
        "Enforce 2FA for Organization Members"
    );
    assert_eq!(first.metadata.source.system, "github");
    assert_eq!(first.metadata.module.module_type, "observer");
}

// ---------------------------------------------------------------------------
// Fail case: MFA not enforced, non-compliant members exist
// ---------------------------------------------------------------------------

#[test]
fn gh101_fail_mfa_not_enforced_with_noncompliant() {
    let org_response = serde_json::json!({
        "login": "test-org",
        "two_factor_requirement_enabled": false,
        "default_repository_permission": "write"
    });
    let members_response = serde_json::json!([
        {"login": "alice", "id": 1},
        {"login": "bob", "id": 2}
    ]);

    let server = MockHTTPServer::new(vec![
        (200, org_response.to_string()),
        (200, members_response.to_string()),
    ]);

    let def = load_check_with_mock_urls(server.url());
    let registry = Arc::new(Registry::new());
    register_check(&registry, def);

    let executor = Executor::new(Arc::clone(&registry));
    let evidence = executor
        .execute_observer("GH-1.01", &test_config())
        .expect("execute GH-1.01 observer");

    assert_eq!(evidence.len(), 2, "expected 2 evidence items");

    // Both assertions should fail (Ineffective).
    for ev in &evidence {
        assert_eq!(ev.control_id, "GH-1.01");
        assert_eq!(
            ev.status_id,
            StatusId::Ineffective,
            "expected Ineffective for fail case, got {:?} — status: {}",
            ev.status_id,
            ev.status,
        );
        assert!(!ev.findings.is_empty(), "fail case should produce findings");
    }

    // First assertion: MFA enforcement (critical severity → severity_id 5).
    let mfa_ev = &evidence[0];
    assert_eq!(mfa_ev.findings[0].title, "Organization MFA Enforcement");
    assert_eq!(mfa_ev.findings[0].severity_id, 5);

    // Second assertion: member compliance (high severity → severity_id 4).
    let member_ev = &evidence[1];
    assert_eq!(member_ev.findings[0].title, "Member 2FA Compliance");
    assert_eq!(member_ev.findings[0].severity_id, 4);

    // Verify raw_data contains extracted variables.
    let raw = &member_ev.raw_data;
    assert_eq!(raw["non_compliant_count"], 2);
}

// ---------------------------------------------------------------------------
// Mixed case: MFA enforced but some members still non-compliant
// ---------------------------------------------------------------------------

#[test]
fn gh101_mixed_mfa_enforced_but_noncompliant_exist() {
    let org_response = serde_json::json!({
        "login": "test-org",
        "two_factor_requirement_enabled": true,
        "default_repository_permission": "read"
    });
    let members_response = serde_json::json!([
        {"login": "charlie", "id": 3}
    ]);

    let server = MockHTTPServer::new(vec![
        (200, org_response.to_string()),
        (200, members_response.to_string()),
    ]);

    let def = load_check_with_mock_urls(server.url());
    let registry = Arc::new(Registry::new());
    register_check(&registry, def);

    let executor = Executor::new(Arc::clone(&registry));
    let evidence = executor
        .execute_observer("GH-1.01", &test_config())
        .expect("execute GH-1.01 observer");

    assert_eq!(evidence.len(), 2);

    // First assertion (MFA enforcement) should pass.
    assert_eq!(evidence[0].status_id, StatusId::Effective);
    assert!(evidence[0].findings.is_empty());

    // Second assertion (member compliance) should fail.
    assert_eq!(evidence[1].status_id, StatusId::Ineffective);
    assert_eq!(evidence[1].findings[0].title, "Member 2FA Compliance");
}

// ---------------------------------------------------------------------------
// Loader integration: verify the real bundled GH-1.01 file loads correctly
// ---------------------------------------------------------------------------

#[test]
fn gh101_bundled_check_loads_and_has_correct_metadata() {
    let def = load_check_file(&gh101_path()).expect("load bundled GH-1.01");

    assert_eq!(def.id, "GH-1.01");
    assert_eq!(def.name, "Enforce 2FA for Organization Members");
    assert_eq!(def.source, "github");
    assert_eq!(def.profile, "L1");
    assert!(def.tags.contains(&"mfa".to_string()));
    assert_eq!(def.steps.len(), 2, "GH-1.01 should have 2 steps");
    assert_eq!(def.assertions.len(), 2, "GH-1.01 should have 2 assertions");
}

// ---------------------------------------------------------------------------
// API error handling: non-200 responses should not panic
// ---------------------------------------------------------------------------

#[test]
fn gh101_api_error_produces_evidence_not_panic() {
    let server = MockHTTPServer::new(vec![
        (401, r#"{"message":"Bad credentials"}"#.to_string()),
        (401, r#"{"message":"Bad credentials"}"#.to_string()),
    ]);

    let def = load_check_with_mock_urls(server.url());
    let registry = Arc::new(Registry::new());
    register_check(&registry, def);

    let executor = Executor::new(Arc::clone(&registry));
    let evidence = executor
        .execute_observer("GH-1.01", &test_config())
        .expect("should produce evidence even on API errors");

    // Should still produce evidence (assertions evaluate against what was extracted).
    assert!(!evidence.is_empty());
}
