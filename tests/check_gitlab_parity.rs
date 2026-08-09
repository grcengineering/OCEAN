// Integration test: load + execute the GitLab checks end-to-end (mocked HTTP).
//
// Mirrors tests/check_pipeline.rs and tests/check_slack_parity.rs's
// MockHTTPServer pattern. Covers pass and fail cases for all four bundled
// GitLab checks (GITLAB-1.03, GITLAB-2.01, GITLAB-4.01, GITLAB-6.01) plus a
// load-all sanity test for checks/gitlab/.
//
// Fixtures reflect the field shapes the HTH how-to-harden GitLab pack code
// parses (packs/gitlab/api/hth-gitlab-1.03-configure-personal-access-token-policies.sh,
// packs/gitlab/api/hth-gitlab-2.01-protect-cicd-variables.sh,
// packs/gitlab/api/hth-gitlab-4.01-enable-push-rules.sh,
// packs/gitlab/api/hth-gitlab-6.01-enable-audit-events.sh), cross-checked
// against docs.gitlab.com/api/ (personal_access_tokens, project_level_variables,
// project_push_rules, audit_events):
//   - Personal access tokens: response fields include id, name, revoked,
//     created_at, scopes, user_id, expires_at, active.
//   - Project variables: response fields include key, variable_type, value,
//     protected, masked, raw, environment_scope.
//   - Push rule: GET /projects/:id/push_rule returns 200 with a literal
//     `null` body when never configured (not a 404); disabled boolean
//     fields (commit_committer_check, reject_unsigned_commits) return null
//     rather than false.
//   - Group audit events: response fields include id, author_id, entity_id,
//     entity_type, details, created_at (Premium/Ultimate only). Streaming
//     destinations carry destination_url and verification_token, matching
//     the verified HTH pack script's parsing.
//
// Unlike the GitHub/Slack fixtures (which hardcode api.<vendor>.com and
// string-replace it), every GitLab check templates its base URL via the
// `gitlab_url` input (env: GITLAB_URL), so tests point straight at the mock
// server through config without any file rewriting.

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

fn gitlab_check_path(filename: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("checks/gitlab")
        .join(filename)
}

fn load_check(filename: &str) -> ocean::check::CheckDefinition {
    load_check_file(&gitlab_check_path(filename))
        .unwrap_or_else(|e| panic!("load {filename}: {e}"))
}

fn run_observer(def: ocean::check::CheckDefinition, config: &HashMap<String, String>) -> Vec<ocean::evidence::Evidence> {
    let registry = Arc::new(Registry::new());
    let id = def.id.clone();
    register_check(&registry, def);
    let executor = Executor::new(Arc::clone(&registry));
    executor
        .execute_observer(&id, config)
        .unwrap_or_else(|e| panic!("execute {id}: {e}"))
}

fn base_config(mock_url: &str) -> HashMap<String, String> {
    let mut cfg = HashMap::new();
    cfg.insert("GITLAB_URL".to_string(), mock_url.to_string());
    cfg.insert("GITLAB_TOKEN".to_string(), "glpat-test-token".to_string());
    cfg
}

// ---------------------------------------------------------------------------
// GITLAB-1.03 — personal access token expiration + scope hygiene
// ---------------------------------------------------------------------------

#[test]
fn gitlab103_pass_all_tokens_compliant() {
    let body = serde_json::json!([
        {
            "id": 1, "name": "ci-deploy-token", "revoked": false,
            "created_at": "2026-01-01T00:00:00Z", "scopes": ["read_repository"],
            "user_id": 10, "active": true, "expires_at": "2026-12-01"
        },
        {
            "id": 2, "name": "read-only-token", "revoked": false,
            "created_at": "2026-02-01T00:00:00Z", "scopes": ["read_api"],
            "user_id": 11, "active": true, "expires_at": "2026-11-01"
        }
    ]);
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check("GITLAB-1.03-pat-policy.check.yaml");

    let evidence = run_observer(def, &base_config(server.url()));
    assert_eq!(evidence.len(), 2, "expected 2 evidence items (one per assertion)");
    for ev in &evidence {
        assert_eq!(ev.control_id, "GITLAB-1.03");
        assert_eq!(ev.status_id, StatusId::Effective, "expected Effective, got: {}", ev.status);
        assert!(ev.findings.is_empty());
    }
}

#[test]
fn gitlab103_fail_missing_expiration_and_broad_scope() {
    let body = serde_json::json!([
        {
            "id": 3, "name": "legacy-token", "revoked": false,
            "created_at": "2024-01-01T00:00:00Z", "scopes": ["read_repository"],
            "user_id": 12, "active": true, "expires_at": null
        },
        {
            "id": 4, "name": "broad-token", "revoked": false,
            "created_at": "2026-01-01T00:00:00Z", "scopes": ["api"],
            "user_id": 13, "active": true, "expires_at": "2026-12-01"
        }
    ]);
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check("GITLAB-1.03-pat-policy.check.yaml");

    let evidence = run_observer(def, &base_config(server.url()));
    assert_eq!(evidence.len(), 2);

    // tokens_have_expiration: token id 3 has expires_at == null.
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
    assert_eq!(evidence[0].findings[0].severity_id, 5); // critical

    // tokens_least_privilege_scope: token id 4 holds "api" scope.
    assert_eq!(evidence[1].status_id, StatusId::Ineffective);
    assert_eq!(evidence[1].findings[0].severity_id, 4); // high
}

// ---------------------------------------------------------------------------
// GITLAB-2.01 — CI/CD variable protection + masking
// ---------------------------------------------------------------------------

#[test]
fn gitlab201_pass_all_variables_protected_and_masked() {
    let body = serde_json::json!([
        {"key": "PROD_API_KEY", "variable_type": "env_var", "protected": true, "masked": true, "raw": true, "environment_scope": "production"},
        {"key": "STAGING_API_KEY", "variable_type": "env_var", "protected": true, "masked": true, "raw": true, "environment_scope": "staging"}
    ]);
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check("GITLAB-2.01-protect-cicd-variables.check.yaml");

    let mut cfg = base_config(server.url());
    cfg.insert("GITLAB_PROJECT_ID".to_string(), "42".to_string());

    let evidence = run_observer(def, &cfg);
    assert_eq!(evidence.len(), 2);
    for ev in &evidence {
        assert_eq!(ev.control_id, "GITLAB-2.01");
        assert_eq!(ev.status_id, StatusId::Effective, "expected Effective, got: {}", ev.status);
        assert!(ev.findings.is_empty());
    }
}

#[test]
fn gitlab201_fail_unprotected_and_unmasked_variables() {
    let body = serde_json::json!([
        {"key": "PROD_API_KEY", "variable_type": "env_var", "protected": false, "masked": true, "raw": true, "environment_scope": "production"},
        {"key": "DEBUG_TOKEN", "variable_type": "env_var", "protected": true, "masked": false, "raw": true, "environment_scope": "*"}
    ]);
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check("GITLAB-2.01-protect-cicd-variables.check.yaml");

    let mut cfg = base_config(server.url());
    cfg.insert("GITLAB_PROJECT_ID".to_string(), "42".to_string());

    let evidence = run_observer(def, &cfg);
    assert_eq!(evidence.len(), 2);

    // all_variables_protected: PROD_API_KEY is unprotected.
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
    assert_eq!(evidence[0].findings[0].title, "All CI/CD Variables Are Protected");

    // all_variables_masked: DEBUG_TOKEN is unmasked.
    assert_eq!(evidence[1].status_id, StatusId::Ineffective);
    assert_eq!(evidence[1].findings[0].title, "All CI/CD Variables Are Masked");
}

// ---------------------------------------------------------------------------
// GITLAB-4.01 — push rules (prevent_secrets, deny_delete_tag, reject_unsigned_commits)
// ---------------------------------------------------------------------------

#[test]
fn gitlab401_pass_all_push_rules_enabled() {
    let body = serde_json::json!({
        "id": 7, "project_id": 42,
        "prevent_secrets": true, "deny_delete_tag": true, "reject_unsigned_commits": true,
        "member_check": false, "commit_committer_check": false
    });
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check("GITLAB-4.01-push-rules.check.yaml");

    let mut cfg = base_config(server.url());
    cfg.insert("GITLAB_PROJECT_ID".to_string(), "42".to_string());

    let evidence = run_observer(def, &cfg);
    assert_eq!(evidence.len(), 4, "expected 4 evidence items (one per assertion)");
    for ev in &evidence {
        assert_eq!(ev.control_id, "GITLAB-4.01");
        assert_eq!(ev.status_id, StatusId::Effective, "expected Effective, got: {}", ev.status);
        assert!(ev.findings.is_empty());
    }
}

/// Push rules exist but are only partially configured. Also exercises the
/// documented GitLab quirk where a disabled boolean push-rule field
/// (reject_unsigned_commits) returns `null` instead of `false`.
#[test]
fn gitlab401_fail_partial_push_rules() {
    let body = serde_json::json!({
        "id": 7, "project_id": 42,
        "prevent_secrets": true, "deny_delete_tag": false, "reject_unsigned_commits": null,
        "member_check": false, "commit_committer_check": null
    });
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check("GITLAB-4.01-push-rules.check.yaml");

    let mut cfg = base_config(server.url());
    cfg.insert("GITLAB_PROJECT_ID".to_string(), "42".to_string());

    let evidence = run_observer(def, &cfg);
    assert_eq!(evidence.len(), 4);

    assert_eq!(evidence[0].status_id, StatusId::Effective, "push_rules_configured should pass — id is present");
    assert_eq!(evidence[1].status_id, StatusId::Effective, "prevent_secrets_enabled should pass");
    assert_eq!(evidence[2].status_id, StatusId::Ineffective, "deny_delete_tag_enabled should fail");
    assert_eq!(evidence[3].status_id, StatusId::Ineffective, "reject_unsigned_commits_enabled should fail on null");
}

/// GitLab returns 200 OK with a literal `null` body when push rules were
/// never configured for the project (not a 404). Every field extraction
/// fails silently, so every assertion must fail closed, not panic.
#[test]
fn gitlab401_fail_push_rules_never_configured() {
    let server = MockHTTPServer::new(vec![(200, "null".to_string())]);
    let def = load_check("GITLAB-4.01-push-rules.check.yaml");

    let mut cfg = base_config(server.url());
    cfg.insert("GITLAB_PROJECT_ID".to_string(), "42".to_string());

    let evidence = run_observer(def, &cfg);
    assert_eq!(evidence.len(), 4, "should still produce evidence even with a null body");
    for ev in &evidence {
        assert_eq!(ev.status_id, StatusId::Ineffective, "expected Ineffective for unconfigured push rules");
    }
    assert_eq!(evidence[0].findings[0].title, "Push Rules Are Configured");
}

// ---------------------------------------------------------------------------
// GITLAB-6.01 — audit event logging + SIEM streaming
// ---------------------------------------------------------------------------

#[test]
fn gitlab601_pass_events_and_streaming_present() {
    let events = serde_json::json!([
        {"id": 1, "author_id": 5, "entity_id": 42, "entity_type": "Project", "details": {"action": "push_rule_update"}, "created_at": "2026-08-01T00:00:00Z"},
        {"id": 2, "author_id": 5, "entity_id": 42, "entity_type": "Project", "details": {"action": "member_role_change"}, "created_at": "2026-08-02T00:00:00Z"}
    ]);
    let destinations = serde_json::json!([
        {"id": 1, "name": "siem-forwarder", "destination_url": "https://siem.example.com/ingest", "verification_token": "abc123"}
    ]);
    let server = MockHTTPServer::new(vec![(200, events.to_string()), (200, destinations.to_string())]);
    let def = load_check("GITLAB-6.01-audit-events.check.yaml");

    let mut cfg = base_config(server.url());
    cfg.insert("GITLAB_GROUP_ID".to_string(), "my-group".to_string());

    let evidence = run_observer(def, &cfg);
    assert_eq!(evidence.len(), 2);
    for ev in &evidence {
        assert_eq!(ev.control_id, "GITLAB-6.01");
        assert_eq!(ev.status_id, StatusId::Effective, "expected Effective, got: {}", ev.status);
        assert!(ev.findings.is_empty());
    }
}

#[test]
fn gitlab601_fail_no_events_no_streaming() {
    let events = serde_json::json!([]);
    let destinations = serde_json::json!([]);
    let server = MockHTTPServer::new(vec![(200, events.to_string()), (200, destinations.to_string())]);
    let def = load_check("GITLAB-6.01-audit-events.check.yaml");

    let mut cfg = base_config(server.url());
    cfg.insert("GITLAB_GROUP_ID".to_string(), "my-group".to_string());

    let evidence = run_observer(def, &cfg);
    assert_eq!(evidence.len(), 2);

    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
    assert_eq!(evidence[0].findings[0].severity_id, 4); // high

    assert_eq!(evidence[1].status_id, StatusId::Ineffective);
    assert_eq!(evidence[1].findings[0].severity_id, 3); // medium
}

// ---------------------------------------------------------------------------
// Loader integration: every checks/gitlab/*.check.yaml file loads cleanly
// ---------------------------------------------------------------------------

#[test]
fn all_gitlab_checks_load_and_have_hth_references() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("checks/gitlab");
    let defs = ocean::check::loader::load_definitions_from_dir(&dir);

    assert!(!defs.is_empty(), "expected at least one GitLab check to load");

    let ids: Vec<&str> = defs.iter().map(|d| d.id.as_str()).collect();
    assert!(ids.contains(&"GITLAB-1.03"), "missing GITLAB-1.03, got: {ids:?}");
    assert!(ids.contains(&"GITLAB-2.01"), "missing GITLAB-2.01, got: {ids:?}");
    assert!(ids.contains(&"GITLAB-4.01"), "missing GITLAB-4.01, got: {ids:?}");
    assert!(ids.contains(&"GITLAB-6.01"), "missing GITLAB-6.01, got: {ids:?}");

    for def in &defs {
        assert_eq!(def.source, "gitlab", "{}: source should be 'gitlab'", def.id);
        assert!(
            !def.references.hth.is_empty(),
            "{}: references.hth is mandatory for GitLab checks",
            def.id
        );
        assert!(
            def.references.hth.starts_with("gitlab:"),
            "{}: references.hth should be 'gitlab:N.N', got '{}'",
            def.id,
            def.references.hth
        );
        assert!(!def.assertions.is_empty(), "{}: check has no assertions", def.id);
        assert!(!def.steps.is_empty(), "{}: check has no steps", def.id);
    }
}
