// Integration test: load + execute the Slack checks end-to-end (mocked HTTP).
//
// Mirrors tests/check_pipeline.rs's MockHTTPServer pattern. Covers pass and
// fail cases for all three bundled Slack checks (SLACK-1.02, SLACK-3.01,
// SLACK-5.01) plus a load-all sanity test for checks/slack/.
//
// Fixtures reflect the field shapes the HTH how-to-harden Slack pack code
// parses (packs/slack/sdk/hth-slack-1.02-scim-user-listing.py,
// packs/slack/api/hth-slack-3.01-audit-approved-apps.py,
// packs/slack/sdk/hth-slack-5.01-audit-logs-api.py) cross-checked against
// api.slack.com/methods documentation:
//   - SCIM Users API (scim/v1/Users): SCIM 2.0 ListResponse envelope
//     (totalResults, itemsPerPage, startIndex, Resources) — no "ok" field.
//   - admin.apps.approved.list / admin.apps.restricted.list: standard
//     Slack Web API {"ok": true/false, ...} envelope.
//   - Audit Logs API (audit/v1/logs): bare {"entries": [...],
//     "response_metadata": {...}} — no "ok" field either.

use std::collections::HashMap;
use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use ocean::check::register_check;
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

fn slack_check_path(filename: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("checks/slack")
        .join(filename)
}

/// Load a bundled Slack check, rewriting its real API host to the mock server.
fn load_check_with_mock_urls(filename: &str, real_host: &str, mock_base: &str) -> ocean::check::CheckDefinition {
    let content = std::fs::read_to_string(slack_check_path(filename))
        .unwrap_or_else(|e| panic!("read {filename}: {e}"));
    let rewritten = content.replace(real_host, mock_base);
    serde_yaml::from_str(&rewritten).unwrap_or_else(|e| panic!("parse rewritten {filename}: {e}"))
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

fn slack_admin_config() -> HashMap<String, String> {
    let mut cfg = HashMap::new();
    cfg.insert("SLACK_ADMIN_TOKEN".to_string(), "xoxp-test-admin".to_string());
    cfg
}

fn slack_audit_config() -> HashMap<String, String> {
    let mut cfg = HashMap::new();
    cfg.insert("SLACK_AUDIT_TOKEN".to_string(), "xoxp-test-audit".to_string());
    cfg
}

// ---------------------------------------------------------------------------
// SLACK-1.02 — SCIM user provisioning
// ---------------------------------------------------------------------------

#[test]
fn slack102_pass_scim_users_provisioned() {
    let body = serde_json::json!({
        "totalResults": 42,
        "itemsPerPage": 20,
        "startIndex": 1,
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "Resources": [
            {"id": "U0001", "userName": "alice@example.com", "active": true}
        ]
    });
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "SLACK-1.02-scim-provisioning.check.yaml",
        "https://api.slack.com",
        server.url(),
    );

    let evidence = run_observer(def, &slack_admin_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].control_id, "SLACK-1.02");
    assert_eq!(evidence[0].status_id, StatusId::Effective);
    assert!(evidence[0].findings.is_empty());
}

#[test]
fn slack102_fail_scim_zero_users() {
    let body = serde_json::json!({
        "totalResults": 0,
        "itemsPerPage": 20,
        "startIndex": 1,
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "Resources": []
    });
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "SLACK-1.02-scim-provisioning.check.yaml",
        "https://api.slack.com",
        server.url(),
    );

    let evidence = run_observer(def, &slack_admin_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
    assert_eq!(evidence[0].findings.len(), 1);
    assert_eq!(evidence[0].findings[0].severity_id, 4); // high
}

// ---------------------------------------------------------------------------
// SLACK-3.01 — approved/restricted app scope audit (ok-envelope quirk)
// ---------------------------------------------------------------------------

#[test]
fn slack301_pass_no_admin_scope_apps() {
    let approved = serde_json::json!({
        "ok": true,
        "approved_apps": [
            {"name": "Google Drive", "scopes": ["channels:read", "files:read"]}
        ],
        "response_metadata": {"next_cursor": ""}
    });
    let restricted = serde_json::json!({
        "ok": true,
        "restricted_apps": [],
        "response_metadata": {"next_cursor": ""}
    });
    let server = MockHTTPServer::new(vec![(200, approved.to_string()), (200, restricted.to_string())]);
    let def = load_check_with_mock_urls(
        "SLACK-3.01-app-approval.check.yaml",
        "https://slack.com",
        server.url(),
    );

    let evidence = run_observer(def, &slack_admin_config());
    assert_eq!(evidence.len(), 2, "expected 2 evidence items (one per assertion)");
    for ev in &evidence {
        assert_eq!(ev.control_id, "SLACK-3.01");
        assert_eq!(ev.status_id, StatusId::Effective, "expected Effective, got: {}", ev.status);
        assert!(ev.findings.is_empty());
    }
}

#[test]
fn slack301_fail_admin_scope_app_found() {
    let approved = serde_json::json!({
        "ok": true,
        "approved_apps": [
            {"name": "Shadow IT Bot", "scopes": ["admin", "chat:write"]}
        ],
        "response_metadata": {"next_cursor": ""}
    });
    let restricted = serde_json::json!({
        "ok": true,
        "restricted_apps": [],
        "response_metadata": {"next_cursor": ""}
    });
    let server = MockHTTPServer::new(vec![(200, approved.to_string()), (200, restricted.to_string())]);
    let def = load_check_with_mock_urls(
        "SLACK-3.01-app-approval.check.yaml",
        "https://slack.com",
        server.url(),
    );

    let evidence = run_observer(def, &slack_admin_config());
    assert_eq!(evidence.len(), 2);

    // First assertion (API reachable) passes.
    assert_eq!(evidence[0].status_id, StatusId::Effective);
    // Second assertion (no admin-scope app) fails.
    assert_eq!(evidence[1].status_id, StatusId::Ineffective);
    assert_eq!(evidence[1].findings[0].title, "No Approved App Holds Admin-Level OAuth Scope");
    assert_eq!(evidence[1].findings[0].severity_id, 4); // high
}

/// Honors the Slack `{"ok": true/false}` envelope quirk: when the API call
/// itself fails (`ok: false`, no `approved_apps` payload), the reachability
/// assertion must fail on the envelope rather than erroring on a missing
/// payload field.
#[test]
fn slack301_fail_ok_envelope_false_no_payload() {
    let approved = serde_json::json!({
        "ok": false,
        "error": "not_allowed_token_type"
    });
    let restricted = serde_json::json!({
        "ok": false,
        "error": "not_allowed_token_type"
    });
    let server = MockHTTPServer::new(vec![(200, approved.to_string()), (200, restricted.to_string())]);
    let def = load_check_with_mock_urls(
        "SLACK-3.01-app-approval.check.yaml",
        "https://slack.com",
        server.url(),
    );

    let evidence = run_observer(def, &slack_admin_config());
    assert_eq!(evidence.len(), 2, "should still produce evidence even when the payload field is absent");

    // ok-envelope assertion fails honestly.
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
    // Scope-audit assertion fails closed (missing `approved_apps` var), not a panic.
    assert_eq!(evidence[1].status_id, StatusId::Ineffective);
}

// ---------------------------------------------------------------------------
// SLACK-5.01 — audit logs actively capturing events (no ok-envelope)
// ---------------------------------------------------------------------------

#[test]
fn slack501_pass_audit_entries_present() {
    let body = serde_json::json!({
        "entries": [
            {
                "id": "0123",
                "date_create": 1700000000,
                "action": "user_login",
                "actor": {"type": "user", "user": {"id": "U1", "email": "alice@example.com"}}
            },
            {
                "id": "0124",
                "date_create": 1700000100,
                "action": "role_change_to_admin",
                "actor": {"type": "user", "user": {"id": "U2", "email": "bob@example.com"}}
            }
        ],
        "response_metadata": {"next_cursor": ""}
    });
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "SLACK-5.01-audit-logging.check.yaml",
        "https://api.slack.com",
        server.url(),
    );

    let evidence = run_observer(def, &slack_audit_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Effective);
    assert!(evidence[0].findings.is_empty());
}

#[test]
fn slack501_fail_no_audit_entries() {
    let body = serde_json::json!({
        "entries": [],
        "response_metadata": {"next_cursor": ""}
    });
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "SLACK-5.01-audit-logging.check.yaml",
        "https://api.slack.com",
        server.url(),
    );

    let evidence = run_observer(def, &slack_audit_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
    assert_eq!(evidence[0].findings[0].severity_id, 4); // high
}

// ---------------------------------------------------------------------------
// Loader integration: every checks/slack/*.check.yaml file loads cleanly
// ---------------------------------------------------------------------------

#[test]
fn all_slack_checks_load_and_have_hth_references() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("checks/slack");
    let defs = ocean::check::loader::load_definitions_from_dir(&dir);

    assert!(!defs.is_empty(), "expected at least one Slack check to load");

    let ids: Vec<&str> = defs.iter().map(|d| d.id.as_str()).collect();
    assert!(ids.contains(&"SLACK-1.02"), "missing SLACK-1.02, got: {ids:?}");
    assert!(ids.contains(&"SLACK-3.01"), "missing SLACK-3.01, got: {ids:?}");
    assert!(ids.contains(&"SLACK-5.01"), "missing SLACK-5.01, got: {ids:?}");

    for def in &defs {
        assert_eq!(def.source, "slack", "{}: source should be 'slack'", def.id);
        assert!(
            !def.references.hth.is_empty(),
            "{}: references.hth is mandatory for Slack checks",
            def.id
        );
        assert!(
            def.references.hth.starts_with("slack:"),
            "{}: references.hth should be 'slack:N.N', got '{}'",
            def.id,
            def.references.hth
        );
        assert!(!def.assertions.is_empty(), "{}: check has no assertions", def.id);
    }
}
