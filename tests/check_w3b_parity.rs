// Integration test: load + execute the wave-3b checks end-to-end (mocked HTTP).
//
// Covers the three new vendors stood up in this wave: Anthropic Claude Admin
// API (ANTH-*), ChatGPT Enterprise Compliance API (CGPT-*), and Workato
// (WKTO-*). Mirrors tests/check_w2a_parity.rs's MockHTTPServer pattern.
//
// Fixtures reflect the field shapes the HTH how-to-harden pack code parses
// for each vendor, cross-checked against the vendor API references cited in
// each check's YAML:
//   - Anthropic Admin API (api.anthropic.com/v1/organizations/*):
//     {"data": [...]} envelope for users, api_keys, workspaces, invites, and
//     usage_report/claude_code (per docs.anthropic.com/en/api/admin-api-overview
//     and the HTH packs/anthropic-claude/api/*.sh scripts, which all parse
//     `.data`).
//   - OpenAI ChatGPT Enterprise Compliance Logs Platform
//     (api.chatgpt.com/v1/compliance/{scope}/{principal}/logs):
//     {"data": [...], "has_more": bool, "last_end_time": ...} per the HTH
//     packs/chatgpt-enterprise/api/common.sh compliance_list_logs() helper.
//   - Workato API (www.workato.com/api/*): {"result": [...]} envelope for
//     managed_users, roles, properties, connections, api_clients,
//     api_access_profiles, deployments, recipes, and activity_logs, per the
//     HTH packs/workato/api/*.sh scripts, which all parse `.result`.

use std::collections::HashMap;
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ocean::check::register_check;
use ocean::evidence::StatusId;
use ocean::module::{Executor, Registry};

/// Minimal mock HTTP server for integration tests.
///
/// Serves a queue of `(status_code, body)` responses in order on an ephemeral
/// port. Unlike a bare one-shot-per-connection server, this reads and
/// answers requests in a loop on each accepted connection (true HTTP/1.1
/// keep-alive) before falling back to accepting a new one. ureq pools
/// connections per host:port and silently retries a dead pooled connection
/// for idempotent GETs but not for POSTs, so a server that closes the
/// socket after every single response races that pool and produces
/// intermittent "connection forcibly closed" failures on any check that
/// issues several sequential requests to the same mock host. Cooperating
/// with keep-alive instead of fighting it removes the race.
struct MockHTTPServer {
    base_url: String,
}

impl MockHTTPServer {
    fn new(responses: Vec<(u16, String)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock HTTP server");
        let addr = listener.local_addr().expect("local addr");
        let queue = Arc::new(Mutex::new(responses));

        std::thread::spawn(move || loop {
            let stream = match listener.accept() {
                Ok((s, _)) => s,
                Err(_) => break,
            };
            let _ = stream.set_nodelay(true);
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            serve_connection(stream, &queue);

            if queue.lock().unwrap().is_empty() {
                break;
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

/// Serve requests on one accepted connection until the client stops sending
/// requests (connection closed / idle) or the response queue drains.
fn serve_connection(mut stream: TcpStream, queue: &Arc<Mutex<Vec<(u16, String)>>>) {
    loop {
        if read_one_request(&mut stream).is_none() {
            return;
        }

        let resp = {
            let mut q = queue.lock().unwrap();
            if q.is_empty() {
                return;
            }
            q.remove(0)
        };
        let (status, body) = resp;
        let raw = format!(
            "HTTP/1.1 {status} OK\r\nContent-Length: {len}\r\nContent-Type: application/json\r\nConnection: keep-alive\r\n\r\n{body}",
            len = body.len()
        );
        if stream.write_all(raw.as_bytes()).is_err() {
            return;
        }
        let _ = stream.flush();
    }
}

/// Read exactly one HTTP request (headers through the blank line, then a
/// Content-Length-sized body if present) off `stream`, leaving the
/// connection positioned at the start of the next request.
fn read_one_request(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) => return None,
            Ok(_) => {
                buf.push(byte[0]);
                if buf.ends_with(b"\r\n\r\n") {
                    break;
                }
                if buf.len() > 65536 {
                    return None;
                }
            }
            Err(_) => return None,
        }
    }

    let header_str = String::from_utf8_lossy(&buf);
    let content_length: usize = header_str
        .lines()
        .find_map(|l| {
            let lower = l.to_ascii_lowercase();
            lower
                .strip_prefix("content-length:")
                .map(|v| v.trim().parse::<usize>().unwrap_or(0))
        })
        .unwrap_or(0);

    if content_length > 0 {
        let mut body = vec![0u8; content_length];
        if stream.read_exact(&mut body).is_err() {
            return None;
        }
        buf.extend_from_slice(&body);
    }

    Some(buf)
}

fn check_path(vendor: &str, filename: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("checks")
        .join(vendor)
        .join(filename)
}

/// Load a bundled check, rewriting its real API host to the mock server —
/// for checks with a hardcoded host in the `url` field.
fn load_check_with_mock_urls(
    vendor: &str,
    filename: &str,
    real_host: &str,
    mock_base: &str,
) -> ocean::check::CheckDefinition {
    let content = std::fs::read_to_string(check_path(vendor, filename))
        .unwrap_or_else(|e| panic!("read {filename}: {e}"));
    let rewritten = content.replace(real_host, mock_base);
    serde_yaml::from_str(&rewritten).unwrap_or_else(|e| panic!("parse rewritten {filename}: {e}"))
}

fn run_observer(
    def: ocean::check::CheckDefinition,
    config: &HashMap<String, String>,
) -> Vec<ocean::evidence::Evidence> {
    let registry = Arc::new(Registry::new());
    let id = def.id.clone();
    register_check(&registry, def);
    let executor = Executor::new(Arc::clone(&registry));
    executor
        .execute_observer(&id, config)
        .unwrap_or_else(|e| panic!("execute {id}: {e}"))
}

// ---------------------------------------------------------------------------
// ANTH-1.02 — least-privilege organization roles
// ---------------------------------------------------------------------------

fn anth_config() -> HashMap<String, String> {
    let mut cfg = HashMap::new();
    cfg.insert("ANTHROPIC_ADMIN_KEY".to_string(), "sk-ant-admin01-test".to_string());
    cfg
}

#[test]
fn anth102_pass_admin_count_within_limit() {
    let body = serde_json::json!({"data": [
        {"id": "u1", "name": "Alice", "email": "alice@x.com", "role": "admin"},
        {"id": "u2", "name": "Bob", "email": "bob@x.com", "role": "developer"}
    ]});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "anthropic-claude",
        "ANTH-1.02-least-privilege-org-roles.check.yaml",
        "https://api.anthropic.com",
        server.url(),
    );

    let evidence = run_observer(def, &anth_config());
    assert_eq!(evidence.len(), 2);
    for ev in &evidence {
        assert_eq!(ev.control_id, "ANTH-1.02");
        assert_eq!(ev.status_id, StatusId::Effective, "expected Effective, got: {}", ev.status);
    }
}

#[test]
fn anth102_fail_admin_count_exceeds_limit() {
    let admins: Vec<_> = (0..4)
        .map(|i| serde_json::json!({"id": format!("u{i}"), "name": format!("Admin{i}"), "email": format!("a{i}@x.com"), "role": "admin"}))
        .collect();
    let body = serde_json::json!({"data": admins});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "anthropic-claude",
        "ANTH-1.02-least-privilege-org-roles.check.yaml",
        "https://api.anthropic.com",
        server.url(),
    );

    let evidence = run_observer(def, &anth_config());
    assert_eq!(evidence.len(), 2);
    assert_eq!(evidence[0].status_id, StatusId::Effective, "reachability assertion should pass");
    assert_eq!(evidence[1].status_id, StatusId::Ineffective, "admin count assertion should fail with 4 admins");
    assert_eq!(evidence[1].findings[0].severity_id, 3); // medium
}

// ---------------------------------------------------------------------------
// ANTH-2.01 — API key workspace scoping
// ---------------------------------------------------------------------------

#[test]
fn anth201_pass_all_keys_named_and_scoped() {
    let body = serde_json::json!({"data": [
        {"id": "k1", "name": "ml-team-prod", "workspace_id": "wrkspc_1", "status": "active", "created_at": "2026-01-01T00:00:00Z"}
    ]});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "anthropic-claude",
        "ANTH-2.01-api-key-workspace-scoping.check.yaml",
        "https://api.anthropic.com",
        server.url(),
    );

    let evidence = run_observer(def, &anth_config());
    assert_eq!(evidence.len(), 2);
    for ev in &evidence {
        assert_eq!(ev.control_id, "ANTH-2.01");
        assert_eq!(ev.status_id, StatusId::Effective, "expected Effective, got: {}", ev.status);
    }
}

#[test]
fn anth201_fail_unnamed_and_default_workspace_keys() {
    let body = serde_json::json!({"data": [
        {"id": "k1", "name": "", "workspace_id": "wrkspc_1", "status": "active", "created_at": "2026-01-01T00:00:00Z"},
        {"id": "k2", "name": "unscoped-key", "workspace_id": null, "status": "active", "created_at": "2026-01-01T00:00:00Z"}
    ]});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "anthropic-claude",
        "ANTH-2.01-api-key-workspace-scoping.check.yaml",
        "https://api.anthropic.com",
        server.url(),
    );

    let evidence = run_observer(def, &anth_config());
    assert_eq!(evidence.len(), 2);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective, "unnamed key should fail");
    assert_eq!(evidence[1].status_id, StatusId::Ineffective, "default-workspace key should fail");
}

// ---------------------------------------------------------------------------
// ANTH-3.02 — workspace admin count
// ---------------------------------------------------------------------------

fn anth_workspace_config() -> HashMap<String, String> {
    let mut cfg = anth_config();
    cfg.insert("workspace_id".to_string(), "wrkspc_test".to_string());
    cfg
}

#[test]
fn anth302_pass_workspace_admin_count_within_limit() {
    let body = serde_json::json!({"data": [
        {"user_id": "u1", "workspace_role": "workspace_admin"},
        {"user_id": "u2", "workspace_role": "workspace_developer"}
    ]});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "anthropic-claude",
        "ANTH-3.02-workspace-admin-count.check.yaml",
        "https://api.anthropic.com",
        server.url(),
    );

    let evidence = run_observer(def, &anth_workspace_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].control_id, "ANTH-3.02");
    assert_eq!(evidence[0].status_id, StatusId::Effective, "expected Effective, got: {}", evidence[0].status);
}

#[test]
fn anth302_fail_workspace_admin_count_exceeds_limit() {
    let admins: Vec<_> = (0..3)
        .map(|i| serde_json::json!({"user_id": format!("u{i}"), "workspace_role": "workspace_admin"}))
        .collect();
    let body = serde_json::json!({"data": admins});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "anthropic-claude",
        "ANTH-3.02-workspace-admin-count.check.yaml",
        "https://api.anthropic.com",
        server.url(),
    );

    let evidence = run_observer(def, &anth_workspace_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
}

// ---------------------------------------------------------------------------
// ANTH-4.01 — data residency configuration
// ---------------------------------------------------------------------------

#[test]
fn anth401_pass_all_active_workspaces_have_geo() {
    let body = serde_json::json!({"data": [
        {"id": "w1", "display_name": "prod", "settings": {"workspace_geo": "us"}},
        {"id": "w2", "display_name": "archived-ws", "settings": {}, "archived_at": "2025-01-01T00:00:00Z"}
    ]});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "anthropic-claude",
        "ANTH-4.01-data-residency-configured.check.yaml",
        "https://api.anthropic.com",
        server.url(),
    );

    let evidence = run_observer(def, &anth_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].control_id, "ANTH-4.01");
    assert_eq!(evidence[0].status_id, StatusId::Effective, "expected Effective, got: {}", evidence[0].status);
}

#[test]
fn anth401_fail_active_workspace_missing_geo() {
    let body = serde_json::json!({"data": [
        {"id": "w1", "display_name": "prod", "settings": {}}
    ]});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "anthropic-claude",
        "ANTH-4.01-data-residency-configured.check.yaml",
        "https://api.anthropic.com",
        server.url(),
    );

    let evidence = run_observer(def, &anth_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
}

// ---------------------------------------------------------------------------
// ANTH-6.01 — pending invites audit
// ---------------------------------------------------------------------------

#[test]
fn anth601_pass_no_pending_invites() {
    let body = serde_json::json!({"data": [
        {"id": "i1", "email": "a@x.com", "status": "accepted"}
    ]});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "anthropic-claude",
        "ANTH-6.01-pending-invites-audit.check.yaml",
        "https://api.anthropic.com",
        server.url(),
    );

    let evidence = run_observer(def, &anth_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].control_id, "ANTH-6.01");
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn anth601_fail_pending_invite_present() {
    let body = serde_json::json!({"data": [
        {"id": "i1", "email": "a@x.com", "status": "pending", "role": "user", "created_at": "2026-01-01T00:00:00Z", "expires_at": "2026-02-01T00:00:00Z"}
    ]});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "anthropic-claude",
        "ANTH-6.01-pending-invites-audit.check.yaml",
        "https://api.anthropic.com",
        server.url(),
    );

    let evidence = run_observer(def, &anth_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
    assert_eq!(evidence[0].findings[0].severity_id, 2); // low
}

// ---------------------------------------------------------------------------
// ANTH-7.04 — Claude Code metrics active
// ---------------------------------------------------------------------------

fn anth_report_config() -> HashMap<String, String> {
    let mut cfg = anth_config();
    cfg.insert("report_date".to_string(), "2026-08-01".to_string());
    cfg
}

#[test]
fn anth704_pass_records_present() {
    let body = serde_json::json!({"data": [
        {"actor": {"email_address": "dev@x.com"}, "core_metrics": {"num_sessions": 3}}
    ]});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "anthropic-claude",
        "ANTH-7.04-claude-code-metrics-active.check.yaml",
        "https://api.anthropic.com",
        server.url(),
    );

    let evidence = run_observer(def, &anth_report_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].control_id, "ANTH-7.04");
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn anth704_fail_zero_records() {
    let body = serde_json::json!({"data": []});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "anthropic-claude",
        "ANTH-7.04-claude-code-metrics-active.check.yaml",
        "https://api.anthropic.com",
        server.url(),
    );

    let evidence = run_observer(def, &anth_report_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
}

// ---------------------------------------------------------------------------
// CGPT-6.01 — agent RBAC audit log active
// ---------------------------------------------------------------------------

fn cgpt_config() -> HashMap<String, String> {
    let mut cfg = HashMap::new();
    cfg.insert("COMPLIANCE_API_KEY".to_string(), "cmpl-test-key".to_string());
    cfg.insert("openai_principal_id".to_string(), "ws_test_123".to_string());
    cfg.insert("compliance_scope".to_string(), "workspaces".to_string());
    cfg.insert("after".to_string(), "2026-07-01T00:00:00Z".to_string());
    cfg
}

#[test]
fn cgpt601_pass_user_log_events_present() {
    let body = serde_json::json!({"data": [{"id": "log1"}], "has_more": false});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "chatgpt-enterprise",
        "CGPT-6.01-agent-rbac-audit-log-active.check.yaml",
        "https://api.chatgpt.com",
        server.url(),
    );

    let evidence = run_observer(def, &cgpt_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].control_id, "CGPT-6.01");
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn cgpt601_fail_zero_user_log_events() {
    let body = serde_json::json!({"data": [], "has_more": false});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "chatgpt-enterprise",
        "CGPT-6.01-agent-rbac-audit-log-active.check.yaml",
        "https://api.chatgpt.com",
        server.url(),
    );

    let evidence = run_observer(def, &cgpt_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
    assert_eq!(evidence[0].findings[0].severity_id, 3); // medium
}

// ---------------------------------------------------------------------------
// CGPT-6.06 — compliance log export active
// ---------------------------------------------------------------------------

#[test]
fn cgpt606_pass_auth_log_events_present() {
    let body = serde_json::json!({"data": [{"id": "auth1"}], "has_more": false});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "chatgpt-enterprise",
        "CGPT-6.06-compliance-log-export-active.check.yaml",
        "https://api.chatgpt.com",
        server.url(),
    );

    let evidence = run_observer(def, &cgpt_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].control_id, "CGPT-6.06");
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn cgpt606_fail_zero_auth_log_events() {
    let body = serde_json::json!({"data": [], "has_more": false});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "chatgpt-enterprise",
        "CGPT-6.06-compliance-log-export-active.check.yaml",
        "https://api.chatgpt.com",
        server.url(),
    );

    let evidence = run_observer(def, &cgpt_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
    assert_eq!(evidence[0].findings[0].severity_id, 4); // high
}

// ---------------------------------------------------------------------------
// WKTO-1.05 — SCIM provisioning coverage
// ---------------------------------------------------------------------------

fn wkto_config() -> HashMap<String, String> {
    let mut cfg = HashMap::new();
    cfg.insert("WORKATO_API_TOKEN".to_string(), "wkto-test-token".to_string());
    cfg
}

#[test]
fn wkto105_pass_all_users_have_external_id() {
    let body = serde_json::json!({"result": [
        {"id": 1, "name": "Alice", "email": "a@x.com", "external_id": "idp-1"}
    ]});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "workato",
        "WKTO-1.05-scim-provisioning-coverage.check.yaml",
        "https://www.workato.com",
        server.url(),
    );

    let evidence = run_observer(def, &wkto_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].control_id, "WKTO-1.05");
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn wkto105_fail_user_missing_external_id() {
    let body = serde_json::json!({"result": [
        {"id": 1, "name": "Manual User", "email": "m@x.com", "external_id": ""}
    ]});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "workato",
        "WKTO-1.05-scim-provisioning-coverage.check.yaml",
        "https://www.workato.com",
        server.url(),
    );

    let evidence = run_observer(def, &wkto_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
}

// ---------------------------------------------------------------------------
// WKTO-2.01 — custom roles inventory (informational reachability)
// ---------------------------------------------------------------------------

#[test]
fn wkto201_pass_roles_api_reachable() {
    let body = serde_json::json!({"result": [
        {"id": 1, "name": "Recipe Developer", "description": "Build and test recipes"}
    ]});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "workato",
        "WKTO-2.01-custom-roles-inventory.check.yaml",
        "https://www.workato.com",
        server.url(),
    );

    let evidence = run_observer(def, &wkto_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].control_id, "WKTO-2.01");
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn wkto201_fail_roles_api_unreachable() {
    let body = serde_json::json!({"error": "unauthorized"});
    let server = MockHTTPServer::new(vec![(401, body.to_string())]);
    let def = load_check_with_mock_urls(
        "workato",
        "WKTO-2.01-custom-roles-inventory.check.yaml",
        "https://www.workato.com",
        server.url(),
    );

    let evidence = run_observer(def, &wkto_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
}

// ---------------------------------------------------------------------------
// WKTO-2.05 — limit admin access
// ---------------------------------------------------------------------------

#[test]
fn wkto205_pass_admin_count_within_limit() {
    let body = serde_json::json!({"result": [
        {"id": 1, "name": "Alice", "email": "a@x.com", "role_name": "Admin"}
    ]});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "workato",
        "WKTO-2.05-limit-admin-access.check.yaml",
        "https://www.workato.com",
        server.url(),
    );

    let evidence = run_observer(def, &wkto_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].control_id, "WKTO-2.05");
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn wkto205_fail_admin_count_exceeds_limit() {
    let admins: Vec<_> = (0..6)
        .map(|i| serde_json::json!({"id": i, "name": format!("Admin{i}"), "email": format!("a{i}@x.com"), "role_name": "Admin"}))
        .collect();
    let body = serde_json::json!({"result": admins});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "workato",
        "WKTO-2.05-limit-admin-access.check.yaml",
        "https://www.workato.com",
        server.url(),
    );

    let evidence = run_observer(def, &wkto_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
}

// ---------------------------------------------------------------------------
// WKTO-3.04 — sensitive property flagging
// ---------------------------------------------------------------------------

#[test]
fn wkto304_pass_secret_shaped_properties_marked_sensitive() {
    let body = serde_json::json!({"result": [
        {"name": "API_SECRET_KEY", "sensitive": true},
        {"name": "REGION", "sensitive": false}
    ]});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "workato",
        "WKTO-3.04-sensitive-property-flagging.check.yaml",
        "https://www.workato.com",
        server.url(),
    );

    let evidence = run_observer(def, &wkto_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].control_id, "WKTO-3.04");
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn wkto304_fail_secret_shaped_property_unmarked() {
    let body = serde_json::json!({"result": [
        {"name": "DB_PASSWORD", "sensitive": false}
    ]});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "workato",
        "WKTO-3.04-sensitive-property-flagging.check.yaml",
        "https://www.workato.com",
        server.url(),
    );

    let evidence = run_observer(def, &wkto_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
    assert_eq!(evidence[0].findings[0].severity_id, 4); // high
}

// ---------------------------------------------------------------------------
// WKTO-4.01 — connection authorization audit
// ---------------------------------------------------------------------------

#[test]
fn wkto401_pass_all_connections_authorized() {
    let body = serde_json::json!({"result": [
        {"id": 1, "name": "salesforce-prod", "provider": "salesforce", "authorized": true}
    ]});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "workato",
        "WKTO-4.01-connection-authorization-audit.check.yaml",
        "https://www.workato.com",
        server.url(),
    );

    let evidence = run_observer(def, &wkto_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].control_id, "WKTO-4.01");
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn wkto401_fail_unauthorized_connection_present() {
    let body = serde_json::json!({"result": [
        {"id": 1, "name": "broken-conn", "provider": "netsuite", "authorized": false}
    ]});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "workato",
        "WKTO-4.01-connection-authorization-audit.check.yaml",
        "https://www.workato.com",
        server.url(),
    );

    let evidence = run_observer(def, &wkto_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
}

// ---------------------------------------------------------------------------
// WKTO-5.01 — API clients scoped (two-step check)
// ---------------------------------------------------------------------------

#[test]
fn wkto501_pass_every_client_has_access_profile() {
    let clients = serde_json::json!({"result": [{"id": "c1", "name": "partner-system", "created_at": "2026-01-01T00:00:00Z"}]});
    let profiles = serde_json::json!({"result": [{"id": "p1", "name": "partner-scope", "api_client_id": "c1", "api_collection_ids": [1]}]});
    let server = MockHTTPServer::new(vec![(200, clients.to_string()), (200, profiles.to_string())]);
    let def = load_check_with_mock_urls(
        "workato",
        "WKTO-5.01-api-clients-scoped.check.yaml",
        "https://www.workato.com",
        server.url(),
    );

    let evidence = run_observer(def, &wkto_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].control_id, "WKTO-5.01");
    assert_eq!(evidence[0].status_id, StatusId::Effective, "expected Effective, got: {}", evidence[0].status);
}

#[test]
fn wkto501_fail_client_with_no_access_profile() {
    let clients = serde_json::json!({"result": [
        {"id": "c1", "name": "partner-system", "created_at": "2026-01-01T00:00:00Z"},
        {"id": "c2", "name": "unscoped-client", "created_at": "2026-01-01T00:00:00Z"}
    ]});
    let profiles = serde_json::json!({"result": [{"id": "p1", "name": "partner-scope", "api_client_id": "c1", "api_collection_ids": [1]}]});
    let server = MockHTTPServer::new(vec![(200, clients.to_string()), (200, profiles.to_string())]);
    let def = load_check_with_mock_urls(
        "workato",
        "WKTO-5.01-api-clients-scoped.check.yaml",
        "https://www.workato.com",
        server.url(),
    );

    let evidence = run_observer(def, &wkto_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
}

// ---------------------------------------------------------------------------
// WKTO-7.02 / WKTO-7.03 — informational reachability audits
// ---------------------------------------------------------------------------

#[test]
fn wkto702_pass_deployments_api_reachable() {
    let body = serde_json::json!({"result": [{"id": 1, "name": "release-42", "state": "completed", "created_at": "2026-01-01T00:00:00Z"}]});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "workato",
        "WKTO-7.02-deployment-inventory.check.yaml",
        "https://www.workato.com",
        server.url(),
    );

    let evidence = run_observer(def, &wkto_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].control_id, "WKTO-7.02");
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn wkto703_pass_folder_recipes_reachable() {
    let mut cfg = wkto_config();
    cfg.insert("folder_id".to_string(), "fldr_123".to_string());
    let body = serde_json::json!({"result": [{"id": 1, "name": "sync-recipe", "running": true, "version": 3}]});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "workato",
        "WKTO-7.03-cicd-recipe-inventory.check.yaml",
        "https://www.workato.com",
        server.url(),
    );

    let evidence = run_observer(def, &cfg);
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].control_id, "WKTO-7.03");
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

// ---------------------------------------------------------------------------
// WKTO-8.01 — activity audit log active
// ---------------------------------------------------------------------------

#[test]
fn wkto801_pass_activity_log_active() {
    let body = serde_json::json!({"result": [
        {"created_at": "2026-08-01T00:00:00Z", "user_name": "alice", "event_type": "recipe_started", "resource_type": "recipe", "details": {}}
    ]});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "workato",
        "WKTO-8.01-activity-audit-log-active.check.yaml",
        "https://www.workato.com",
        server.url(),
    );

    let evidence = run_observer(def, &wkto_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].control_id, "WKTO-8.01");
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn wkto801_fail_zero_activity_events() {
    let body = serde_json::json!({"result": []});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "workato",
        "WKTO-8.01-activity-audit-log-active.check.yaml",
        "https://www.workato.com",
        server.url(),
    );

    let evidence = run_observer(def, &wkto_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
    assert_eq!(evidence[0].findings[0].severity_id, 4); // high
}

// ---------------------------------------------------------------------------
// WKTO-8.03 — recipe error monitoring
// ---------------------------------------------------------------------------

#[test]
fn wkto803_pass_all_active_recipes_running() {
    let body = serde_json::json!({"result": [
        {"id": 1, "name": "sync-recipe", "last_run_at": "2026-08-01T00:00:00Z", "running": true}
    ]});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "workato",
        "WKTO-8.03-recipe-error-monitoring.check.yaml",
        "https://www.workato.com",
        server.url(),
    );

    let evidence = run_observer(def, &wkto_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].control_id, "WKTO-8.03");
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn wkto803_fail_active_recipe_stopped() {
    let body = serde_json::json!({"result": [
        {"id": 1, "name": "sync-recipe", "last_run_at": "2026-08-01T00:00:00Z", "running": false}
    ]});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "workato",
        "WKTO-8.03-recipe-error-monitoring.check.yaml",
        "https://www.workato.com",
        server.url(),
    );

    let evidence = run_observer(def, &wkto_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
}

// ---------------------------------------------------------------------------
// Loader integration: every checks/{anthropic-claude,chatgpt-enterprise,
// workato}/*.check.yaml file loads cleanly with mandatory HTH references.
// ---------------------------------------------------------------------------

fn assert_vendor_dir_loads(dir_name: &str, source: &str, hth_prefixes: &[&str], expected_ids: &[&str]) {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("checks")
        .join(dir_name);
    let defs = ocean::check::loader::load_definitions_from_dir(&dir);

    assert!(!defs.is_empty(), "expected at least one {dir_name} check to load");

    let ids: Vec<&str> = defs.iter().map(|d| d.id.as_str()).collect();
    for expected in expected_ids {
        assert!(ids.contains(expected), "missing {expected}, got: {ids:?}");
    }

    for def in &defs {
        assert_eq!(def.source, source, "{}: source should be '{source}'", def.id);
        assert!(
            !def.references.hth.is_empty(),
            "{}: references.hth is mandatory for {dir_name} checks",
            def.id
        );
        assert!(
            hth_prefixes.iter().any(|p| def.references.hth.starts_with(p)),
            "{}: references.hth should start with one of {hth_prefixes:?}, got '{}'",
            def.id,
            def.references.hth
        );
        assert!(!def.assertions.is_empty(), "{}: check has no assertions", def.id);
        assert!(!def.steps.is_empty(), "{}: check has no steps", def.id);
    }
}

#[test]
fn all_anthropic_claude_checks_load_and_have_hth_references() {
    assert_vendor_dir_loads(
        "anthropic-claude",
        "anthropic-claude",
        &["anthropic-claude:", "anthropic-api:", "claude-code:"],
        &["ANTH-1.02", "ANTH-2.01", "ANTH-3.02", "ANTH-4.01", "ANTH-6.01", "ANTH-7.04"],
    );
}

#[test]
fn all_chatgpt_enterprise_checks_load_and_have_hth_references() {
    assert_vendor_dir_loads(
        "chatgpt-enterprise",
        "chatgpt-enterprise",
        &["chatgpt-enterprise:"],
        &["CGPT-6.01", "CGPT-6.06"],
    );
}

#[test]
fn all_workato_checks_load_and_have_hth_references() {
    assert_vendor_dir_loads(
        "workato",
        "workato",
        &["workato:"],
        &[
            "WKTO-1.05", "WKTO-2.01", "WKTO-2.05", "WKTO-3.04", "WKTO-4.01",
            "WKTO-5.01", "WKTO-7.02", "WKTO-7.03", "WKTO-8.01", "WKTO-8.03",
        ],
    );
}
