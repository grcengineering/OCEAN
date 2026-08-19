// Integration test: load + execute the Wave-2c checks end-to-end (mocked HTTP).
//
// Covers pass and fail cases for the eight bundled checks across four new
// vendors (Rapid7 InsightVM, Tenable Vulnerability Management, SailPoint
// Identity Security Cloud, OneLogin), plus a load-all sanity test per vendor
// directory. Mirrors tests/check_slack_parity.rs's MockHTTPServer pattern.
//
// Fixtures reflect the field shapes documented in the HTH how-to-harden pack
// code these checks derive from:
//   - packs/rapid7/api/hth-rapid7-3.01-rbac-role-audit.sh,
//     hth-rapid7-3.02-admin-account-audit.sh (InsightVM Security Console API
//     v3, HAL-style {"resources": [...]} envelope, HTTP Basic auth).
//   - packs/tenable/api/hth-tenable-1.02-user-role-audit.sh,
//     hth-tenable-1.03-audit-log-export.sh (Tenable Vulnerability Management
//     REST API, X-ApiKeys header, {"users": [...]} / {"events": [...]}
//     envelopes).
//   - packs/sailpoint/api/hth-sailpoint-2.02-pat-governance.sh (Identity
//     Security Cloud v3 Personal Access Tokens API — OAuth client-credentials
//     mint, then a bare JSON array response).
//   - packs/onelogin/api/hth-onelogin-3.03-privileged-role-inventory.sh,
//     hth-onelogin-3.04-inactive-users.sh, hth-onelogin-5.01-events-export.sh
//     (OneLogin REST API v2/v1 — OAuth client-credentials mint, then either a
//     bare JSON array (v2) or a {"data": [...]} envelope (v1 Events, which
//     also uses the documented "bearer:<token>" header format with a colon).

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
/// port. Multi-step checks (SailPoint, OneLogin) queue one response per step.
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

/// Load a bundled check as-is (base URL is fully input-driven, e.g. Rapid7's
/// `console_url` / SailPoint's `sail_base_url` — no host string to rewrite).
fn load_check(vendor: &str, filename: &str) -> ocean::check::CheckDefinition {
    let content = std::fs::read_to_string(check_path(vendor, filename))
        .unwrap_or_else(|e| panic!("read {filename}: {e}"));
    serde_yaml::from_str(&content).unwrap_or_else(|e| panic!("parse {filename}: {e}"))
}

/// Load a bundled check, rewriting a literal real-host (or real-host-template)
/// substring to the mock server's base URL before parsing.
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
        .unwrap_or_else(|e| panic!("execute {id}: {e:?}"))
}

// ---------------------------------------------------------------------------
// R7-3.01 — RBAC role audit (at most one all-permissions role)
// ---------------------------------------------------------------------------

fn r7_config(mock_url: &str) -> HashMap<String, String> {
    let mut cfg = HashMap::new();
    cfg.insert("RAPID7_BASIC_AUTH".to_string(), "dGVzdDp0ZXN0".to_string());
    cfg.insert("console_url".to_string(), mock_url.to_string());
    cfg
}

#[test]
fn r7301_pass_single_all_permissions_role() {
    let body = serde_json::json!({
        "resources": [
            {"name": "Global Administrator", "id": 1, "privileges": ["all-permissions"]},
            {"name": "Auditor", "id": 2, "privileges": ["view-reports", "view-assets"]}
        ]
    });
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check("rapid7", "R7-3.01-rbac-role-audit.check.yaml");

    let evidence = run_observer(def, &r7_config(server.url()));
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].control_id, "R7-3.01");
    assert_eq!(evidence[0].status_id, StatusId::Effective);
    assert!(evidence[0].findings.is_empty());
}

#[test]
fn r7301_fail_two_all_permissions_roles() {
    let body = serde_json::json!({
        "resources": [
            {"name": "Global Administrator", "id": 1, "privileges": ["all-permissions"]},
            {"name": "Rogue Custom Role", "id": 3, "privileges": ["all-permissions"]}
        ]
    });
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check("rapid7", "R7-3.01-rbac-role-audit.check.yaml");

    let evidence = run_observer(def, &r7_config(server.url()));
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
    assert_eq!(evidence[0].findings[0].severity_id, 4); // high
}

// ---------------------------------------------------------------------------
// R7-3.02 — Global Administrator account ceiling
// ---------------------------------------------------------------------------

fn r7_user(login: &str, superuser: bool, enabled: bool) -> serde_json::Value {
    serde_json::json!({
        "login": login, "enabled": enabled, "locked": false,
        "role": {"name": if superuser { "Global Administrator" } else { "User" }, "superuser": superuser},
        "authentication": {"type": "normal"}
    })
}

#[test]
fn r7302_pass_within_admin_ceiling() {
    let body = serde_json::json!({
        "resources": [
            r7_user("admin1", true, true),
            r7_user("admin2", true, true),
            r7_user("analyst1", false, true)
        ]
    });
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check("rapid7", "R7-3.02-admin-account-ceiling.check.yaml");

    let evidence = run_observer(def, &r7_config(server.url()));
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn r7302_fail_exceeds_admin_ceiling() {
    let body = serde_json::json!({
        "resources": [
            r7_user("admin1", true, true),
            r7_user("admin2", true, true),
            r7_user("admin3", true, true),
            r7_user("admin4", true, true)
        ]
    });
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check("rapid7", "R7-3.02-admin-account-ceiling.check.yaml");

    let evidence = run_observer(def, &r7_config(server.url()));
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
    assert_eq!(evidence[0].findings[0].severity_id, 4); // high
}

// ---------------------------------------------------------------------------
// TEN-1.02 — Administrator [64] account ceiling
// ---------------------------------------------------------------------------

fn tenable_config() -> HashMap<String, String> {
    let mut cfg = HashMap::new();
    cfg.insert(
        "TENABLE_API_KEYS".to_string(),
        "accessKey=AK123;secretKey=SK456".to_string(),
    );
    cfg
}

fn tenable_user(username: &str, permissions: u32, enabled: bool) -> serde_json::Value {
    serde_json::json!({
        "username": username, "permissions": permissions, "enabled": enabled,
        "api_permitted": true,
        "two_factor": {"sms_enabled": 0, "email_enabled": 0}
    })
}

#[test]
fn ten102_pass_within_admin_ceiling() {
    let body = serde_json::json!({
        "users": [
            tenable_user("admin1@example.com", 64, true),
            tenable_user("admin2@example.com", 64, true),
            tenable_user("scanner@example.com", 40, true)
        ]
    });
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "tenable",
        "TEN-1.02-admin-account-ceiling.check.yaml",
        "https://cloud.tenable.com",
        server.url(),
    );

    let evidence = run_observer(def, &tenable_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn ten102_fail_exceeds_admin_ceiling() {
    let body = serde_json::json!({
        "users": [
            tenable_user("admin1@example.com", 64, true),
            tenable_user("admin2@example.com", 64, true),
            tenable_user("admin3@example.com", 64, true),
            tenable_user("admin4@example.com", 64, true)
        ]
    });
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "tenable",
        "TEN-1.02-admin-account-ceiling.check.yaml",
        "https://cloud.tenable.com",
        server.url(),
    );

    let evidence = run_observer(def, &tenable_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
    assert_eq!(evidence[0].findings[0].severity_id, 4); // high
}

// ---------------------------------------------------------------------------
// TEN-1.03 — administrator audit log actively capturing events
// ---------------------------------------------------------------------------

fn tenable_audit_config() -> HashMap<String, String> {
    let mut cfg = tenable_config();
    cfg.insert("audit_since".to_string(), "2026-07-01".to_string());
    cfg
}

#[test]
fn ten103_pass_audit_events_present() {
    let body = serde_json::json!({
        "events": [
            {"action": "user.role_change", "actor": {"id": "1", "name": "admin1@example.com"},
             "crud": "U", "received": "2026-07-15T00:00:00Z",
             "target": {"id": "9", "name": "analyst@example.com", "type": "user"}}
        ]
    });
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "tenable",
        "TEN-1.03-audit-log-active.check.yaml",
        "https://cloud.tenable.com",
        server.url(),
    );

    let evidence = run_observer(def, &tenable_audit_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn ten103_fail_no_audit_events() {
    let body = serde_json::json!({"events": []});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "tenable",
        "TEN-1.03-audit-log-active.check.yaml",
        "https://cloud.tenable.com",
        server.url(),
    );

    let evidence = run_observer(def, &tenable_audit_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
    assert_eq!(evidence[0].findings[0].severity_id, 4); // high
}

// ---------------------------------------------------------------------------
// SAIL-2.02 — non-managed PATs must not be never-expiring
// ---------------------------------------------------------------------------

fn sail_config(mock_url: &str) -> HashMap<String, String> {
    let mut cfg = HashMap::new();
    cfg.insert("SAIL_CLIENT_ID".to_string(), "client-abc".to_string());
    cfg.insert("SAIL_CLIENT_SECRET".to_string(), "secret-xyz".to_string());
    cfg.insert("sail_base_url".to_string(), mock_url.to_string());
    cfg
}

#[test]
fn sail202_pass_no_never_expiring_non_managed_pats() {
    let token_resp =
        serde_json::json!({"access_token": "tok-123", "token_type": "Bearer", "expires_in": 3600});
    let pats = serde_json::json!([
        {"id": "1", "name": "ci-integration", "owner": {"name": "svc-ci"},
         "created": "2026-01-01T00:00:00Z", "lastUsed": "2026-07-01T00:00:00Z",
         "expirationDate": "2026-12-01T00:00:00Z", "managed": false},
        {"id": "2", "name": "slpt-support-token", "owner": {"name": "slpt.services"},
         "created": "2026-01-01T00:00:00Z", "lastUsed": null,
         "expirationDate": null, "managed": true}
    ]);
    let server = MockHTTPServer::new(vec![(200, token_resp.to_string()), (200, pats.to_string())]);
    let def = load_check("sailpoint", "SAIL-2.02-pat-never-expiring.check.yaml");

    let evidence = run_observer(def, &sail_config(server.url()));
    assert_eq!(evidence.len(), 1);
    assert_eq!(
        evidence[0].status_id,
        StatusId::Effective,
        "expected Effective, got: {}",
        evidence[0].status
    );
}

#[test]
fn sail202_fail_never_expiring_non_managed_pat_found() {
    let token_resp =
        serde_json::json!({"access_token": "tok-123", "token_type": "Bearer", "expires_in": 3600});
    let pats = serde_json::json!([
        {"id": "3", "name": "leaky-integration", "owner": {"name": "alice"},
         "created": "2025-06-01T00:00:00Z", "lastUsed": "2026-01-01T00:00:00Z",
         "expirationDate": null, "managed": false}
    ]);
    let server = MockHTTPServer::new(vec![(200, token_resp.to_string()), (200, pats.to_string())]);
    let def = load_check("sailpoint", "SAIL-2.02-pat-never-expiring.check.yaml");

    let evidence = run_observer(def, &sail_config(server.url()));
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
    assert_eq!(evidence[0].findings[0].severity_id, 5); // critical
}

// ---------------------------------------------------------------------------
// OL-3.03 — privileged role inventory (reachability)
// ---------------------------------------------------------------------------

fn onelogin_config() -> HashMap<String, String> {
    let mut cfg = HashMap::new();
    cfg.insert("ONELOGIN_CLIENT_ID".to_string(), "ol-client-id".to_string());
    cfg.insert(
        "ONELOGIN_CLIENT_SECRET".to_string(),
        "ol-client-secret".to_string(),
    );
    cfg.insert("onelogin_subdomain".to_string(), "testcorp".to_string());
    cfg
}

const OL_HOST_TEMPLATE: &str = "https://{{onelogin_subdomain}}.onelogin.com";

#[test]
fn ol303_pass_roles_retrieved() {
    let token_resp =
        serde_json::json!({"access_token": "ol-tok", "token_type": "bearer", "expires_in": 36000});
    let roles = serde_json::json!([
        {"id": 1, "name": "Super User", "admins": [10, 11], "users": [10, 11, 12]},
        {"id": 2, "name": "Help Desk", "admins": [13], "users": [13]}
    ]);
    let server = MockHTTPServer::new(vec![
        (200, token_resp.to_string()),
        (200, roles.to_string()),
    ]);
    let def = load_check_with_mock_urls(
        "onelogin",
        "OL-3.03-privileged-role-inventory.check.yaml",
        OL_HOST_TEMPLATE,
        server.url(),
    );

    let evidence = run_observer(def, &onelogin_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(
        evidence[0].status_id,
        StatusId::Effective,
        "expected Effective, got: {}",
        evidence[0].status
    );
}

#[test]
fn ol303_fail_roles_api_unreachable() {
    let token_resp =
        serde_json::json!({"access_token": "ol-tok", "token_type": "bearer", "expires_in": 36000});
    let error_body = serde_json::json!({"status": {"code": 401, "message": "Unauthorized"}});
    let server = MockHTTPServer::new(vec![
        (200, token_resp.to_string()),
        (401, error_body.to_string()),
    ]);
    let def = load_check_with_mock_urls(
        "onelogin",
        "OL-3.03-privileged-role-inventory.check.yaml",
        OL_HOST_TEMPLATE,
        server.url(),
    );

    let evidence = run_observer(def, &onelogin_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
}

// ---------------------------------------------------------------------------
// OL-3.04 — inactive users past the suspension cutoff (reachability)
// ---------------------------------------------------------------------------

fn onelogin_inactive_config() -> HashMap<String, String> {
    let mut cfg = onelogin_config();
    cfg.insert(
        "inactive_cutoff".to_string(),
        "2026-05-01T00:00:00Z".to_string(),
    );
    cfg
}

#[test]
fn ol304_pass_inactive_users_retrieved() {
    let token_resp =
        serde_json::json!({"access_token": "ol-tok", "token_type": "bearer", "expires_in": 36000});
    let users = serde_json::json!([
        {"id": 100, "username": "dormant.contractor", "email": "dormant@example.com",
         "state": 1, "status": 1, "last_login": "2026-01-01T00:00:00Z"}
    ]);
    let server = MockHTTPServer::new(vec![
        (200, token_resp.to_string()),
        (200, users.to_string()),
    ]);
    let def = load_check_with_mock_urls(
        "onelogin",
        "OL-3.04-inactive-users.check.yaml",
        OL_HOST_TEMPLATE,
        server.url(),
    );

    let evidence = run_observer(def, &onelogin_inactive_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(
        evidence[0].status_id,
        StatusId::Effective,
        "expected Effective, got: {}",
        evidence[0].status
    );
}

#[test]
fn ol304_fail_users_api_unreachable() {
    let token_resp =
        serde_json::json!({"access_token": "ol-tok", "token_type": "bearer", "expires_in": 36000});
    let error_body =
        serde_json::json!({"status": {"code": 500, "message": "Internal Server Error"}});
    let server = MockHTTPServer::new(vec![
        (200, token_resp.to_string()),
        (500, error_body.to_string()),
    ]);
    let def = load_check_with_mock_urls(
        "onelogin",
        "OL-3.04-inactive-users.check.yaml",
        OL_HOST_TEMPLATE,
        server.url(),
    );

    let evidence = run_observer(def, &onelogin_inactive_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
}

// ---------------------------------------------------------------------------
// OL-5.01 — event audit logging actively capturing events
// ---------------------------------------------------------------------------

#[test]
fn ol501_pass_recent_events_present() {
    let token_resp =
        serde_json::json!({"access_token": "ol-tok", "token_type": "bearer", "expires_in": 36000});
    let events = serde_json::json!({
        "data": [
            {"id": 555, "created_at": "2026-08-01T00:00:00Z", "event_type_id": 5,
             "user_name": "alice", "actor_user_name": "alice", "ipaddr": "10.0.0.1", "app_name": "-"}
        ],
        "pagination": {"next_link": null}
    });
    let server = MockHTTPServer::new(vec![
        (200, token_resp.to_string()),
        (200, events.to_string()),
    ]);
    let def = load_check_with_mock_urls(
        "onelogin",
        "OL-5.01-audit-logging-active.check.yaml",
        OL_HOST_TEMPLATE,
        server.url(),
    );

    let evidence = run_observer(def, &onelogin_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(
        evidence[0].status_id,
        StatusId::Effective,
        "expected Effective, got: {}",
        evidence[0].status
    );
}

#[test]
fn ol501_fail_no_recent_events() {
    let token_resp =
        serde_json::json!({"access_token": "ol-tok", "token_type": "bearer", "expires_in": 36000});
    let events = serde_json::json!({"data": [], "pagination": {"next_link": null}});
    let server = MockHTTPServer::new(vec![
        (200, token_resp.to_string()),
        (200, events.to_string()),
    ]);
    let def = load_check_with_mock_urls(
        "onelogin",
        "OL-5.01-audit-logging-active.check.yaml",
        OL_HOST_TEMPLATE,
        server.url(),
    );

    let evidence = run_observer(def, &onelogin_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
    assert_eq!(evidence[0].findings[0].severity_id, 4); // high
}

// ---------------------------------------------------------------------------
// Loader integration: every checks/{vendor}/*.check.yaml loads cleanly
// ---------------------------------------------------------------------------

fn assert_vendor_dir_loads(vendor: &str, expected_ids: &[&str], hth_prefix: &str) {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("checks")
        .join(vendor);
    let defs = ocean::check::loader::load_definitions_from_dir(&dir);

    assert!(
        !defs.is_empty(),
        "expected at least one {vendor} check to load"
    );

    let ids: Vec<&str> = defs.iter().map(|d| d.id.as_str()).collect();
    for expected in expected_ids {
        assert!(ids.contains(expected), "missing {expected}, got: {ids:?}");
    }

    for def in &defs {
        assert_eq!(
            def.source, vendor,
            "{}: source should be '{vendor}'",
            def.id
        );
        assert!(
            !def.references.hth.is_empty(),
            "{}: references.hth is mandatory for {vendor} checks",
            def.id
        );
        assert!(
            def.references.hth.starts_with(hth_prefix),
            "{}: references.hth should start with '{hth_prefix}', got '{}'",
            def.id,
            def.references.hth
        );
        assert!(
            !def.assertions.is_empty(),
            "{}: check has no assertions",
            def.id
        );
        assert!(!def.steps.is_empty(), "{}: check has no steps", def.id);
    }
}

#[test]
fn all_rapid7_checks_load_and_have_hth_references() {
    assert_vendor_dir_loads("rapid7", &["R7-3.01", "R7-3.02"], "rapid7:");
}

#[test]
fn all_tenable_checks_load_and_have_hth_references() {
    assert_vendor_dir_loads("tenable", &["TEN-1.02", "TEN-1.03"], "tenable:");
}

#[test]
fn all_sailpoint_checks_load_and_have_hth_references() {
    assert_vendor_dir_loads("sailpoint", &["SAIL-2.02"], "sailpoint:");
}

#[test]
fn all_onelogin_checks_load_and_have_hth_references() {
    assert_vendor_dir_loads("onelogin", &["OL-3.03", "OL-3.04", "OL-5.01"], "onelogin:");
}

// ─── Form-encoding certification ─────────────────────────────────────────────
// OAuth token endpoints (SailPoint, OneLogin) are form-only; the interpreter's
// body_form support must put application/x-www-form-urlencoded on the wire,
// not JSON. This test captures the raw mint request and asserts both the
// Content-Type header and the k=v body shape.

#[test]
fn oauth_mint_sends_form_urlencoded_not_json() {
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind capture server");
    let addr = listener.local_addr().expect("addr");
    let captured: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
    let captured_writer = Arc::clone(&captured);

    std::thread::spawn(move || {
        // First request: the mint (capture it). Second: the PAT list.
        for i in 0..2 {
            if let Ok((mut stream, _)) = listener.accept() {
                // Never hang the suite: bounded reads regardless of client behavior.
                let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
                // Read until the full body arrives (headers + Content-Length),
                // not just the first TCP segment.
                let mut raw: Vec<u8> = Vec::new();
                let mut buf = [0u8; 16384];
                loop {
                    let n = match stream.read(&mut buf) {
                        Ok(n) => n,
                        Err(_) => break, // timeout or reset — respond with what we have
                    };
                    if n == 0 {
                        break;
                    }
                    raw.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&raw);
                    if let Some(header_end) = text.find(
                        "

",
                    ) {
                        let content_length = text
                            .lines()
                            .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
                            .and_then(|l| l.split(':').nth(1))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        if raw.len() >= header_end + 4 + content_length {
                            break;
                        }
                    }
                }
                if i == 0 {
                    *captured_writer.lock().unwrap() = String::from_utf8_lossy(&raw).to_string();
                }
                let body = if i == 0 {
                    r#"{"access_token":"tok"}"#
                } else {
                    r#"[]"#
                };
                let raw = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(raw.as_bytes());
            }
        }
    });

    let base = format!("http://127.0.0.1:{}", addr.port());
    let content = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("checks/sailpoint/SAIL-2.02-pat-never-expiring.check.yaml"),
    )
    .expect("read SAIL-2.02");
    let rewritten = content.replace("{{sail_base_url}}", &base);
    let def: ocean::check::CheckDefinition =
        serde_yaml::from_str(&rewritten).expect("parse SAIL-2.02");

    let mut cfg = std::collections::HashMap::new();
    cfg.insert("SAIL_CLIENT_ID".to_string(), "cid".to_string());
    cfg.insert("SAIL_CLIENT_SECRET".to_string(), "sec".to_string());
    cfg.insert("sail_base_url".to_string(), base.clone());
    let observer = ocean::check::YamlObserver::new(def);
    use ocean::module::Observer as _;
    let _ = observer.observe(&cfg);

    let raw = captured.lock().unwrap().clone();
    assert!(
        raw.contains("application/x-www-form-urlencoded"),
        "mint request must be form-encoded, got:\n{raw}"
    );
    assert!(
        raw.contains("grant_type=client_credentials"),
        "form body must carry k=v pairs, got:\n{raw}"
    );
    assert!(
        !raw.contains("{\"grant_type\""),
        "mint body must not be JSON, got:\n{raw}"
    );
}
