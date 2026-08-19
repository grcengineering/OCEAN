// Integration test: load + execute the wave-2a checks end-to-end (mocked HTTP).
//
// Covers the three new vendors stood up in this wave: 1Password (OP-4.01),
// SendGrid (SG-1.04, SG-3.02), and Zoom (ZOOM-2.01, ZOOM-4.02). Mirrors
// tests/check_slack_parity.rs's MockHTTPServer pattern.
//
// Fixtures reflect the field shapes the HTH how-to-harden pack code parses
// for each vendor, cross-checked against the vendor API references cited in
// each check's YAML:
//   - 1Password Events API (events.1password.com/api/v2/{auth/introspect,
//     auditevents,itemusages,signinattempts}): {"features":[...]} for
//     introspect, {"items":[...],"cursor":...,"has_more":...} for each
//     event-class endpoint (per 1password.dev/events-api/reference/).
//   - SendGrid v3 REST API: /v3/access_settings/whitelist returns
//     {"result":[...]}; /v3/teammates has a documented envelope
//     inconsistency between "results" (example response) and "result"
//     (schema) — both are exercised here.
//   - Zoom REST API v2 (api.zoom.us): /v2/accounts/{accountId}/settings and
//     /v2/accounts/{accountId}/lock_settings return nested setting-group
//     objects; ZOOM-2.01/4.02 assert group presence only (no per-field
//     assertions — see check YAML rationale).

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
/// intermittent "connection forcibly closed" failures on any check —
/// like OP-4.01 — that issues several sequential requests to the same
/// mock host. Cooperating with keep-alive instead of fighting it removes
/// the race.
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

/// Load a bundled check as-is (no host rewriting) — for checks whose HTTP
/// host is templated via an input (e.g. OP-4.01's `{{op_events_base}}`),
/// where the mock URL is supplied through config instead.
fn load_check(vendor: &str, filename: &str) -> ocean::check::CheckDefinition {
    let content = std::fs::read_to_string(check_path(vendor, filename))
        .unwrap_or_else(|e| panic!("read {filename}: {e}"));
    serde_yaml::from_str(&content).unwrap_or_else(|e| panic!("parse {filename}: {e}"))
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
// OP-4.01 — 1Password Events API audit logging (host templated via input)
// ---------------------------------------------------------------------------

fn op_config(mock_url: &str) -> HashMap<String, String> {
    let mut cfg = HashMap::new();
    cfg.insert(
        "OP_EVENTS_TOKEN".to_string(),
        "op-events-test-token".to_string(),
    );
    cfg.insert("OP_EVENTS_BASE".to_string(), mock_url.to_string());
    cfg
}

#[test]
fn op401_pass_all_event_classes_active() {
    let introspect =
        serde_json::json!({"features": ["auditevents", "itemusages", "signinattempts"]});
    let audit_events = serde_json::json!({
        "items": [{"uuid": "e1", "action": "policy-change", "timestamp": "2026-01-01T00:00:00Z"}],
        "cursor": "c1",
        "has_more": false
    });
    let item_usages = serde_json::json!({
        "items": [{"uuid": "i1", "action": "item-viewed", "timestamp": "2026-01-01T00:00:00Z"}],
        "cursor": "c1",
        "has_more": false
    });
    let signin_attempts = serde_json::json!({
        "items": [{"uuid": "s1", "type": "credentials_ok", "timestamp": "2026-01-01T00:00:00Z"}],
        "cursor": "c1",
        "has_more": false
    });
    let server = MockHTTPServer::new(vec![
        (200, introspect.to_string()),
        (200, audit_events.to_string()),
        (200, item_usages.to_string()),
        (200, signin_attempts.to_string()),
    ]);
    let def = load_check("1password", "OP-4.01-events-api-audit-logging.check.yaml");

    let evidence = run_observer(def, &op_config(server.url()));
    assert_eq!(
        evidence.len(),
        4,
        "expected 4 evidence items (one per assertion)"
    );
    for ev in &evidence {
        assert_eq!(ev.control_id, "OP-4.01");
        assert_eq!(
            ev.status_id,
            StatusId::Effective,
            "expected Effective, got: {}",
            ev.status
        );
        assert!(ev.findings.is_empty());
    }
}

#[test]
fn op401_fail_zero_audit_events() {
    let introspect =
        serde_json::json!({"features": ["auditevents", "itemusages", "signinattempts"]});
    let audit_events = serde_json::json!({"items": [], "cursor": "c1", "has_more": false});
    let item_usages = serde_json::json!({
        "items": [{"uuid": "i1"}],
        "cursor": "c1",
        "has_more": false
    });
    let signin_attempts = serde_json::json!({
        "items": [{"uuid": "s1"}],
        "cursor": "c1",
        "has_more": false
    });
    let server = MockHTTPServer::new(vec![
        (200, introspect.to_string()),
        (200, audit_events.to_string()),
        (200, item_usages.to_string()),
        (200, signin_attempts.to_string()),
    ]);
    let def = load_check("1password", "OP-4.01-events-api-audit-logging.check.yaml");

    let evidence = run_observer(def, &op_config(server.url()));
    assert_eq!(evidence.len(), 4);

    // Order matches assertion declaration order: token, audit, item, signin.
    assert_eq!(
        evidence[0].status_id,
        StatusId::Effective,
        "token features assertion"
    );
    assert_eq!(
        evidence[1].status_id,
        StatusId::Ineffective,
        "audit events assertion should fail"
    );
    assert_eq!(evidence[1].findings[0].severity_id, 4); // high
    assert_eq!(
        evidence[2].status_id,
        StatusId::Effective,
        "item usage assertion"
    );
    assert_eq!(
        evidence[3].status_id,
        StatusId::Effective,
        "signin attempts assertion"
    );
}

#[test]
fn op401_fail_token_has_no_authorized_features() {
    let introspect = serde_json::json!({"features": []});
    let audit_events =
        serde_json::json!({"items": [{"uuid": "e1"}], "cursor": "c1", "has_more": false});
    let item_usages =
        serde_json::json!({"items": [{"uuid": "i1"}], "cursor": "c1", "has_more": false});
    let signin_attempts =
        serde_json::json!({"items": [{"uuid": "s1"}], "cursor": "c1", "has_more": false});
    let server = MockHTTPServer::new(vec![
        (200, introspect.to_string()),
        (200, audit_events.to_string()),
        (200, item_usages.to_string()),
        (200, signin_attempts.to_string()),
    ]);
    let def = load_check("1password", "OP-4.01-events-api-audit-logging.check.yaml");

    let evidence = run_observer(def, &op_config(server.url()));
    assert_eq!(evidence.len(), 4);
    assert_eq!(
        evidence[0].status_id,
        StatusId::Ineffective,
        "token features assertion should fail"
    );
    assert_eq!(evidence[0].findings[0].severity_id, 3); // medium
    assert_eq!(evidence[1].status_id, StatusId::Effective);
    assert_eq!(evidence[2].status_id, StatusId::Effective);
    assert_eq!(evidence[3].status_id, StatusId::Effective);
}

// ---------------------------------------------------------------------------
// SG-1.04 — SendGrid IP Access Management allowlist (hardcoded host)
// ---------------------------------------------------------------------------

fn sendgrid_config() -> HashMap<String, String> {
    let mut cfg = HashMap::new();
    cfg.insert("SENDGRID_API_KEY".to_string(), "SG.test-key".to_string());
    cfg
}

#[test]
fn sg104_pass_allowlist_populated() {
    let body = serde_json::json!({
        "result": [
            {"id": 1, "ip": "203.0.113.10", "created_at": 1700000000, "updated_at": 1700000000}
        ]
    });
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "sendgrid",
        "SG-1.04-ip-access-management.check.yaml",
        "https://api.sendgrid.com",
        server.url(),
    );

    let evidence = run_observer(def, &sendgrid_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].control_id, "SG-1.04");
    assert_eq!(evidence[0].status_id, StatusId::Effective);
    assert!(evidence[0].findings.is_empty());
}

#[test]
fn sg104_fail_allowlist_empty() {
    let body = serde_json::json!({"result": []});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "sendgrid",
        "SG-1.04-ip-access-management.check.yaml",
        "https://api.sendgrid.com",
        server.url(),
    );

    let evidence = run_observer(def, &sendgrid_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
    assert_eq!(evidence[0].findings[0].severity_id, 4); // high
}

// ---------------------------------------------------------------------------
// SG-3.02 — SendGrid teammate Administrator grant audit (envelope quirk)
// ---------------------------------------------------------------------------

#[test]
fn sg302_pass_results_key_admin_count_within_limit() {
    let body = serde_json::json!({
        "results": [
            {"username": "alice", "email": "alice@example.com", "user_type": "admin", "is_admin": true},
            {"username": "bob", "email": "bob@example.com", "user_type": "teammate", "is_admin": false}
        ]
    });
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "sendgrid",
        "SG-3.02-teammate-permissions-audit.check.yaml",
        "https://api.sendgrid.com",
        server.url(),
    );

    let evidence = run_observer(def, &sendgrid_config());
    assert_eq!(evidence.len(), 2);
    for ev in &evidence {
        assert_eq!(ev.control_id, "SG-3.02");
        assert_eq!(
            ev.status_id,
            StatusId::Effective,
            "expected Effective, got: {}",
            ev.status
        );
    }
}

#[test]
fn sg302_fail_results_key_too_many_admins() {
    let admins: Vec<_> = (0..4)
        .map(|i| serde_json::json!({"username": format!("admin{i}"), "email": format!("a{i}@x.com"), "user_type": "admin", "is_admin": true}))
        .collect();
    let body = serde_json::json!({"results": admins});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "sendgrid",
        "SG-3.02-teammate-permissions-audit.check.yaml",
        "https://api.sendgrid.com",
        server.url(),
    );

    let evidence = run_observer(def, &sendgrid_config());
    assert_eq!(evidence.len(), 2);
    assert_eq!(
        evidence[0].status_id,
        StatusId::Effective,
        "reachability assertion should pass"
    );
    assert_eq!(
        evidence[1].status_id,
        StatusId::Ineffective,
        "admin-count assertion should fail with 4 admins"
    );
    assert_eq!(evidence[1].findings[0].severity_id, 3); // medium
}

#[test]
fn sg302_pass_result_schema_key_variant() {
    let body = serde_json::json!({
        "result": [
            {"username": "alice", "email": "alice@example.com", "user_type": "admin", "is_admin": true}
        ]
    });
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "sendgrid",
        "SG-3.02-teammate-permissions-audit.check.yaml",
        "https://api.sendgrid.com",
        server.url(),
    );

    let evidence = run_observer(def, &sendgrid_config());
    assert_eq!(evidence.len(), 2);
    for ev in &evidence {
        assert_eq!(
            ev.status_id,
            StatusId::Effective,
            "expected Effective via the 'result' schema key, got: {}",
            ev.status
        );
    }
}

#[test]
fn sg302_fail_neither_envelope_key_present() {
    let body = serde_json::json!({"unexpected": "shape"});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "sendgrid",
        "SG-3.02-teammate-permissions-audit.check.yaml",
        "https://api.sendgrid.com",
        server.url(),
    );

    let evidence = run_observer(def, &sendgrid_config());
    assert_eq!(
        evidence.len(),
        2,
        "should still produce evidence, not panic, when neither key is present"
    );
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
    assert_eq!(evidence[1].status_id, StatusId::Ineffective);
}

// ---------------------------------------------------------------------------
// ZOOM-2.01 — meeting security setting-group presence (hardcoded host)
// ---------------------------------------------------------------------------

fn zoom_config() -> HashMap<String, String> {
    let mut cfg = HashMap::new();
    cfg.insert(
        "ZOOM_ACCESS_TOKEN".to_string(),
        "zoom-test-access-token".to_string(),
    );
    cfg
}

#[test]
fn zoom201_pass_groups_present_and_locks_reachable() {
    let settings = serde_json::json!({
        "schedule_meeting": {"require_password_for_scheduling_new_meetings": true},
        "in_meeting": {"waiting_room": true},
        "meeting_security": {"meeting_password": true}
    });
    let lock_settings = serde_json::json!({
        "schedule_meeting": {"require_password_for_scheduling_new_meetings": true}
    });
    let server = MockHTTPServer::new(vec![
        (200, settings.to_string()),
        (200, lock_settings.to_string()),
    ]);
    let def = load_check_with_mock_urls(
        "zoom",
        "ZOOM-2.01-meeting-security-settings-audit.check.yaml",
        "https://api.zoom.us",
        server.url(),
    );

    let evidence = run_observer(def, &zoom_config());
    assert_eq!(evidence.len(), 2);
    for ev in &evidence {
        assert_eq!(ev.control_id, "ZOOM-2.01");
        assert_eq!(
            ev.status_id,
            StatusId::Effective,
            "expected Effective, got: {}",
            ev.status
        );
    }
}

#[test]
fn zoom201_fail_missing_group_and_empty_locks() {
    let settings = serde_json::json!({
        "schedule_meeting": {},
        "in_meeting": {}
        // meeting_security intentionally absent
    });
    let lock_settings = serde_json::json!({});
    let server = MockHTTPServer::new(vec![
        (200, settings.to_string()),
        (200, lock_settings.to_string()),
    ]);
    let def = load_check_with_mock_urls(
        "zoom",
        "ZOOM-2.01-meeting-security-settings-audit.check.yaml",
        "https://api.zoom.us",
        server.url(),
    );

    let evidence = run_observer(def, &zoom_config());
    assert_eq!(evidence.len(), 2);
    assert_eq!(
        evidence[0].status_id,
        StatusId::Ineffective,
        "missing meeting_security group should fail"
    );
    assert_eq!(
        evidence[1].status_id,
        StatusId::Ineffective,
        "empty lock_settings should fail"
    );
}

// ---------------------------------------------------------------------------
// ZOOM-4.02 — recording security settings presence + account-wide lock
// ---------------------------------------------------------------------------

#[test]
fn zoom402_pass_recording_present_and_locked() {
    let settings = serde_json::json!({
        "recording": {"cloud_recording": true, "recording_password_requirement": {"length": 8}}
    });
    let lock_settings = serde_json::json!({
        "recording": {"cloud_recording": true}
    });
    let server = MockHTTPServer::new(vec![
        (200, settings.to_string()),
        (200, lock_settings.to_string()),
    ]);
    let def = load_check_with_mock_urls(
        "zoom",
        "ZOOM-4.02-recording-security-settings-audit.check.yaml",
        "https://api.zoom.us",
        server.url(),
    );

    let evidence = run_observer(def, &zoom_config());
    assert_eq!(evidence.len(), 2);
    for ev in &evidence {
        assert_eq!(ev.control_id, "ZOOM-4.02");
        assert_eq!(
            ev.status_id,
            StatusId::Effective,
            "expected Effective, got: {}",
            ev.status
        );
    }
}

#[test]
fn zoom402_fail_recording_not_locked() {
    let settings = serde_json::json!({"recording": {"cloud_recording": true}});
    let lock_settings = serde_json::json!({"in_meeting": {"waiting_room": true}});
    let server = MockHTTPServer::new(vec![
        (200, settings.to_string()),
        (200, lock_settings.to_string()),
    ]);
    let def = load_check_with_mock_urls(
        "zoom",
        "ZOOM-4.02-recording-security-settings-audit.check.yaml",
        "https://api.zoom.us",
        server.url(),
    );

    let evidence = run_observer(def, &zoom_config());
    assert_eq!(evidence.len(), 2);
    assert_eq!(
        evidence[0].status_id,
        StatusId::Effective,
        "recording group is present"
    );
    assert_eq!(
        evidence[1].status_id,
        StatusId::Ineffective,
        "recording lock is absent"
    );
    assert_eq!(evidence[1].findings[0].severity_id, 4); // high
}

#[test]
fn zoom402_fail_recording_group_absent() {
    let settings = serde_json::json!({"schedule_meeting": {}});
    let lock_settings = serde_json::json!({"recording": {"cloud_recording": true}});
    let server = MockHTTPServer::new(vec![
        (200, settings.to_string()),
        (200, lock_settings.to_string()),
    ]);
    let def = load_check_with_mock_urls(
        "zoom",
        "ZOOM-4.02-recording-security-settings-audit.check.yaml",
        "https://api.zoom.us",
        server.url(),
    );

    let evidence = run_observer(def, &zoom_config());
    assert_eq!(evidence.len(), 2);
    assert_eq!(
        evidence[0].status_id,
        StatusId::Ineffective,
        "recording group is absent from settings"
    );
    assert_eq!(
        evidence[1].status_id,
        StatusId::Effective,
        "recording lock is present"
    );
}

// ---------------------------------------------------------------------------
// Loader integration: every checks/{1password,sendgrid,zoom}/*.check.yaml
// file loads cleanly with mandatory HTH references.
// ---------------------------------------------------------------------------

fn assert_vendor_dir_loads(dir_name: &str, source: &str, hth_prefix: &str, expected_ids: &[&str]) {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("checks")
        .join(dir_name);
    let defs = ocean::check::loader::load_definitions_from_dir(&dir);

    assert!(
        !defs.is_empty(),
        "expected at least one {dir_name} check to load"
    );

    let ids: Vec<&str> = defs.iter().map(|d| d.id.as_str()).collect();
    for expected in expected_ids {
        assert!(ids.contains(expected), "missing {expected}, got: {ids:?}");
    }

    for def in &defs {
        assert_eq!(
            def.source, source,
            "{}: source should be '{source}'",
            def.id
        );
        assert!(
            !def.references.hth.is_empty(),
            "{}: references.hth is mandatory for {dir_name} checks",
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
fn all_1password_checks_load_and_have_hth_references() {
    assert_vendor_dir_loads("1password", "1password", "1password:", &["OP-4.01"]);
}

#[test]
fn all_sendgrid_checks_load_and_have_hth_references() {
    assert_vendor_dir_loads("sendgrid", "sendgrid", "sendgrid:", &["SG-1.04", "SG-3.02"]);
}

#[test]
fn all_zoom_checks_load_and_have_hth_references() {
    assert_vendor_dir_loads("zoom", "zoom", "zoom:", &["ZOOM-2.01", "ZOOM-4.02"]);
}
