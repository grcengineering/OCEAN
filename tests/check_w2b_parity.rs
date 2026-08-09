// Integration test: load + execute the Notion and Postman checks end-to-end
// (mocked HTTP). Mirrors tests/check_slack_parity.rs's MockHTTPServer
// pattern. Covers pass and fail cases for all five bundled checks
// (NOTION-2.01, NOTION-3.01, PM-2.04, PM-3.04, PM-4.01) plus a load-all
// sanity test for checks/notion/ and checks/postman/.
//
// Fixtures reflect the field shapes the HTH how-to-harden pack code parses,
// cross-checked against each vendor's own API docs:
//   - Notion GET /v1/users: {"results": [...], "has_more": bool,
//     "next_cursor": str|null} — per-user objects carry "type" ("person" |
//     "bot") and, for bot users, "name" (developers.notion.com/reference/get-users).
//   - Notion POST /v1/search: {"results": [...], "has_more": ..., ...} —
//     page objects carry "public_url" (string | null)
//     (developers.notion.com/reference/page, /reference/post-search).
//   - Postman GET /workspaces?type=public: {"workspaces": [...]}.
//   - Postman POST /detected-secrets-queries: {"data": [...], "meta": {...}}.
//   - Postman GET /audit/logs: {"trails": [...]} (no "ok" envelope).

use std::collections::HashMap;
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;
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

/// Load a bundled check, rewriting its real API host to the mock server.
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

fn run_observer(def: ocean::check::CheckDefinition, config: &HashMap<String, String>) -> Vec<ocean::evidence::Evidence> {
    let registry = Arc::new(Registry::new());
    let id = def.id.clone();
    register_check(&registry, def);
    let executor = Executor::new(Arc::clone(&registry));
    executor
        .execute_observer(&id, config)
        .unwrap_or_else(|e| panic!("execute {id}: {e}"))
}

fn notion_config() -> HashMap<String, String> {
    let mut cfg = HashMap::new();
    cfg.insert("NOTION_TOKEN".to_string(), "secret_test_token".to_string());
    cfg
}

fn postman_config() -> HashMap<String, String> {
    let mut cfg = HashMap::new();
    cfg.insert("POSTMAN_API_KEY".to_string(), "PMAK-test-key".to_string());
    cfg
}

// ---------------------------------------------------------------------------
// NOTION-2.01 — workspace membership / bot attribution audit
// ---------------------------------------------------------------------------

#[test]
fn notion201_pass_reachable_and_bots_named() {
    let body = serde_json::json!({
        "results": [
            {"object": "user", "id": "u1", "type": "person", "name": "Alice",
             "person": {"email": "alice@example.com"}},
            {"object": "user", "id": "u2", "type": "bot", "name": "CI Integration",
             "bot": {}}
        ],
        "has_more": false,
        "next_cursor": null
    });
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "notion",
        "NOTION-2.01-workspace-access-audit.check.yaml",
        "https://api.notion.com",
        server.url(),
    );

    let evidence = run_observer(def, &notion_config());
    assert_eq!(evidence.len(), 2, "expected 2 evidence items (one per assertion)");
    for ev in &evidence {
        assert_eq!(ev.control_id, "NOTION-2.01");
        assert_eq!(ev.status_id, StatusId::Effective, "expected Effective, got: {}", ev.status);
        assert!(ev.findings.is_empty());
    }
}

#[test]
fn notion201_fail_unnamed_bot_integration() {
    let body = serde_json::json!({
        "results": [
            {"object": "user", "id": "u1", "type": "person", "name": "Alice",
             "person": {"email": "alice@example.com"}},
            {"object": "user", "id": "u2", "type": "bot", "name": null, "bot": {}}
        ],
        "has_more": false,
        "next_cursor": null
    });
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "notion",
        "NOTION-2.01-workspace-access-audit.check.yaml",
        "https://api.notion.com",
        server.url(),
    );

    let evidence = run_observer(def, &notion_config());
    assert_eq!(evidence.len(), 2);

    // First assertion (API reachable) passes.
    assert_eq!(evidence[0].status_id, StatusId::Effective);
    // Second assertion (every bot has a name) fails.
    assert_eq!(evidence[1].status_id, StatusId::Ineffective);
    assert_eq!(
        evidence[1].findings[0].title,
        "Every Bot/Integration User Has a Visible Name"
    );
    assert_eq!(evidence[1].findings[0].severity_id, 3); // medium
}

/// A 403 (missing "Read user information" capability) returns a Notion
/// error object with no "results" key. The reachability assertion must
/// fail honestly, and the bot-naming assertion must fail closed on the
/// missing "users" variable rather than panicking.
#[test]
fn notion201_fail_403_no_results_key() {
    let body = serde_json::json!({
        "object": "error",
        "status": 403,
        "code": "restricted_resource",
        "message": "Insufficient permissions for this endpoint."
    });
    let server = MockHTTPServer::new(vec![(403, body.to_string())]);
    let def = load_check_with_mock_urls(
        "notion",
        "NOTION-2.01-workspace-access-audit.check.yaml",
        "https://api.notion.com",
        server.url(),
    );

    let evidence = run_observer(def, &notion_config());
    assert_eq!(evidence.len(), 2, "should still produce evidence even when the payload field is absent");
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
    assert_eq!(evidence[1].status_id, StatusId::Ineffective);
}

// ---------------------------------------------------------------------------
// NOTION-3.01 — public page audit
// ---------------------------------------------------------------------------

#[test]
fn notion301_pass_no_public_pages() {
    let body = serde_json::json!({
        "results": [
            {"object": "page", "id": "p1", "public_url": null, "last_edited_time": "2026-01-01T00:00:00.000Z"}
        ],
        "has_more": false,
        "next_cursor": null
    });
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "notion",
        "NOTION-3.01-public-page-audit.check.yaml",
        "https://api.notion.com",
        server.url(),
    );

    let evidence = run_observer(def, &notion_config());
    assert_eq!(evidence.len(), 2);
    for ev in &evidence {
        assert_eq!(ev.status_id, StatusId::Effective, "expected Effective, got: {}", ev.status);
    }
}

#[test]
fn notion301_fail_public_page_found() {
    let body = serde_json::json!({
        "results": [
            {"object": "page", "id": "p1", "public_url": null, "last_edited_time": "2026-01-01T00:00:00.000Z"},
            {"object": "page", "id": "p2", "public_url": "https://example.notion.site/p2",
             "last_edited_time": "2026-01-02T00:00:00.000Z"}
        ],
        "has_more": false,
        "next_cursor": null
    });
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "notion",
        "NOTION-3.01-public-page-audit.check.yaml",
        "https://api.notion.com",
        server.url(),
    );

    let evidence = run_observer(def, &notion_config());
    assert_eq!(evidence.len(), 2);
    assert_eq!(evidence[0].status_id, StatusId::Effective);
    assert_eq!(evidence[1].status_id, StatusId::Ineffective);
    assert_eq!(evidence[1].findings[0].severity_id, 4); // high
}

// ---------------------------------------------------------------------------
// PM-2.04 — public workspace audit
// ---------------------------------------------------------------------------

#[test]
fn pm204_pass_no_public_workspaces() {
    let body = serde_json::json!({"workspaces": []});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "postman",
        "PM-2.04-public-workspace-audit.check.yaml",
        "https://api.getpostman.com",
        server.url(),
    );

    let evidence = run_observer(def, &postman_config());
    assert_eq!(evidence.len(), 2);
    for ev in &evidence {
        assert_eq!(ev.control_id, "PM-2.04");
        assert_eq!(ev.status_id, StatusId::Effective, "expected Effective, got: {}", ev.status);
    }
}

#[test]
fn pm204_fail_public_workspace_found() {
    let body = serde_json::json!({
        "workspaces": [
            {"id": "w1", "name": "Public API Docs", "type": "team", "visibility": "public"}
        ]
    });
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "postman",
        "PM-2.04-public-workspace-audit.check.yaml",
        "https://api.getpostman.com",
        server.url(),
    );

    let evidence = run_observer(def, &postman_config());
    assert_eq!(evidence.len(), 2);
    assert_eq!(evidence[0].status_id, StatusId::Effective);
    assert_eq!(evidence[1].status_id, StatusId::Ineffective);
    assert_eq!(evidence[1].findings[0].severity_id, 4); // high
}

// ---------------------------------------------------------------------------
// PM-3.04 — secret scanner unresolved findings
// ---------------------------------------------------------------------------

#[test]
fn pm304_pass_no_unresolved_findings() {
    let body = serde_json::json!({"data": [], "meta": {"nextCursor": null}});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "postman",
        "PM-3.04-secret-scanner-findings.check.yaml",
        "https://api.getpostman.com",
        server.url(),
    );

    let evidence = run_observer(def, &postman_config());
    assert_eq!(evidence.len(), 2);
    for ev in &evidence {
        assert_eq!(ev.status_id, StatusId::Effective, "expected Effective, got: {}", ev.status);
    }
}

#[test]
fn pm304_fail_unresolved_finding_present() {
    let body = serde_json::json!({
        "data": [
            {
                "detectedAt": "2026-08-01T00:00:00.000Z",
                "secretId": "s1",
                "secretType": "aws_access_key",
                "resolution": "unresolved",
                "workspaceId": "w1",
                "occurrences": 1,
                "obfuscatedSecret": "AKIA****************"
            }
        ],
        "meta": {"nextCursor": null}
    });
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "postman",
        "PM-3.04-secret-scanner-findings.check.yaml",
        "https://api.getpostman.com",
        server.url(),
    );

    let evidence = run_observer(def, &postman_config());
    assert_eq!(evidence.len(), 2);
    assert_eq!(evidence[0].status_id, StatusId::Effective);
    assert_eq!(evidence[1].status_id, StatusId::Ineffective);
    assert_eq!(evidence[1].findings[0].severity_id, 5); // critical
}

// ---------------------------------------------------------------------------
// PM-4.01 — audit logs actively capturing events
// ---------------------------------------------------------------------------

#[test]
fn pm401_pass_audit_entries_present() {
    let body = serde_json::json!({
        "trails": [
            {"id": "t1", "timestamp": "2026-08-01T00:00:00.000Z", "action": "user.login"},
            {"id": "t2", "timestamp": "2026-08-01T00:05:00.000Z", "action": "workspace.created"}
        ]
    });
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "postman",
        "PM-4.01-audit-logs.check.yaml",
        "https://api.getpostman.com",
        server.url(),
    );

    let evidence = run_observer(def, &postman_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Effective);
    assert!(evidence[0].findings.is_empty());
}

#[test]
fn pm401_fail_no_audit_entries() {
    let body = serde_json::json!({"trails": []});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls(
        "postman",
        "PM-4.01-audit-logs.check.yaml",
        "https://api.getpostman.com",
        server.url(),
    );

    let evidence = run_observer(def, &postman_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
    assert_eq!(evidence[0].findings[0].severity_id, 4); // high
}

// ---------------------------------------------------------------------------
// Loader integration: every checks/notion/*.check.yaml and
// checks/postman/*.check.yaml file loads cleanly
// ---------------------------------------------------------------------------

#[test]
fn all_notion_checks_load_and_have_hth_references() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("checks/notion");
    let defs = ocean::check::loader::load_definitions_from_dir(&dir);

    assert!(!defs.is_empty(), "expected at least one Notion check to load");

    let ids: Vec<&str> = defs.iter().map(|d| d.id.as_str()).collect();
    assert!(ids.contains(&"NOTION-2.01"), "missing NOTION-2.01, got: {ids:?}");
    assert!(ids.contains(&"NOTION-3.01"), "missing NOTION-3.01, got: {ids:?}");

    for def in &defs {
        assert_eq!(def.source, "notion", "{}: source should be 'notion'", def.id);
        assert!(
            !def.references.hth.is_empty(),
            "{}: references.hth is mandatory for Notion checks",
            def.id
        );
        assert!(
            def.references.hth.starts_with("notion:"),
            "{}: references.hth should be 'notion:N.N', got '{}'",
            def.id,
            def.references.hth
        );
        assert!(!def.assertions.is_empty(), "{}: check has no assertions", def.id);
    }
}

#[test]
fn all_postman_checks_load_and_have_hth_references() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("checks/postman");
    let defs = ocean::check::loader::load_definitions_from_dir(&dir);

    assert!(!defs.is_empty(), "expected at least one Postman check to load");

    let ids: Vec<&str> = defs.iter().map(|d| d.id.as_str()).collect();
    assert!(ids.contains(&"PM-2.04"), "missing PM-2.04, got: {ids:?}");
    assert!(ids.contains(&"PM-3.04"), "missing PM-3.04, got: {ids:?}");
    assert!(ids.contains(&"PM-4.01"), "missing PM-4.01, got: {ids:?}");

    for def in &defs {
        assert_eq!(def.source, "postman", "{}: source should be 'postman'", def.id);
        assert!(
            !def.references.hth.is_empty(),
            "{}: references.hth is mandatory for Postman checks",
            def.id
        );
        assert!(
            def.references.hth.starts_with("postman:"),
            "{}: references.hth should be 'postman:N.N', got '{}'",
            def.id,
            def.references.hth
        );
        assert!(!def.assertions.is_empty(), "{}: check has no assertions", def.id);
    }
}
