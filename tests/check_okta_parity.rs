// Integration tests: Okta (HTH parity) checks under checks/okta/.
//
// Mirrors the MockHTTPServer TDD pattern from tests/check_pipeline.rs. Six
// representative newly-authored checks each get a pass case and a fail case
// built from Okta's documented API response shapes (developer.okta.com). A
// load-all test guards the whole checks/okta/ directory for parse errors,
// duplicate IDs, and JSON Schema validity.

use std::collections::HashMap;
use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use ocean::check::{load_check_file, register_check, CheckDefinition};
use ocean::evidence::StatusId;
use ocean::module::{Executor, Registry};

// ---------------------------------------------------------------------------
// Mock HTTP server (copied from tests/check_pipeline.rs — kept local so this
// file has no cross-test-file dependency).
// ---------------------------------------------------------------------------

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

fn okta_check_path(filename: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("checks/okta")
        .join(filename)
}

/// Load a check file and rewrite the `{{okta_domain}}`-templated host to the
/// mock server base URL so the interpreter's HTTP calls land on the mock.
fn load_check_with_mock_urls(filename: &str, mock_base: &str) -> CheckDefinition {
    let path = okta_check_path(filename);
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
    let rewritten = content.replace("https://{{okta_domain}}", mock_base);
    serde_yaml::from_str(&rewritten)
        .unwrap_or_else(|e| panic!("parse rewritten {}: {}", filename, e))
}

fn okta_test_config() -> HashMap<String, String> {
    let mut cfg = HashMap::new();
    cfg.insert("OKTA_API_TOKEN".to_string(), "test-ssws-token".to_string());
    cfg.insert("OKTA_DOMAIN".to_string(), "test.okta.com".to_string());
    cfg
}

fn run_observer(def: CheckDefinition, id: &str) -> Vec<ocean::evidence::Evidence> {
    let registry = Arc::new(Registry::new());
    register_check(&registry, def);
    let executor = Executor::new(Arc::clone(&registry));
    executor
        .execute_observer(id, &okta_test_config())
        .unwrap_or_else(|e| panic!("execute observer {}: {}", id, e))
}

// ===========================================================================
// OKTA-1.03 — Hardware-Bound Session Tokens (Okta Verify / FastPass)
// ===========================================================================

fn authenticator(key: &str, status: &str) -> serde_json::Value {
    serde_json::json!({
        "type": "app",
        "id": "aut1",
        "key": key,
        "status": status,
        "name": key,
        "settings": {}
    })
}

#[test]
fn okta103_pass_okta_verify_active() {
    let body = serde_json::json!([
        authenticator("okta_verify", "ACTIVE"),
        authenticator("security_question", "INACTIVE"),
    ]);
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls("OKTA-1.03-hardware-bound-tokens.check.yaml", server.url());
    let evidence = run_observer(def, "OKTA-1.03");

    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Effective, "status: {}", evidence[0].status);
    assert!(evidence[0].findings.is_empty());
}

#[test]
fn okta103_fail_okta_verify_not_active() {
    let body = serde_json::json!([
        authenticator("okta_verify", "INACTIVE"),
    ]);
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls("OKTA-1.03-hardware-bound-tokens.check.yaml", server.url());
    let evidence = run_observer(def, "OKTA-1.03");

    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective, "status: {}", evidence[0].status);
    assert!(!evidence[0].findings.is_empty());
}

// ===========================================================================
// OKTA-1.90 — Default Authentication Policy Reliance
// ===========================================================================

fn access_policy(name: &str, system: bool) -> serde_json::Value {
    serde_json::json!({
        "id": format!("pol-{name}"),
        "name": name,
        "system": system,
        "type": "ACCESS_POLICY"
    })
}

#[test]
fn okta190_pass_custom_policy_exists() {
    let body = serde_json::json!([
        access_policy("Default Policy", true),
        access_policy("MFA Required - All Applications", false),
    ]);
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls("OKTA-1.90-default-auth-policy.check.yaml", server.url());
    let evidence = run_observer(def, "OKTA-1.90");

    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Effective, "status: {}", evidence[0].status);
    assert!(evidence[0].findings.is_empty());
}

#[test]
fn okta190_fail_only_default_policy_exists() {
    let body = serde_json::json!([
        access_policy("Default Policy", true),
    ]);
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls("OKTA-1.90-default-auth-policy.check.yaml", server.url());
    let evidence = run_observer(def, "OKTA-1.90");

    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective, "status: {}", evidence[0].status);
    assert_eq!(evidence[0].findings[0].severity_id, 5); // critical
}

// ===========================================================================
// OKTA-1.11 — End-User Security Notifications
// ===========================================================================

fn org_settings(all_notifications_enabled: bool) -> serde_json::Value {
    serde_json::json!({
        "id": "org1",
        "endUserNotifications": {
            "newSignOnNotification": {"enabled": all_notifications_enabled},
            "authenticatorEnrolledNotification": {"enabled": all_notifications_enabled},
            "authenticatorResetNotification": {"enabled": all_notifications_enabled},
            "passwordChangedNotification": {"enabled": all_notifications_enabled},
            "factorResetNotification": {"enabled": all_notifications_enabled}
        }
    })
}

#[test]
fn okta111_pass_all_notifications_and_sar_enabled() {
    let settings = org_settings(true);
    let sar = serde_json::json!({"enabled": true});
    let server = MockHTTPServer::new(vec![
        (200, settings.to_string()),
        (200, sar.to_string()),
    ]);
    let def = load_check_with_mock_urls("OKTA-1.11-security-notifications.check.yaml", server.url());
    let evidence = run_observer(def, "OKTA-1.11");

    assert_eq!(evidence.len(), 2, "expected 2 evidence items (one per assertion)");
    for ev in &evidence {
        assert_eq!(ev.status_id, StatusId::Effective, "status: {}", ev.status);
        assert!(ev.findings.is_empty());
    }
}

#[test]
fn okta111_fail_notifications_disabled_and_sar_disabled() {
    let settings = org_settings(false);
    let sar = serde_json::json!({"enabled": false});
    let server = MockHTTPServer::new(vec![
        (200, settings.to_string()),
        (200, sar.to_string()),
    ]);
    let def = load_check_with_mock_urls("OKTA-1.11-security-notifications.check.yaml", server.url());
    let evidence = run_observer(def, "OKTA-1.11");

    assert_eq!(evidence.len(), 2);
    for ev in &evidence {
        assert_eq!(ev.status_id, StatusId::Ineffective, "status: {}", ev.status);
        assert!(!ev.findings.is_empty());
    }
}

// ===========================================================================
// OKTA-2.03 — Anonymizer and Tor Blocking (DefaultEnhancedDynamicZone)
// ===========================================================================

fn dynamic_zone(status: &str, usage: &str) -> serde_json::Value {
    serde_json::json!({
        "id": "nzo_default",
        "name": "DefaultEnhancedDynamicZone",
        "type": "DYNAMIC_V2",
        "status": status,
        "usage": usage
    })
}

#[test]
fn okta203_pass_zone_active_blocklist() {
    let body = serde_json::json!([dynamic_zone("ACTIVE", "BLOCKLIST")]);
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls("OKTA-2.03-anonymizer-blocking.check.yaml", server.url());
    let evidence = run_observer(def, "OKTA-2.03");

    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Effective, "status: {}", evidence[0].status);
}

#[test]
fn okta203_fail_zone_inactive() {
    let body = serde_json::json!([dynamic_zone("INACTIVE", "BLOCKLIST")]);
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls("OKTA-2.03-anonymizer-blocking.check.yaml", server.url());
    let evidence = run_observer(def, "OKTA-2.03");

    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective, "status: {}", evidence[0].status);
}

// ===========================================================================
// OKTA-4.02 — Session Persistence Disabled
// ===========================================================================

fn sign_on_policy(system: bool, use_persistent_cookie: bool) -> serde_json::Value {
    serde_json::json!({
        "id": "pol-sso",
        "name": "Custom Sign-On Policy",
        "system": system,
        "settings": {
            "oie": {
                "session": {
                    "usePersistentCookie": use_persistent_cookie
                }
            }
        }
    })
}

#[test]
fn okta402_pass_no_persistent_custom_sessions() {
    let body = serde_json::json!([
        sign_on_policy(true, false),
        sign_on_policy(false, false),
    ]);
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls("OKTA-4.02-session-persistence.check.yaml", server.url());
    let evidence = run_observer(def, "OKTA-4.02");

    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Effective, "status: {}", evidence[0].status);
}

#[test]
fn okta402_fail_custom_policy_allows_persistent_session() {
    let body = serde_json::json!([
        sign_on_policy(false, true),
    ]);
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls("OKTA-4.02-session-persistence.check.yaml", server.url());
    let evidence = run_observer(def, "OKTA-4.02");

    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective, "status: {}", evidence[0].status);
}

// ===========================================================================
// OKTA-4.03 — Admin Session ASN/IP Binding
// ===========================================================================

fn org_settings_binding(asn: &str, ip: &str) -> serde_json::Value {
    serde_json::json!({
        "id": "org1",
        "adminSessionASNBinding": asn,
        "adminSessionIPBinding": ip
    })
}

#[test]
fn okta403_pass_both_bindings_enabled() {
    let body = org_settings_binding("ENABLED", "ENABLED");
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls("OKTA-4.03-admin-session-security.check.yaml", server.url());
    let evidence = run_observer(def, "OKTA-4.03");

    assert_eq!(evidence.len(), 2, "expected 2 evidence items (one per assertion)");
    for ev in &evidence {
        assert_eq!(ev.status_id, StatusId::Effective, "status: {}", ev.status);
    }
}

#[test]
fn okta403_fail_bindings_disabled() {
    let body = org_settings_binding("DISABLED", "DISABLED");
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check_with_mock_urls("OKTA-4.03-admin-session-security.check.yaml", server.url());
    let evidence = run_observer(def, "OKTA-4.03");

    assert_eq!(evidence.len(), 2);
    for ev in &evidence {
        assert_eq!(ev.status_id, StatusId::Ineffective, "status: {}", ev.status);
        assert!(!ev.findings.is_empty());
    }
}

// ===========================================================================
// Load-all test: every checks/okta/*.check.yaml must parse, have a unique
// id, and validate against the JSON Schema.
// ===========================================================================

#[test]
fn all_okta_checks_load_and_have_unique_ids() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("checks/okta");
    let mut ids = std::collections::HashSet::new();
    let mut count = 0;
    for entry in std::fs::read_dir(&dir).expect("read checks/okta dir") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("yaml") {
            continue;
        }
        let def = load_check_file(&path)
            .unwrap_or_else(|e| panic!("load {}: {}", path.display(), e));
        assert!(!def.id.is_empty(), "{} has empty id", path.display());
        assert!(
            ids.insert(def.id.clone()),
            "duplicate check id '{}' found in {}",
            def.id,
            path.display()
        );
        assert!(
            !def.references.hth.is_empty(),
            "{} is missing references.hth",
            path.display()
        );
        count += 1;
    }
    assert!(count >= 28, "expected at least 28 okta checks (15 original + 13 new), found {count}");
}
