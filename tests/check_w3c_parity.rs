// Integration test: load + execute the wave-3c checks end-to-end (mocked HTTP).
//
// Covers the three new vendors stood up in this wave: Vercel (VERCEL-1.02,
// VERCEL-1.05, VERCEL-2.03, VERCEL-3.03, VERCEL-3.04, VERCEL-8.02,
// VERCEL-9.01), JumpCloud (JC-1.01, JC-2.01, JC-4.01, JC-5.01), and
// Salesforce (SFDC-1.01, SFDC-2.01, SFDC-3.01, SFDC-5.01). Mirrors
// tests/check_w2a_parity.rs's MockHTTPServer pattern verbatim.
//
// Fixtures reflect the field shapes the HTH how-to-harden pack code parses
// for each vendor, cross-checked against the vendor API references cited in
// each check's YAML:
//   - Vercel REST API (api.vercel.com): /v2/teams/{id} returns a team object
//     with a `saml` field; /v2/teams/{id}/members returns {"members":[...]};
//     /v10/projects returns {"projects":[...]} with gitForkProtection;
//     /v9/projects/{id} returns skewProtection; the Firewall
//     /v1/security/firewall/config/active endpoint returns {"rules":[...],
//     "managedRulesets":{...}}; /v1/log-drains returns a bare top-level array.
//   - JumpCloud API (console.jumpcloud.com): /api/organizations returns a
//     bare array of org objects; /api/organizations/{id} returns
//     settings.requireAdminMFA and settings.features.directoryInsights.enabled;
//     /api/systemusers returns {"results":[...],"totalCount":N}; /api/v2/policies
//     returns a bare array.
//   - Salesforce REST API (v59.0): /services/data/v59.0/query and
//     /services/data/v59.0/tooling/query both return
//     {"totalSize":N,"records":[...]} (per Salesforce's documented SOQL query
//     response envelope). Host is templated via the sf_instance_url input,
//     matching the OP-4.01 host-templated-via-input pattern.

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

/// Load a bundled check as-is (no host rewriting) — for checks whose HTTP
/// host is templated via an input (e.g. Salesforce's `{{sf_instance_url}}`),
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
// Vercel — shared config
// ---------------------------------------------------------------------------

fn vercel_config() -> HashMap<String, String> {
    let mut cfg = HashMap::new();
    cfg.insert("VERCEL_TOKEN".to_string(), "vercel-test-token".to_string());
    cfg.insert("VERCEL_TEAM_ID".to_string(), "team_test123".to_string());
    cfg.insert("VERCEL_PROJECT_ID".to_string(), "prj_test123".to_string());
    cfg
}

fn load_vercel(filename: &str, mock_url: &str) -> ocean::check::CheckDefinition {
    load_check_with_mock_urls("vercel", filename, "https://api.vercel.com", mock_url)
}

// ---------------------------------------------------------------------------
// VERCEL-1.02 — directory sync + owner-role minimization
// ---------------------------------------------------------------------------

#[test]
fn vercel102_pass_saml_configured_and_owners_minimized() {
    let team = serde_json::json!({"saml": {"enforced": true}});
    let members = serde_json::json!({"members": [
        {"uid": "u1", "role": "MEMBER"},
        {"uid": "u2", "role": "OWNER"}
    ]});
    let server = MockHTTPServer::new(vec![(200, team.to_string()), (200, members.to_string())]);
    let def = load_vercel(
        "VERCEL-1.02-directory-sync-owner-minimization.check.yaml",
        server.url(),
    );

    let evidence = run_observer(def, &vercel_config());
    assert_eq!(evidence.len(), 2);
    for ev in &evidence {
        assert_eq!(ev.control_id, "VERCEL-1.02");
        assert_eq!(
            ev.status_id,
            StatusId::Effective,
            "expected Effective, got: {}",
            ev.status
        );
    }
}

#[test]
fn vercel102_fail_no_saml_and_too_many_owners() {
    let team = serde_json::json!({"saml": null});
    let members = serde_json::json!({"members": [
        {"uid": "u1", "role": "OWNER"},
        {"uid": "u2", "role": "OWNER"},
        {"uid": "u3", "role": "OWNER"},
        {"uid": "u4", "role": "OWNER"}
    ]});
    let server = MockHTTPServer::new(vec![(200, team.to_string()), (200, members.to_string())]);
    let def = load_vercel(
        "VERCEL-1.02-directory-sync-owner-minimization.check.yaml",
        server.url(),
    );

    let evidence = run_observer(def, &vercel_config());
    assert_eq!(evidence.len(), 2);
    assert_eq!(
        evidence[0].status_id,
        StatusId::Ineffective,
        "saml assertion should fail"
    );
    assert_eq!(evidence[0].findings[0].severity_id, 4); // high
    assert_eq!(
        evidence[1].status_id,
        StatusId::Ineffective,
        "owner-minimization assertion should fail"
    );
    assert_eq!(evidence[1].findings[0].severity_id, 3); // medium
}

// ---------------------------------------------------------------------------
// VERCEL-1.05 — Git fork protection audit
// ---------------------------------------------------------------------------

#[test]
fn vercel105_pass_all_projects_fork_protected() {
    let projects = serde_json::json!({"projects": [
        {"id": "p1", "name": "app-one", "gitForkProtection": true},
        {"id": "p2", "name": "app-two", "gitForkProtection": true}
    ]});
    let server = MockHTTPServer::new(vec![(200, projects.to_string())]);
    let def = load_vercel("VERCEL-1.05-fork-protection-audit.check.yaml", server.url());

    let evidence = run_observer(def, &vercel_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].control_id, "VERCEL-1.05");
    assert_eq!(evidence[0].status_id, StatusId::Effective);
    assert!(evidence[0].findings.is_empty());
}

#[test]
fn vercel105_fail_one_project_missing_fork_protection() {
    let projects = serde_json::json!({"projects": [
        {"id": "p1", "name": "app-one", "gitForkProtection": true},
        {"id": "p2", "name": "app-two", "gitForkProtection": false}
    ]});
    let server = MockHTTPServer::new(vec![(200, projects.to_string())]);
    let def = load_vercel("VERCEL-1.05-fork-protection-audit.check.yaml", server.url());

    let evidence = run_observer(def, &vercel_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
    assert_eq!(evidence[0].findings[0].severity_id, 4); // high
}

// ---------------------------------------------------------------------------
// VERCEL-2.03 — skew protection
// ---------------------------------------------------------------------------

#[test]
fn vercel203_pass_skew_protection_configured() {
    let project = serde_json::json!({"name": "app-one", "skewProtection": {"enabled": true}});
    let server = MockHTTPServer::new(vec![(200, project.to_string())]);
    let def = load_vercel(
        "VERCEL-2.03-rolling-releases-skew-protection.check.yaml",
        server.url(),
    );

    let evidence = run_observer(def, &vercel_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn vercel203_fail_skew_protection_absent() {
    let project = serde_json::json!({"name": "app-one"});
    let server = MockHTTPServer::new(vec![(200, project.to_string())]);
    let def = load_vercel(
        "VERCEL-2.03-rolling-releases-skew-protection.check.yaml",
        server.url(),
    );

    let evidence = run_observer(def, &vercel_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
    assert_eq!(evidence[0].findings[0].severity_id, 3); // medium
}

// ---------------------------------------------------------------------------
// VERCEL-3.03 — firewall persistent actions
// ---------------------------------------------------------------------------

#[test]
fn vercel303_pass_persistent_action_rule_present() {
    let config = serde_json::json!({"rules": [
        {"name": "hth-persistent-block-scanners", "action": {"mitigate": {"action": "deny", "actionDuration": "24h", "persistentAction": true}}}
    ]});
    let server = MockHTTPServer::new(vec![(200, config.to_string())]);
    let def = load_vercel(
        "VERCEL-3.03-firewall-persistent-actions.check.yaml",
        server.url(),
    );

    let evidence = run_observer(def, &vercel_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn vercel303_fail_no_persistent_action_rule() {
    let config = serde_json::json!({"rules": [
        {"name": "log-only", "action": {"mitigate": {"action": "log", "persistentAction": false}}}
    ]});
    let server = MockHTTPServer::new(vec![(200, config.to_string())]);
    let def = load_vercel(
        "VERCEL-3.03-firewall-persistent-actions.check.yaml",
        server.url(),
    );

    let evidence = run_observer(def, &vercel_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
    assert_eq!(evidence[0].findings[0].severity_id, 3); // medium
}

// ---------------------------------------------------------------------------
// VERCEL-3.04 — AI Bots managed ruleset
// ---------------------------------------------------------------------------

#[test]
fn vercel304_pass_ai_bots_active() {
    let config =
        serde_json::json!({"managedRulesets": {"ai_bots": {"active": true, "action": "log"}}});
    let server = MockHTTPServer::new(vec![(200, config.to_string())]);
    let def = load_vercel(
        "VERCEL-3.04-ai-bots-managed-ruleset.check.yaml",
        server.url(),
    );

    let evidence = run_observer(def, &vercel_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn vercel304_fail_ai_bots_ruleset_absent() {
    let config = serde_json::json!({"managedRulesets": {"bot_protection": {"active": true, "action": "challenge"}}});
    let server = MockHTTPServer::new(vec![(200, config.to_string())]);
    let def = load_vercel(
        "VERCEL-3.04-ai-bots-managed-ruleset.check.yaml",
        server.url(),
    );

    let evidence = run_observer(def, &vercel_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
    assert_eq!(evidence[0].findings[0].severity_id, 3); // medium
}

// ---------------------------------------------------------------------------
// VERCEL-8.02 — SIEM log drain
// ---------------------------------------------------------------------------

#[test]
fn vercel802_pass_log_drain_configured() {
    let drains = serde_json::json!([
        {"id": "ld1", "name": "siem-export", "endpoint": "https://siem.example.com/ingest"}
    ]);
    let server = MockHTTPServer::new(vec![(200, drains.to_string())]);
    let def = load_vercel(
        "VERCEL-8.02-audit-log-drain-siem-streaming.check.yaml",
        server.url(),
    );

    let evidence = run_observer(def, &vercel_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn vercel802_fail_no_log_drains() {
    let drains = serde_json::json!([]);
    let server = MockHTTPServer::new(vec![(200, drains.to_string())]);
    let def = load_vercel(
        "VERCEL-8.02-audit-log-drain-siem-streaming.check.yaml",
        server.url(),
    );

    let evidence = run_observer(def, &vercel_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
    assert_eq!(evidence[0].findings[0].severity_id, 4); // high
}

// ---------------------------------------------------------------------------
// VERCEL-9.01 — deny x-middleware-subrequest (CVE-2025-29927 defense)
// ---------------------------------------------------------------------------

#[test]
fn vercel901_pass_middleware_subrequest_denied() {
    let config = serde_json::json!({"rules": [
        {
            "name": "hth-cve-2025-29927-deny-middleware-subrequest",
            "conditionGroup": [{"conditions": [{"type": "header", "key": "x-middleware-subrequest", "op": "ex"}]}],
            "action": {"mitigate": {"action": "deny", "actionDuration": "permanent", "persistentAction": true}}
        }
    ]});
    let server = MockHTTPServer::new(vec![(200, config.to_string())]);
    let def = load_vercel(
        "VERCEL-9.01-nextjs-middleware-header-strip.check.yaml",
        server.url(),
    );

    let evidence = run_observer(def, &vercel_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn vercel901_fail_no_matching_deny_rule() {
    let config = serde_json::json!({"rules": [
        {
            "name": "hth-log-nextjs-internal-headers",
            "conditionGroup": [{"conditions": [{"type": "header", "key": "x-nextjs-data", "op": "ex"}]}],
            "action": {"mitigate": {"action": "log"}}
        }
    ]});
    let server = MockHTTPServer::new(vec![(200, config.to_string())]);
    let def = load_vercel(
        "VERCEL-9.01-nextjs-middleware-header-strip.check.yaml",
        server.url(),
    );

    let evidence = run_observer(def, &vercel_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
    assert_eq!(evidence[0].findings[0].severity_id, 4); // high
}

// ---------------------------------------------------------------------------
// JumpCloud — shared config
// ---------------------------------------------------------------------------

fn jumpcloud_config() -> HashMap<String, String> {
    let mut cfg = HashMap::new();
    cfg.insert(
        "JUMPCLOUD_API_KEY".to_string(),
        "jc-test-api-key".to_string(),
    );
    cfg
}

fn load_jumpcloud(filename: &str, mock_url: &str) -> ocean::check::CheckDefinition {
    load_check_with_mock_urls(
        "jumpcloud",
        filename,
        "https://console.jumpcloud.com",
        mock_url,
    )
}

// ---------------------------------------------------------------------------
// JC-1.01 — admin portal MFA required
// ---------------------------------------------------------------------------

#[test]
fn jc101_pass_admin_mfa_required() {
    let orgs = serde_json::json!([{"id": "org123", "name": "Test Org"}]);
    let org = serde_json::json!({"id": "org123", "settings": {"requireAdminMFA": true}});
    let server = MockHTTPServer::new(vec![(200, orgs.to_string()), (200, org.to_string())]);
    let def = load_jumpcloud("JC-1.01-admin-portal-mfa-required.check.yaml", server.url());

    let evidence = run_observer(def, &jumpcloud_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].control_id, "JC-1.01");
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn jc101_fail_admin_mfa_not_required() {
    let orgs = serde_json::json!([{"id": "org123", "name": "Test Org"}]);
    let org = serde_json::json!({"id": "org123", "settings": {"requireAdminMFA": false}});
    let server = MockHTTPServer::new(vec![(200, orgs.to_string()), (200, org.to_string())]);
    let def = load_jumpcloud("JC-1.01-admin-portal-mfa-required.check.yaml", server.url());

    let evidence = run_observer(def, &jumpcloud_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
    assert_eq!(evidence[0].findings[0].severity_id, 5); // critical
}

// ---------------------------------------------------------------------------
// JC-2.01 — user portal MFA enrollment audit
// ---------------------------------------------------------------------------

#[test]
fn jc201_pass_all_users_have_mfa() {
    let users = serde_json::json!({
        "totalCount": 2,
        "results": [
            {"email": "alice@example.com", "totp_enabled": true, "enable_user_portal_multifactor": false},
            {"email": "bob@example.com", "totp_enabled": false, "enable_user_portal_multifactor": true}
        ]
    });
    let server = MockHTTPServer::new(vec![(200, users.to_string())]);
    let def = load_jumpcloud(
        "JC-2.01-user-portal-mfa-enrollment-audit.check.yaml",
        server.url(),
    );

    let evidence = run_observer(def, &jumpcloud_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn jc201_fail_user_without_any_mfa() {
    let users = serde_json::json!({
        "totalCount": 1,
        "results": [
            {"email": "carol@example.com", "totp_enabled": false, "enable_user_portal_multifactor": false}
        ]
    });
    let server = MockHTTPServer::new(vec![(200, users.to_string())]);
    let def = load_jumpcloud(
        "JC-2.01-user-portal-mfa-enrollment-audit.check.yaml",
        server.url(),
    );

    let evidence = run_observer(def, &jumpcloud_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
    assert_eq!(evidence[0].findings[0].severity_id, 4); // high
}

// ---------------------------------------------------------------------------
// JC-4.01 — device policy inventory (audit-style, reachability assertion)
// ---------------------------------------------------------------------------

#[test]
fn jc401_pass_policies_retrieved() {
    let policies = serde_json::json!([
        {"id": "pol1", "name": "Disk Encryption"},
        {"id": "pol2", "name": "Screen Lock"}
    ]);
    let server = MockHTTPServer::new(vec![(200, policies.to_string())]);
    let def = load_jumpcloud("JC-4.01-device-policy-inventory.check.yaml", server.url());

    let evidence = run_observer(def, &jumpcloud_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn jc401_fail_policies_endpoint_unreachable() {
    let server = MockHTTPServer::new(vec![(500, "{}".to_string())]);
    let def = load_jumpcloud("JC-4.01-device-policy-inventory.check.yaml", server.url());

    let evidence = run_observer(def, &jumpcloud_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
    assert_eq!(evidence[0].findings[0].severity_id, 3); // medium
}

// ---------------------------------------------------------------------------
// JC-5.01 — Directory Insights enabled
// ---------------------------------------------------------------------------

#[test]
fn jc501_pass_directory_insights_enabled() {
    let orgs = serde_json::json!([{"id": "org123", "name": "Test Org"}]);
    let org = serde_json::json!({
        "id": "org123",
        "settings": {"features": {"directoryInsights": {"enabled": true}}}
    });
    let server = MockHTTPServer::new(vec![(200, orgs.to_string()), (200, org.to_string())]);
    let def = load_jumpcloud(
        "JC-5.01-directory-insights-enabled.check.yaml",
        server.url(),
    );

    let evidence = run_observer(def, &jumpcloud_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn jc501_fail_directory_insights_disabled() {
    let orgs = serde_json::json!([{"id": "org123", "name": "Test Org"}]);
    let org = serde_json::json!({
        "id": "org123",
        "settings": {"features": {"directoryInsights": {"enabled": false}}}
    });
    let server = MockHTTPServer::new(vec![(200, orgs.to_string()), (200, org.to_string())]);
    let def = load_jumpcloud(
        "JC-5.01-directory-insights-enabled.check.yaml",
        server.url(),
    );

    let evidence = run_observer(def, &jumpcloud_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
    assert_eq!(evidence[0].findings[0].severity_id, 4); // high
}

// ---------------------------------------------------------------------------
// Salesforce — shared config (host templated via sf_instance_url input)
// ---------------------------------------------------------------------------

fn salesforce_config(mock_url: &str) -> HashMap<String, String> {
    let mut cfg = HashMap::new();
    cfg.insert(
        "SF_ACCESS_TOKEN".to_string(),
        "sf-test-access-token".to_string(),
    );
    cfg.insert("SF_INSTANCE_URL".to_string(), mock_url.to_string());
    cfg
}

// ---------------------------------------------------------------------------
// SFDC-1.01 — MFA prompt disabled audit
// ---------------------------------------------------------------------------

#[test]
fn sfdc101_pass_no_users_with_mfa_disabled() {
    let body = serde_json::json!({
        "totalSize": 2,
        "records": [
            {"Username": "alice", "UserPreferencesDisableMFAPrompt": false},
            {"Username": "bob", "UserPreferencesDisableMFAPrompt": false}
        ]
    });
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check(
        "salesforce",
        "SFDC-1.01-mfa-prompt-disabled-audit.check.yaml",
    );

    let evidence = run_observer(def, &salesforce_config(server.url()));
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].control_id, "SFDC-1.01");
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn sfdc101_fail_user_with_mfa_prompt_disabled() {
    let body = serde_json::json!({
        "totalSize": 1,
        "records": [{"Username": "carol", "UserPreferencesDisableMFAPrompt": true}]
    });
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check(
        "salesforce",
        "SFDC-1.01-mfa-prompt-disabled-audit.check.yaml",
    );

    let evidence = run_observer(def, &salesforce_config(server.url()));
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
    assert_eq!(evidence[0].findings[0].severity_id, 4); // high
}

// ---------------------------------------------------------------------------
// SFDC-2.01 — Login IP Ranges configured
// ---------------------------------------------------------------------------

#[test]
fn sfdc201_pass_login_ip_ranges_configured() {
    let body = serde_json::json!({
        "totalSize": 1,
        "records": [{"StartAddress": "203.0.113.0", "EndAddress": "203.0.113.255", "Description": "HQ"}]
    });
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check(
        "salesforce",
        "SFDC-2.01-login-ip-ranges-configured.check.yaml",
    );

    let evidence = run_observer(def, &salesforce_config(server.url()));
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn sfdc201_fail_no_login_ip_ranges() {
    let body = serde_json::json!({"totalSize": 0, "records": []});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check(
        "salesforce",
        "SFDC-2.01-login-ip-ranges-configured.check.yaml",
    );

    let evidence = run_observer(def, &salesforce_config(server.url()));
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
    assert_eq!(evidence[0].findings[0].severity_id, 3); // medium
}

// ---------------------------------------------------------------------------
// SFDC-3.01 — Connected App admin pre-authorization + stale OAuth tokens
// ---------------------------------------------------------------------------

#[test]
fn sfdc301_pass_apps_preauthorized_and_no_stale_tokens() {
    let apps = serde_json::json!({
        "totalSize": 1,
        "records": [{"Name": "Internal Tool", "OptionsAllowAdminApprovedUsersOnly": true}]
    });
    let stale = serde_json::json!({"totalSize": 0, "records": []});
    let server = MockHTTPServer::new(vec![(200, apps.to_string()), (200, stale.to_string())]);
    let def = load_check(
        "salesforce",
        "SFDC-3.01-connected-app-scopes-audit.check.yaml",
    );

    let evidence = run_observer(def, &salesforce_config(server.url()));
    assert_eq!(evidence.len(), 2);
    for ev in &evidence {
        assert_eq!(ev.control_id, "SFDC-3.01");
        assert_eq!(
            ev.status_id,
            StatusId::Effective,
            "expected Effective, got: {}",
            ev.status
        );
    }
}

#[test]
fn sfdc301_fail_open_app_and_stale_token() {
    let apps = serde_json::json!({
        "totalSize": 1,
        "records": [{"Name": "Shadow IT App", "OptionsAllowAdminApprovedUsersOnly": false}]
    });
    let stale = serde_json::json!({
        "totalSize": 1,
        "records": [{"AppName": "Old Integration", "LastUsedDate": "2025-01-01T00:00:00.000+0000"}]
    });
    let server = MockHTTPServer::new(vec![(200, apps.to_string()), (200, stale.to_string())]);
    let def = load_check(
        "salesforce",
        "SFDC-3.01-connected-app-scopes-audit.check.yaml",
    );

    let evidence = run_observer(def, &salesforce_config(server.url()));
    assert_eq!(evidence.len(), 2);
    assert_eq!(
        evidence[0].status_id,
        StatusId::Ineffective,
        "admin pre-auth assertion should fail"
    );
    assert_eq!(evidence[0].findings[0].severity_id, 4); // high
    assert_eq!(
        evidence[1].status_id,
        StatusId::Ineffective,
        "stale-token assertion should fail"
    );
    assert_eq!(evidence[1].findings[0].severity_id, 3); // medium
}

// ---------------------------------------------------------------------------
// SFDC-5.01 — Event Monitoring active
// ---------------------------------------------------------------------------

#[test]
fn sfdc501_pass_event_monitoring_active() {
    let body = serde_json::json!({
        "totalSize": 3,
        "records": [{"EventType": "Login", "LogDate": "2026-01-01"}]
    });
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check("salesforce", "SFDC-5.01-event-monitoring-active.check.yaml");

    let evidence = run_observer(def, &salesforce_config(server.url()));
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn sfdc501_fail_no_event_log_files() {
    let body = serde_json::json!({"totalSize": 0, "records": []});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check("salesforce", "SFDC-5.01-event-monitoring-active.check.yaml");

    let evidence = run_observer(def, &salesforce_config(server.url()));
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
    assert_eq!(evidence[0].findings[0].severity_id, 4); // high
}

// ---------------------------------------------------------------------------
// Loader integration: every checks/{vercel,jumpcloud,salesforce}/*.check.yaml
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
fn all_vercel_checks_load_and_have_hth_references() {
    assert_vendor_dir_loads(
        "vercel",
        "vercel",
        "vercel:",
        &[
            "VERCEL-1.02",
            "VERCEL-1.05",
            "VERCEL-2.03",
            "VERCEL-3.03",
            "VERCEL-3.04",
            "VERCEL-8.02",
            "VERCEL-9.01",
        ],
    );
}

#[test]
fn all_jumpcloud_checks_load_and_have_hth_references() {
    assert_vendor_dir_loads(
        "jumpcloud",
        "jumpcloud",
        "jumpcloud:",
        &["JC-1.01", "JC-2.01", "JC-4.01", "JC-5.01"],
    );
}

#[test]
fn all_salesforce_checks_load_and_have_hth_references() {
    assert_vendor_dir_loads(
        "salesforce",
        "salesforce",
        "salesforce:",
        &["SFDC-1.01", "SFDC-2.01", "SFDC-3.01", "SFDC-5.01"],
    );
}
