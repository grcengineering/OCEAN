// Integration test: load + execute the wave-3a checks end-to-end (mocked HTTP).
//
// Covers the three new vendors stood up in this wave: Cloudflare (CF-1.01,
// CF-1.03, CF-1.04, CF-2.02, CF-2.03, CF-3.01..3.04, CF-4.01..4.03, CF-5.01,
// CF-6.01), Auth0 (AUTH0-1.01..1.04, AUTH0-2.01, AUTH0-2.02, AUTH0-3.01,
// AUTH0-4.02, AUTH0-5.01), and LaunchDarkly (LD-1.01, LD-1.02, LD-2.01,
// LD-2.02, LD-3.01, LD-3.02, LD-4.01). Mirrors tests/check_w2a_parity.rs's
// MockHTTPServer pattern (copied verbatim below).
//
// Fixtures reflect the field shapes the HTH how-to-harden pack code parses
// for each vendor, cross-checked against the vendor API references cited in
// each check's YAML:
//   - Cloudflare API v4 (api.cloudflare.com/client/v4): every endpoint
//     wraps its payload as {"success": bool, "result": ...} per
//     packs/cloudflare/api/common.sh's cf_get/cf_post helpers and every
//     hth-cloudflare-*.sh script's `jq '.result...'` usage.
//   - Auth0 Management API v2 (https://{domain}/api/v2): attack-protection
//     and tenant-settings endpoints return a bare JSON object
//     ({"enabled": ...}); connections, clients, guardian/policies, and
//     log-streams return a bare JSON array — per packs/auth0/api/*.sh's
//     `jq -r '.enabled'` (object) vs `jq -c '.[]'` / `jq 'length'` (array)
//     usage. Auth0 checks template the full Management API base URL via
//     the auth0_api_base input (like 1Password's op_events_base) rather
//     than a hardcoded https://{{auth0_domain}} scheme, since the
//     interpreter cannot template a URL's scheme+host independently and a
//     hardcoded https:// prefix would be unmockable over plain HTTP.
//   - LaunchDarkly API v2 (app.launchdarkly.com/api/v2): list endpoints
//     wrap results as {"items": [...], "totalCount": N} per
//     packs/launchdarkly/api/common.sh's ld_get helper and every
//     hth-launchdarkly-*.sh script's `jq '.items[...]'` usage. The
//     Authorization header carries the raw API key with no "Bearer"
//     prefix, per common.sh's ld_get definition.

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
/// host is templated via an input (e.g. Auth0's `{{auth0_api_base}}`),
/// where the mock URL is supplied through config instead.
fn load_check(vendor: &str, filename: &str) -> ocean::check::CheckDefinition {
    let content = std::fs::read_to_string(check_path(vendor, filename))
        .unwrap_or_else(|e| panic!("read {filename}: {e}"));
    serde_yaml::from_str(&content).unwrap_or_else(|e| panic!("parse {filename}: {e}"))
}

/// Load a bundled check, rewriting its real API host to the mock server —
/// for checks with a hardcoded host in the `url` field (Cloudflare and
/// LaunchDarkly, both single-tenant-host APIs).
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
// Cloudflare shared config
// ---------------------------------------------------------------------------

fn cf_config() -> HashMap<String, String> {
    let mut cfg = HashMap::new();
    cfg.insert("CF_API_TOKEN".to_string(), "cf-test-token".to_string());
    cfg.insert("CF_ACCOUNT_ID".to_string(), "test-account-id".to_string());
    cfg
}

fn cf_check(server: &MockHTTPServer, filename: &str) -> ocean::check::CheckDefinition {
    load_check_with_mock_urls("cloudflare", filename, "https://api.cloudflare.com", server.url())
}

// ---------------------------------------------------------------------------
// CF-1.01 — Identity provider configured
// ---------------------------------------------------------------------------

#[test]
fn cf101_pass_identity_provider_configured() {
    let body = serde_json::json!({"success": true, "result": [{"id": "idp1", "name": "Corp IdP", "type": "oidc"}]});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = cf_check(&server, "CF-1.01-identity-provider-configured.check.yaml");

    let evidence = run_observer(def, &cf_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].control_id, "CF-1.01");
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn cf101_fail_no_identity_providers() {
    let body = serde_json::json!({"success": true, "result": []});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = cf_check(&server, "CF-1.01-identity-provider-configured.check.yaml");

    let evidence = run_observer(def, &cf_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
    assert_eq!(evidence[0].findings[0].severity_id, 4); // high
}

// ---------------------------------------------------------------------------
// CF-1.03 — Device enrollment policy audit (reachability-based)
// ---------------------------------------------------------------------------

#[test]
fn cf103_pass_device_policy_reachable() {
    let body = serde_json::json!({"success": true, "result": {"allow_mode_switch": false}});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = cf_check(&server, "CF-1.03-device-enrollment-policy-audit.check.yaml");

    let evidence = run_observer(def, &cf_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn cf103_fail_device_policy_unreachable() {
    let server = MockHTTPServer::new(vec![(500, "{}".to_string())]);
    let def = cf_check(&server, "CF-1.03-device-enrollment-policy-audit.check.yaml");

    let evidence = run_observer(def, &cf_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
}

// ---------------------------------------------------------------------------
// CF-1.04 — Super Administrator count
// ---------------------------------------------------------------------------

#[test]
fn cf104_pass_super_admin_count_within_limit() {
    let body = serde_json::json!({"success": true, "result": [
        {"user": {"email": "a@x.com"}, "roles": [{"name": "Super Administrator"}]},
        {"user": {"email": "b@x.com"}, "roles": [{"name": "Administrator Read Only"}]}
    ]});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = cf_check(&server, "CF-1.04-super-admin-count.check.yaml");

    let evidence = run_observer(def, &cf_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn cf104_fail_super_admin_count_exceeds_limit() {
    let members: Vec<_> = (0..4)
        .map(|i| serde_json::json!({"user": {"email": format!("a{i}@x.com")}, "roles": [{"name": "Super Administrator"}]}))
        .collect();
    let body = serde_json::json!({"success": true, "result": members});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = cf_check(&server, "CF-1.04-super-admin-count.check.yaml");

    let evidence = run_observer(def, &cf_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
    assert_eq!(evidence[0].findings[0].severity_id, 3); // medium
}

// ---------------------------------------------------------------------------
// CF-2.02 — WARP device posture rule exists
// ---------------------------------------------------------------------------

#[test]
fn cf202_pass_warp_posture_rule_exists() {
    let body = serde_json::json!({"success": true, "result": [{"id": "r1", "name": "WARP Required", "type": "warp"}]});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = cf_check(&server, "CF-2.02-warp-device-posture-rule.check.yaml");

    let evidence = run_observer(def, &cf_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn cf202_fail_no_warp_posture_rule() {
    let body = serde_json::json!({"success": true, "result": [{"id": "r1", "name": "Disk Check", "type": "disk_encryption"}]});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = cf_check(&server, "CF-2.02-warp-device-posture-rule.check.yaml");

    let evidence = run_observer(def, &cf_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
}

// ---------------------------------------------------------------------------
// CF-2.03 — Recommended device posture checks configured (3 assertions)
// ---------------------------------------------------------------------------

#[test]
fn cf203_pass_all_posture_checks_configured() {
    let body = serde_json::json!({"success": true, "result": [
        {"id": "r1", "type": "disk_encryption"},
        {"id": "r2", "type": "firewall"},
        {"id": "r3", "type": "os_version"}
    ]});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = cf_check(&server, "CF-2.03-device-posture-checks-configured.check.yaml");

    let evidence = run_observer(def, &cf_config());
    assert_eq!(evidence.len(), 3);
    for ev in &evidence {
        assert_eq!(ev.status_id, StatusId::Effective, "expected Effective, got: {}", ev.status);
    }
}

#[test]
fn cf203_fail_missing_disk_and_firewall_checks() {
    let body = serde_json::json!({"success": true, "result": [
        {"id": "r3", "type": "os_version"}
    ]});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = cf_check(&server, "CF-2.03-device-posture-checks-configured.check.yaml");

    let evidence = run_observer(def, &cf_config());
    assert_eq!(evidence.len(), 3);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective, "disk_encryption missing");
    assert_eq!(evidence[1].status_id, StatusId::Ineffective, "firewall missing");
    assert_eq!(evidence[2].status_id, StatusId::Effective, "os_version present");
}

// ---------------------------------------------------------------------------
// CF-3.01 — Gateway DNS block rule
// ---------------------------------------------------------------------------

#[test]
fn cf301_pass_dns_block_rule_exists() {
    let body = serde_json::json!({"success": true, "result": [
        {"id": "r1", "action": "block", "filters": ["dns"], "name": "HTH: Block Security Threats (DNS)"}
    ]});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = cf_check(&server, "CF-3.01-gateway-dns-block-rule.check.yaml");

    let evidence = run_observer(def, &cf_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn cf301_fail_no_dns_block_rule() {
    let body = serde_json::json!({"success": true, "result": [
        {"id": "r1", "action": "block", "filters": ["http"], "name": "HTH: Block Malware Downloads (HTTP)"}
    ]});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = cf_check(&server, "CF-3.01-gateway-dns-block-rule.check.yaml");

    let evidence = run_observer(def, &cf_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
}

// ---------------------------------------------------------------------------
// CF-3.02 — Gateway HTTP block rule
// ---------------------------------------------------------------------------

#[test]
fn cf302_pass_http_block_rule_exists() {
    let body = serde_json::json!({"success": true, "result": [
        {"id": "r1", "action": "block", "filters": ["http"], "name": "HTH: Block Malware Downloads (HTTP)"}
    ]});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = cf_check(&server, "CF-3.02-gateway-http-block-rule.check.yaml");

    let evidence = run_observer(def, &cf_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn cf302_fail_no_http_block_rule() {
    let body = serde_json::json!({"success": true, "result": [
        {"id": "r1", "action": "block", "filters": ["dns"], "name": "HTH: Block Security Threats (DNS)"}
    ]});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = cf_check(&server, "CF-3.02-gateway-http-block-rule.check.yaml");

    let evidence = run_observer(def, &cf_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
}

// ---------------------------------------------------------------------------
// CF-3.03 — Gateway network (L4) policy
// ---------------------------------------------------------------------------

#[test]
fn cf303_pass_network_l4_policy_exists() {
    let body = serde_json::json!({"success": true, "result": [
        {"id": "r1", "action": "block", "filters": ["l4"], "name": "HTH: Block External SSH"}
    ]});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = cf_check(&server, "CF-3.03-gateway-network-policy.check.yaml");

    let evidence = run_observer(def, &cf_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn cf303_fail_no_network_l4_policy() {
    let body = serde_json::json!({"success": true, "result": []});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = cf_check(&server, "CF-3.03-gateway-network-policy.check.yaml");

    let evidence = run_observer(def, &cf_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
}

// ---------------------------------------------------------------------------
// CF-3.04 — Browser isolation policy
// ---------------------------------------------------------------------------

#[test]
fn cf304_pass_browser_isolation_policy_exists() {
    let body = serde_json::json!({"success": true, "result": [
        {"id": "r1", "action": "isolate", "filters": ["http"], "name": "HTH: Isolate Risky Websites"}
    ]});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = cf_check(&server, "CF-3.04-browser-isolation-policy.check.yaml");

    let evidence = run_observer(def, &cf_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn cf304_fail_no_browser_isolation_policy() {
    let body = serde_json::json!({"success": true, "result": [
        {"id": "r1", "action": "block", "filters": ["http"], "name": "HTH: Block Malware Downloads (HTTP)"}
    ]});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = cf_check(&server, "CF-3.04-browser-isolation-policy.check.yaml");

    let evidence = run_observer(def, &cf_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
}

// ---------------------------------------------------------------------------
// CF-4.01 — WARP client settings hardened (3 assertions)
// ---------------------------------------------------------------------------

#[test]
fn cf401_pass_warp_settings_hardened() {
    let body = serde_json::json!({"success": true, "result": {
        "auto_connect": 0, "allow_mode_switch": false, "tunnel_protocol": "wireguard"
    }});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = cf_check(&server, "CF-4.01-warp-client-settings-hardened.check.yaml");

    let evidence = run_observer(def, &cf_config());
    assert_eq!(evidence.len(), 3);
    for ev in &evidence {
        assert_eq!(ev.status_id, StatusId::Effective, "expected Effective, got: {}", ev.status);
    }
}

#[test]
fn cf401_fail_warp_settings_not_hardened() {
    let body = serde_json::json!({"success": true, "result": {
        "auto_connect": 300, "allow_mode_switch": true, "tunnel_protocol": "masque"
    }});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = cf_check(&server, "CF-4.01-warp-client-settings-hardened.check.yaml");

    let evidence = run_observer(def, &cf_config());
    assert_eq!(evidence.len(), 3);
    for ev in &evidence {
        assert_eq!(ev.status_id, StatusId::Ineffective, "expected Ineffective, got: {}", ev.status);
    }
}

// ---------------------------------------------------------------------------
// CF-4.02 — WARP client locked (2 assertions)
// ---------------------------------------------------------------------------

#[test]
fn cf402_pass_warp_client_locked() {
    let body = serde_json::json!({"success": true, "result": {"switch_locked": true, "allowed_to_leave": false}});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = cf_check(&server, "CF-4.02-warp-client-locked.check.yaml");

    let evidence = run_observer(def, &cf_config());
    assert_eq!(evidence.len(), 2);
    for ev in &evidence {
        assert_eq!(ev.status_id, StatusId::Effective, "expected Effective, got: {}", ev.status);
    }
}

#[test]
fn cf402_fail_warp_client_not_locked() {
    let body = serde_json::json!({"success": true, "result": {"switch_locked": false, "allowed_to_leave": true}});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = cf_check(&server, "CF-4.02-warp-client-locked.check.yaml");

    let evidence = run_observer(def, &cf_config());
    assert_eq!(evidence.len(), 2);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
    assert_eq!(evidence[0].findings[0].severity_id, 4); // high
    assert_eq!(evidence[1].status_id, StatusId::Ineffective);
}

// ---------------------------------------------------------------------------
// CF-4.03 — Split tunnel exclusion count
// ---------------------------------------------------------------------------

#[test]
fn cf403_pass_exclusion_count_reasonable() {
    let body = serde_json::json!({"success": true, "result": [
        {"address": "10.0.0.0/8", "description": "internal"},
        {"address": "192.168.0.0/16", "description": "vpn"}
    ]});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = cf_check(&server, "CF-4.03-split-tunnel-exclusion-count.check.yaml");

    let evidence = run_observer(def, &cf_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn cf403_fail_exclusion_count_excessive() {
    let exclusions: Vec<_> = (0..25)
        .map(|i| serde_json::json!({"address": format!("10.0.{i}.0/24"), "description": "exception"}))
        .collect();
    let body = serde_json::json!({"success": true, "result": exclusions});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = cf_check(&server, "CF-4.03-split-tunnel-exclusion-count.check.yaml");

    let evidence = run_observer(def, &cf_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
}

// ---------------------------------------------------------------------------
// CF-5.01 — Tunnel configuration audit (reachability-based)
// ---------------------------------------------------------------------------

#[test]
fn cf501_pass_tunnels_reachable() {
    let body = serde_json::json!({"success": true, "result": [
        {"id": "t1", "name": "prod-tunnel", "status": "healthy", "connections": [{"id": "c1"}]}
    ]});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = cf_check(&server, "CF-5.01-tunnel-configuration-audit.check.yaml");

    let evidence = run_observer(def, &cf_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn cf501_fail_tunnels_unreachable() {
    let server = MockHTTPServer::new(vec![(500, "{}".to_string())]);
    let def = cf_check(&server, "CF-5.01-tunnel-configuration-audit.check.yaml");

    let evidence = run_observer(def, &cf_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
}

// ---------------------------------------------------------------------------
// CF-6.01 — Logpush Zero Trust datasets (4 assertions)
// ---------------------------------------------------------------------------

#[test]
fn cf601_pass_all_datasets_active() {
    let body = serde_json::json!({"success": true, "result": [
        {"name": "access", "dataset": "access_requests", "enabled": true, "destination_conf": "s3://bucket"},
        {"name": "dns", "dataset": "gateway_dns", "enabled": true, "destination_conf": "s3://bucket"},
        {"name": "http", "dataset": "gateway_http", "enabled": true, "destination_conf": "s3://bucket"},
        {"name": "net", "dataset": "gateway_network", "enabled": true, "destination_conf": "s3://bucket"}
    ]});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = cf_check(&server, "CF-6.01-logpush-zero-trust-datasets.check.yaml");

    let evidence = run_observer(def, &cf_config());
    assert_eq!(evidence.len(), 4);
    for ev in &evidence {
        assert_eq!(ev.status_id, StatusId::Effective, "expected Effective, got: {}", ev.status);
    }
}

#[test]
fn cf601_fail_gateway_datasets_missing() {
    let body = serde_json::json!({"success": true, "result": [
        {"name": "access", "dataset": "access_requests", "enabled": true, "destination_conf": "s3://bucket"},
        {"name": "dns", "dataset": "gateway_dns", "enabled": true, "destination_conf": "s3://bucket"}
    ]});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = cf_check(&server, "CF-6.01-logpush-zero-trust-datasets.check.yaml");

    let evidence = run_observer(def, &cf_config());
    assert_eq!(evidence.len(), 4);
    assert_eq!(evidence[0].status_id, StatusId::Effective, "access_requests active");
    assert_eq!(evidence[1].status_id, StatusId::Effective, "gateway_dns active");
    assert_eq!(evidence[2].status_id, StatusId::Ineffective, "gateway_http missing");
    assert_eq!(evidence[3].status_id, StatusId::Ineffective, "gateway_network missing");
}

// ---------------------------------------------------------------------------
// Auth0 shared config
// ---------------------------------------------------------------------------

fn auth0_config(mock_url: &str) -> HashMap<String, String> {
    let mut cfg = HashMap::new();
    cfg.insert("AUTH0_TOKEN".to_string(), "auth0-test-token".to_string());
    cfg.insert("AUTH0_API_BASE".to_string(), format!("{mock_url}/api/v2"));
    cfg
}

// ---------------------------------------------------------------------------
// AUTH0-1.01 — Brute force protection (2 assertions)
// ---------------------------------------------------------------------------

#[test]
fn auth0101_pass_brute_force_protection_hardened() {
    let body = serde_json::json!({"enabled": true, "max_attempts": 5, "mode": "count_per_identifier_and_ip"});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check("auth0", "AUTH0-1.01-brute-force-protection.check.yaml");

    let evidence = run_observer(def, &auth0_config(server.url()));
    assert_eq!(evidence.len(), 2);
    for ev in &evidence {
        assert_eq!(ev.status_id, StatusId::Effective, "expected Effective, got: {}", ev.status);
    }
}

#[test]
fn auth0101_fail_brute_force_protection_disabled_and_loose() {
    let body = serde_json::json!({"enabled": false, "max_attempts": 10});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check("auth0", "AUTH0-1.01-brute-force-protection.check.yaml");

    let evidence = run_observer(def, &auth0_config(server.url()));
    assert_eq!(evidence.len(), 2);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective, "protection disabled");
    assert_eq!(evidence[0].findings[0].severity_id, 5); // critical
    assert_eq!(evidence[1].status_id, StatusId::Ineffective, "max_attempts above threshold");
}

// ---------------------------------------------------------------------------
// AUTH0-1.02 — Suspicious IP throttling
// ---------------------------------------------------------------------------

#[test]
fn auth0102_pass_suspicious_ip_throttling_enabled() {
    let body = serde_json::json!({"enabled": true});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check("auth0", "AUTH0-1.02-suspicious-ip-throttling.check.yaml");

    let evidence = run_observer(def, &auth0_config(server.url()));
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn auth0102_fail_suspicious_ip_throttling_disabled() {
    let body = serde_json::json!({"enabled": false});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check("auth0", "AUTH0-1.02-suspicious-ip-throttling.check.yaml");

    let evidence = run_observer(def, &auth0_config(server.url()));
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
}

// ---------------------------------------------------------------------------
// AUTH0-1.03 — Breached password detection
// ---------------------------------------------------------------------------

#[test]
fn auth0103_pass_breached_password_detection_enabled() {
    let body = serde_json::json!({"enabled": true, "method": "standard"});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check("auth0", "AUTH0-1.03-breached-password-detection.check.yaml");

    let evidence = run_observer(def, &auth0_config(server.url()));
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn auth0103_fail_breached_password_detection_disabled() {
    let body = serde_json::json!({"enabled": false});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check("auth0", "AUTH0-1.03-breached-password-detection.check.yaml");

    let evidence = run_observer(def, &auth0_config(server.url()));
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
}

// ---------------------------------------------------------------------------
// AUTH0-1.04 — Bot detection
// ---------------------------------------------------------------------------

#[test]
fn auth0104_pass_bot_detection_enabled() {
    let body = serde_json::json!({"bot_detection_level": "medium"});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check("auth0", "AUTH0-1.04-bot-detection.check.yaml");

    let evidence = run_observer(def, &auth0_config(server.url()));
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn auth0104_fail_bot_detection_off() {
    let body = serde_json::json!({"bot_detection_level": "off"});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check("auth0", "AUTH0-1.04-bot-detection.check.yaml");

    let evidence = run_observer(def, &auth0_config(server.url()));
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
}

// ---------------------------------------------------------------------------
// AUTH0-2.01 — Connection password policy (2 assertions)
// ---------------------------------------------------------------------------

#[test]
fn auth0201_pass_connections_hardened() {
    let body = serde_json::json!([
        {"id": "con_1", "name": "Username-Password-Authentication", "options": {"password_policy": "excellent", "brute_force_protection": true}}
    ]);
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check("auth0", "AUTH0-2.01-connection-password-policy.check.yaml");

    let evidence = run_observer(def, &auth0_config(server.url()));
    assert_eq!(evidence.len(), 2);
    for ev in &evidence {
        assert_eq!(ev.status_id, StatusId::Effective, "expected Effective, got: {}", ev.status);
    }
}

#[test]
fn auth0201_fail_connections_weak() {
    let body = serde_json::json!([
        {"id": "con_1", "name": "Username-Password-Authentication", "options": {"password_policy": "fair", "brute_force_protection": false}}
    ]);
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check("auth0", "AUTH0-2.01-connection-password-policy.check.yaml");

    let evidence = run_observer(def, &auth0_config(server.url()));
    assert_eq!(evidence.len(), 2);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective, "weak password policy");
    assert_eq!(evidence[1].status_id, StatusId::Ineffective, "brute force protection disabled");
}

// ---------------------------------------------------------------------------
// AUTH0-2.02 — Guardian MFA policy
// ---------------------------------------------------------------------------

#[test]
fn auth0202_pass_mfa_all_applications() {
    let body = serde_json::json!(["all-applications"]);
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check("auth0", "AUTH0-2.02-guardian-mfa-policy.check.yaml");

    let evidence = run_observer(def, &auth0_config(server.url()));
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn auth0202_fail_mfa_not_enforced() {
    let body = serde_json::json!([]);
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check("auth0", "AUTH0-2.02-guardian-mfa-policy.check.yaml");

    let evidence = run_observer(def, &auth0_config(server.url()));
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
    assert_eq!(evidence[0].findings[0].severity_id, 5); // critical
}

// ---------------------------------------------------------------------------
// AUTH0-3.01 — Tenant settings hardened (3 assertions)
// ---------------------------------------------------------------------------

#[test]
fn auth0301_pass_tenant_settings_hardened() {
    let body = serde_json::json!({
        "session_lifetime": 8,
        "idle_session_lifetime": 1,
        "flags": {"revoke_refresh_token_grant": true, "enable_sso": true}
    });
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check("auth0", "AUTH0-3.01-tenant-settings-hardened.check.yaml");

    let evidence = run_observer(def, &auth0_config(server.url()));
    assert_eq!(evidence.len(), 3);
    for ev in &evidence {
        assert_eq!(ev.status_id, StatusId::Effective, "expected Effective, got: {}", ev.status);
    }
}

#[test]
fn auth0301_fail_tenant_settings_loose() {
    let body = serde_json::json!({
        "session_lifetime": 24,
        "idle_session_lifetime": 4,
        "flags": {"revoke_refresh_token_grant": false}
    });
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check("auth0", "AUTH0-3.01-tenant-settings-hardened.check.yaml");

    let evidence = run_observer(def, &auth0_config(server.url()));
    assert_eq!(evidence.len(), 3);
    for ev in &evidence {
        assert_eq!(ev.status_id, StatusId::Ineffective, "expected Ineffective, got: {}", ev.status);
    }
}

// ---------------------------------------------------------------------------
// AUTH0-4.02 — Application configuration audit (3 assertions)
// ---------------------------------------------------------------------------

#[test]
fn auth0402_pass_clients_hardened() {
    let body = serde_json::json!([
        {
            "name": "Internal SPA",
            "client_id": "abc123",
            "app_type": "spa",
            "oidc_conformant": true,
            "jwt_configuration": {"lifetime_in_seconds": 3600},
            "refresh_token": {"rotation_type": "rotating"}
        }
    ]);
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check("auth0", "AUTH0-4.02-application-configuration-audit.check.yaml");

    let evidence = run_observer(def, &auth0_config(server.url()));
    assert_eq!(evidence.len(), 3);
    for ev in &evidence {
        assert_eq!(ev.status_id, StatusId::Effective, "expected Effective, got: {}", ev.status);
    }
}

#[test]
fn auth0402_fail_clients_not_hardened() {
    let body = serde_json::json!([
        {
            "name": "Legacy App",
            "client_id": "def456",
            "app_type": "regular_web",
            "oidc_conformant": false,
            "jwt_configuration": {"lifetime_in_seconds": 36000},
            "refresh_token": {"rotation_type": "non-rotating"}
        }
    ]);
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check("auth0", "AUTH0-4.02-application-configuration-audit.check.yaml");

    let evidence = run_observer(def, &auth0_config(server.url()));
    assert_eq!(evidence.len(), 3);
    for ev in &evidence {
        assert_eq!(ev.status_id, StatusId::Ineffective, "expected Ineffective, got: {}", ev.status);
    }
}

// ---------------------------------------------------------------------------
// AUTH0-5.01 — Log stream active
// ---------------------------------------------------------------------------

#[test]
fn auth0501_pass_active_log_stream_exists() {
    let body = serde_json::json!([
        {"id": "lst_1", "name": "SIEM Stream", "type": "http", "status": "active"}
    ]);
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check("auth0", "AUTH0-5.01-log-stream-active.check.yaml");

    let evidence = run_observer(def, &auth0_config(server.url()));
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn auth0501_fail_no_active_log_stream() {
    let body = serde_json::json!([]);
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = load_check("auth0", "AUTH0-5.01-log-stream-active.check.yaml");

    let evidence = run_observer(def, &auth0_config(server.url()));
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
}

// ---------------------------------------------------------------------------
// LaunchDarkly shared config
// ---------------------------------------------------------------------------

fn ld_config() -> HashMap<String, String> {
    let mut cfg = HashMap::new();
    cfg.insert("LD_API_KEY".to_string(), "ld-test-key".to_string());
    cfg.insert("LD_PROJECT_KEY".to_string(), "default".to_string());
    cfg
}

fn ld_check(server: &MockHTTPServer, filename: &str) -> ocean::check::CheckDefinition {
    load_check_with_mock_urls("launchdarkly", filename, "https://app.launchdarkly.com", server.url())
}

// ---------------------------------------------------------------------------
// LD-1.01 — Member MFA audit
// ---------------------------------------------------------------------------

#[test]
fn ld101_pass_all_members_have_mfa() {
    let body = serde_json::json!({"items": [
        {"email": "alice@example.com", "role": "admin", "mfa": true},
        {"email": "bob@example.com", "role": "writer", "mfa": true}
    ], "totalCount": 2});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = ld_check(&server, "LD-1.01-member-mfa-audit.check.yaml");

    let evidence = run_observer(def, &ld_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn ld101_fail_member_without_mfa() {
    let body = serde_json::json!({"items": [
        {"email": "alice@example.com", "role": "admin", "mfa": true},
        {"email": "bob@example.com", "role": "writer", "mfa": false}
    ], "totalCount": 2});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = ld_check(&server, "LD-1.01-member-mfa-audit.check.yaml");

    let evidence = run_observer(def, &ld_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
    assert_eq!(evidence[0].findings[0].severity_id, 5); // critical
}

// ---------------------------------------------------------------------------
// LD-1.02 — Admin role count
// ---------------------------------------------------------------------------

#[test]
fn ld102_pass_admin_count_within_limit() {
    let body = serde_json::json!({"items": [
        {"email": "alice@example.com", "role": "admin"},
        {"email": "bob@example.com", "role": "writer"}
    ]});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = ld_check(&server, "LD-1.02-admin-role-count.check.yaml");

    let evidence = run_observer(def, &ld_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn ld102_fail_admin_count_exceeds_limit() {
    let members: Vec<_> = (0..4)
        .map(|i| serde_json::json!({"email": format!("admin{i}@example.com"), "role": "admin"}))
        .collect();
    let body = serde_json::json!({"items": members});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = ld_check(&server, "LD-1.02-admin-role-count.check.yaml");

    let evidence = run_observer(def, &ld_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
}

// ---------------------------------------------------------------------------
// LD-2.01 — Environment secure mode (2 assertions)
// ---------------------------------------------------------------------------

#[test]
fn ld201_pass_all_environments_secure_mode() {
    let body = serde_json::json!({"items": [
        {"key": "production", "name": "Production", "secureMode": true},
        {"key": "staging", "name": "Staging", "secureMode": true}
    ]});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = ld_check(&server, "LD-2.01-environment-secure-mode.check.yaml");

    let evidence = run_observer(def, &ld_config());
    assert_eq!(evidence.len(), 2);
    for ev in &evidence {
        assert_eq!(ev.status_id, StatusId::Effective, "expected Effective, got: {}", ev.status);
    }
}

#[test]
fn ld201_fail_production_secure_mode_disabled() {
    let body = serde_json::json!({"items": [
        {"key": "production", "name": "Production", "secureMode": false},
        {"key": "staging", "name": "Staging", "secureMode": true}
    ]});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = ld_check(&server, "LD-2.01-environment-secure-mode.check.yaml");

    let evidence = run_observer(def, &ld_config());
    assert_eq!(evidence.len(), 2);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective, "an environment lacks secure mode");
    assert_eq!(evidence[1].status_id, StatusId::Ineffective, "production lacks secure mode");
}

// ---------------------------------------------------------------------------
// LD-2.02 — API token admin role
// ---------------------------------------------------------------------------

#[test]
fn ld202_pass_no_admin_tokens() {
    let body = serde_json::json!({"items": [
        {"_id": "tok_1", "name": "ci-deploy", "role": "writer"}
    ]});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = ld_check(&server, "LD-2.02-api-token-admin-role.check.yaml");

    let evidence = run_observer(def, &ld_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn ld202_fail_admin_token_exists() {
    let body = serde_json::json!({"items": [
        {"_id": "tok_1", "name": "legacy-automation", "role": "admin"}
    ]});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = ld_check(&server, "LD-2.02-api-token-admin-role.check.yaml");

    let evidence = run_observer(def, &ld_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
    assert_eq!(evidence[0].findings[0].severity_id, 4); // high
}

// ---------------------------------------------------------------------------
// LD-3.01 — Production environment change controls (3 assertions)
// ---------------------------------------------------------------------------

#[test]
fn ld301_pass_production_hardened() {
    let body = serde_json::json!({
        "key": "production", "requireComments": true, "confirmChanges": true, "critical": true
    });
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = ld_check(&server, "LD-3.01-production-environment-hardened.check.yaml");

    let evidence = run_observer(def, &ld_config());
    assert_eq!(evidence.len(), 3);
    for ev in &evidence {
        assert_eq!(ev.status_id, StatusId::Effective, "expected Effective, got: {}", ev.status);
    }
}

#[test]
fn ld301_fail_production_not_hardened() {
    let body = serde_json::json!({
        "key": "production", "requireComments": false, "confirmChanges": false, "critical": false
    });
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = ld_check(&server, "LD-3.01-production-environment-hardened.check.yaml");

    let evidence = run_observer(def, &ld_config());
    assert_eq!(evidence.len(), 3);
    for ev in &evidence {
        assert_eq!(ev.status_id, StatusId::Ineffective, "expected Ineffective, got: {}", ev.status);
    }
}

// ---------------------------------------------------------------------------
// LD-3.02 — Flag ownership audit
// ---------------------------------------------------------------------------

#[test]
fn ld302_pass_all_flags_have_maintainer() {
    let body = serde_json::json!({"items": [
        {"key": "new-checkout", "temporary": true, "_maintainer": {"_id": "u1"}},
        {"key": "beta-search", "temporary": true, "_maintainerTeam": {"key": "search-team"}}
    ]});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = ld_check(&server, "LD-3.02-flag-lifecycle-hygiene.check.yaml");

    let evidence = run_observer(def, &ld_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn ld302_fail_flag_without_maintainer() {
    let body = serde_json::json!({"items": [
        {"key": "orphaned-flag", "temporary": true}
    ]});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = ld_check(&server, "LD-3.02-flag-lifecycle-hygiene.check.yaml");

    let evidence = run_observer(def, &ld_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
}

// ---------------------------------------------------------------------------
// LD-4.01 — Audit log webhook active
// ---------------------------------------------------------------------------

#[test]
fn ld401_pass_active_webhook_exists() {
    let body = serde_json::json!({"items": [
        {"_id": "wh_1", "name": "HTH SIEM Webhook", "url": "https://siem.example.com/hook", "on": true}
    ]});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = ld_check(&server, "LD-4.01-audit-log-webhook-active.check.yaml");

    let evidence = run_observer(def, &ld_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn ld401_fail_no_active_webhook() {
    let body = serde_json::json!({"items": [
        {"_id": "wh_1", "name": "Disabled Hook", "url": "https://siem.example.com/hook", "on": false}
    ]});
    let server = MockHTTPServer::new(vec![(200, body.to_string())]);
    let def = ld_check(&server, "LD-4.01-audit-log-webhook-active.check.yaml");

    let evidence = run_observer(def, &ld_config());
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
}

// ---------------------------------------------------------------------------
// Loader integration: every checks/{cloudflare,auth0,launchdarkly}/*.check.yaml
// file loads cleanly with mandatory HTH references.
// ---------------------------------------------------------------------------

fn assert_vendor_dir_loads(dir_name: &str, source: &str, hth_prefix: &str, expected_ids: &[&str]) {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("checks")
        .join(dir_name);
    let defs = ocean::check::loader::load_definitions_from_dir(&dir);

    assert!(!defs.is_empty(), "expected at least one {dir_name} check to load");

    let ids: Vec<&str> = defs.iter().map(|d| d.id.as_str()).collect();
    for expected in expected_ids {
        assert!(ids.contains(expected), "missing {expected}, got: {ids:?}");
    }
    assert_eq!(ids.len(), expected_ids.len(), "unexpected extra or missing {dir_name} checks: {ids:?}");

    for def in &defs {
        assert_eq!(def.source, source, "{}: source should be '{source}'", def.id);
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
        assert!(!def.assertions.is_empty(), "{}: check has no assertions", def.id);
        assert!(!def.steps.is_empty(), "{}: check has no steps", def.id);
    }
}

#[test]
fn all_cloudflare_checks_load_and_have_hth_references() {
    assert_vendor_dir_loads(
        "cloudflare",
        "cloudflare",
        "cloudflare:",
        &[
            "CF-1.01", "CF-1.03", "CF-1.04", "CF-2.02", "CF-2.03", "CF-3.01", "CF-3.02", "CF-3.03",
            "CF-3.04", "CF-4.01", "CF-4.02", "CF-4.03", "CF-5.01", "CF-6.01",
        ],
    );
}

#[test]
fn all_auth0_checks_load_and_have_hth_references() {
    assert_vendor_dir_loads(
        "auth0",
        "auth0",
        "auth0:",
        &[
            "AUTH0-1.01", "AUTH0-1.02", "AUTH0-1.03", "AUTH0-1.04", "AUTH0-2.01", "AUTH0-2.02",
            "AUTH0-3.01", "AUTH0-4.02", "AUTH0-5.01",
        ],
    );
}

#[test]
fn all_launchdarkly_checks_load_and_have_hth_references() {
    assert_vendor_dir_loads(
        "launchdarkly",
        "launchdarkly",
        "launchdarkly:",
        &["LD-1.01", "LD-1.02", "LD-2.01", "LD-2.02", "LD-3.01", "LD-3.02", "LD-4.01"],
    );
}
