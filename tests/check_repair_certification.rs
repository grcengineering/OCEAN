// Certification tests for the extract/CEL repair pass over the sibling defect
// class (Jinja2-style pipe filters and unsupported `$[?(@...)]` JSONPath
// filters that the runtime cannot execute).
//
// Mirrors the MockHTTPServer TDD pattern from tests/check_pipeline.rs and
// tests/check_entra_parity.rs. Each repaired check gets a pass case and a
// fail case built from documented vendor API response shapes, proving the
// rewritten `extract` paths and CEL `assertions` actually execute against
// realistic data rather than merely parsing.

use std::collections::HashMap;
use std::io::{ErrorKind, Read as _, Write as _};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ocean::check::{register_check, CheckDefinition};
use ocean::evidence::{Evidence, StatusId};
use ocean::module::{ConfirmAuthorizer, EnvironmentScope, Executor, Registry, TestConfig};

// ---------------------------------------------------------------------------
// Mock HTTP server (copied from tests/check_pipeline.rs — kept local so this
// file has no cross-test-file dependency).
// ---------------------------------------------------------------------------

struct MockHTTPServer {
    base_url: String,
}

/// Find the end of the HTTP header block (index right after `\r\n\r\n`).
fn header_terminator(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// Parse a case-insensitive `Content-Length` value out of raw header bytes.
fn content_length(headers: &[u8]) -> usize {
    let text = String::from_utf8_lossy(headers);
    text.lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.trim().eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0)
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
                // Drain the full request before responding. A single read()
                // call can race a POST body arriving in a later TCP segment
                // (headers and body written separately by the client) —
                // reading only the headers and then responding + closing
                // would reset the client mid-write. Loop until we've read
                // past the header terminator and the full Content-Length
                // body, falling back to a short read timeout for requests
                // with no body (GET) so we don't block waiting for bytes
                // that will never arrive.
                let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
                let mut total: Vec<u8> = Vec::new();
                let mut buf = [0u8; 8192];
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            total.extend_from_slice(&buf[..n]);
                            if let Some(header_end) = header_terminator(&total) {
                                let need = header_end + content_length(&total[..header_end]);
                                if total.len() >= need {
                                    break;
                                }
                            }
                        }
                        Err(ref e)
                            if e.kind() == ErrorKind::WouldBlock
                                || e.kind() == ErrorKind::TimedOut =>
                        {
                            break
                        }
                        Err(_) => break,
                    }
                }

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

fn check_path(vendor_dir: &str, filename: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("checks")
        .join(vendor_dir)
        .join(filename)
}

/// Load a check file and rewrite its literal request host(s) to the mock
/// server base URL. `hosts` are matched as raw substrings against the
/// unparsed YAML text, same as the established parity-test convention.
fn load_check_with_mock_urls(
    vendor_dir: &str,
    filename: &str,
    hosts: &[&str],
    mock_base: &str,
) -> CheckDefinition {
    let path = check_path(vendor_dir, filename);
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
    let mut rewritten = content;
    for host in hosts {
        rewritten = rewritten.replace(host, mock_base);
    }
    serde_yaml::from_str(&rewritten)
        .unwrap_or_else(|e| panic!("parse rewritten {}: {}", filename, e))
}

fn run_observer_with_config(
    def: CheckDefinition,
    id: &str,
    config: &HashMap<String, String>,
) -> Vec<Evidence> {
    let registry = Arc::new(Registry::new());
    register_check(&registry, def);
    let executor = Executor::new(Arc::clone(&registry));
    executor
        .execute_observer(id, config)
        .unwrap_or_else(|e| panic!("execute observer {}: {}", id, e))
}

fn run_tester_with_config(
    def: CheckDefinition,
    id: &str,
    config: HashMap<String, String>,
    target_environment: EnvironmentScope,
) -> Vec<Evidence> {
    let registry = Arc::new(Registry::new());
    register_check(&registry, def);
    let executor = Executor::new(Arc::clone(&registry));
    let cfg = TestConfig {
        module_config: config,
        target_environment,
        authorizer: Box::new(ConfirmAuthorizer),
    };
    executor
        .execute_tester(id, &cfg)
        .unwrap_or_else(|e| panic!("execute tester {}: {}", id, e))
}

fn aws_config() -> HashMap<String, String> {
    let mut cfg = HashMap::new();
    cfg.insert("AWS_ACCESS_KEY_ID".to_string(), "AKIATEST".to_string());
    cfg.insert("AWS_SECRET_ACCESS_KEY".to_string(), "test-secret".to_string());
    cfg.insert("AWS_REGION".to_string(), "us-east-1".to_string());
    cfg
}

fn azure_config() -> HashMap<String, String> {
    let mut cfg = HashMap::new();
    cfg.insert("AZURE_CLIENT_ID".to_string(), "test-client-id".to_string());
    cfg.insert("AZURE_CLIENT_SECRET".to_string(), "test-secret".to_string());
    cfg.insert("AZURE_TENANT_ID".to_string(), "test-tenant-id".to_string());
    cfg.insert("AZURE_SUBSCRIPTION_ID".to_string(), "test-sub-id".to_string());
    cfg
}

fn github_config() -> HashMap<String, String> {
    let mut cfg = HashMap::new();
    cfg.insert("GITHUB_TOKEN".to_string(), "ghp_test_token".to_string());
    cfg.insert("GITHUB_ORG".to_string(), "test-org".to_string());
    cfg
}

fn okta_config() -> HashMap<String, String> {
    let mut cfg = HashMap::new();
    cfg.insert("OKTA_API_TOKEN".to_string(), "test-okta-token".to_string());
    cfg.insert("OKTA_DOMAIN".to_string(), "test.okta.com".to_string());
    cfg
}

const AWS_CLOUDTRAIL_HOST: &str = "https://cloudtrail.{{aws_region}}.amazonaws.com";
const AZURE_GRAPH_HOST: &str = "https://graph.microsoft.com";
const AZURE_ARM_HOST: &str = "https://management.azure.com";
const GITHUB_HOST: &str = "https://api.github.com";
const OKTA_HOST: &str = "https://{{okta_domain}}";

// ===========================================================================
// AWS-CT-1.01 — CloudTrail Enabled in All Regions (partial repair)
//
// Only `trail_exists` and `multi_region_enabled` were repaired (both were
// broken Jinja2 pipe filters self-contained to step 1's output). The third
// assertion `trail_is_logging` depends on step 2's body `Name:
// "{{trails[0].TrailARN}}"`, which the template engine cannot resolve
// (extracted arrays are never stringified into the template context) — a
// pre-existing structural bug outside the assigned defect class, left
// untouched and not certified here. See report for details.
// ===========================================================================

fn ct101_trail(is_multi_region: bool) -> serde_json::Value {
    serde_json::json!({
        "Name": "org-trail",
        "S3BucketName": "org-trail-logs",
        "IncludeGlobalServiceEvents": true,
        "IsMultiRegionTrail": is_multi_region,
        "HomeRegion": "us-east-1",
        "TrailARN": "arn:aws:cloudtrail:us-east-1:111122223333:trail/org-trail",
        "LogFileValidationEnabled": true,
        "IsOrganizationTrail": false
    })
}

#[test]
fn ct101_pass_trail_exists_and_multi_region() {
    let describe_trails = serde_json::json!({"trailList": [ct101_trail(true)]});
    let trail_status = serde_json::json!({"IsLogging": true});
    let server = MockHTTPServer::new(vec![
        (200, describe_trails.to_string()),
        (200, trail_status.to_string()),
    ]);

    let def = load_check_with_mock_urls(
        "aws",
        "AWS-CT-1.01-cloudtrail-enabled.check.yaml",
        &[AWS_CLOUDTRAIL_HOST],
        server.url(),
    );
    let evidence = run_observer_with_config(def, "AWS-CT-1.01", &aws_config());

    assert_eq!(evidence.len(), 3);
    assert_eq!(evidence[0].status_id, StatusId::Effective, "trail_exists");
    assert_eq!(evidence[1].status_id, StatusId::Effective, "multi_region_enabled");
}

#[test]
fn ct101_fail_no_trails() {
    let describe_trails = serde_json::json!({"trailList": []});
    let trail_status = serde_json::json!({"IsLogging": false});
    let server = MockHTTPServer::new(vec![
        (200, describe_trails.to_string()),
        (200, trail_status.to_string()),
    ]);

    let def = load_check_with_mock_urls(
        "aws",
        "AWS-CT-1.01-cloudtrail-enabled.check.yaml",
        &[AWS_CLOUDTRAIL_HOST],
        server.url(),
    );
    let evidence = run_observer_with_config(def, "AWS-CT-1.01", &aws_config());

    assert_eq!(evidence.len(), 3);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective, "trail_exists");
    assert_eq!(evidence[1].status_id, StatusId::Ineffective, "multi_region_enabled");
}

#[test]
fn ct101_fail_no_multi_region_trail() {
    let describe_trails = serde_json::json!({"trailList": [ct101_trail(false)]});
    let trail_status = serde_json::json!({"IsLogging": true});
    let server = MockHTTPServer::new(vec![
        (200, describe_trails.to_string()),
        (200, trail_status.to_string()),
    ]);

    let def = load_check_with_mock_urls(
        "aws",
        "AWS-CT-1.01-cloudtrail-enabled.check.yaml",
        &[AWS_CLOUDTRAIL_HOST],
        server.url(),
    );
    let evidence = run_observer_with_config(def, "AWS-CT-1.01", &aws_config());

    assert_eq!(evidence[0].status_id, StatusId::Effective, "trail_exists");
    assert_eq!(evidence[1].status_id, StatusId::Ineffective, "multi_region_enabled");
}

// ===========================================================================
// AWS-CT-2.01 — CloudTrail Log File Validation
// ===========================================================================

#[test]
fn ct201_pass_all_trails_validated() {
    let trail = serde_json::json!({
        "Name": "org-trail",
        "IsMultiRegionTrail": true,
        "LogFileValidationEnabled": true
    });
    let describe_trails = serde_json::json!({"trailList": [trail]});
    let server = MockHTTPServer::new(vec![(200, describe_trails.to_string())]);

    let def = load_check_with_mock_urls(
        "aws",
        "AWS-CT-2.01-cloudtrail-validation.check.yaml",
        &[AWS_CLOUDTRAIL_HOST],
        server.url(),
    );
    let evidence = run_observer_with_config(def, "AWS-CT-2.01", &aws_config());

    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Effective);
    assert!(evidence[0].findings.is_empty());
}

#[test]
fn ct201_fail_one_trail_unvalidated() {
    let validated = serde_json::json!({
        "Name": "org-trail",
        "IsMultiRegionTrail": true,
        "LogFileValidationEnabled": true
    });
    let unvalidated = serde_json::json!({
        "Name": "legacy-trail",
        "IsMultiRegionTrail": false,
        "LogFileValidationEnabled": false
    });
    let describe_trails = serde_json::json!({"trailList": [validated, unvalidated]});
    let server = MockHTTPServer::new(vec![(200, describe_trails.to_string())]);

    let def = load_check_with_mock_urls(
        "aws",
        "AWS-CT-2.01-cloudtrail-validation.check.yaml",
        &[AWS_CLOUDTRAIL_HOST],
        server.url(),
    );
    let evidence = run_observer_with_config(def, "AWS-CT-2.01", &aws_config());

    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
    assert_eq!(evidence[0].findings.len(), 1);
}

// ===========================================================================
// AZURE-AAD-2.01 — Legacy Authentication Blocking
// ===========================================================================

fn aad201_blocking_policy(state: &str) -> serde_json::Value {
    serde_json::json!({
        "id": "policy-block-legacy",
        "displayName": "Block legacy authentication",
        "state": state,
        "conditions": {
            "clientAppTypes": ["exchangeActiveSync", "other"]
        },
        "grantControls": {
            "operator": "OR",
            "builtInControls": ["block"]
        }
    })
}

#[test]
fn aad201_pass_legacy_auth_blocked() {
    let policies = serde_json::json!({"value": [aad201_blocking_policy("enabled")]});
    let server = MockHTTPServer::new(vec![(200, policies.to_string())]);

    let def = load_check_with_mock_urls(
        "azure",
        "AZURE-AAD-2.01-legacy-auth.check.yaml",
        &[AZURE_GRAPH_HOST],
        server.url(),
    );
    let evidence = run_observer_with_config(def, "AZURE-AAD-2.01", &azure_config());

    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn aad201_fail_no_blocking_policy() {
    // Policy exists but is disabled — should not count.
    let policies = serde_json::json!({"value": [aad201_blocking_policy("disabled")]});
    let server = MockHTTPServer::new(vec![(200, policies.to_string())]);

    let def = load_check_with_mock_urls(
        "azure",
        "AZURE-AAD-2.01-legacy-auth.check.yaml",
        &[AZURE_GRAPH_HOST],
        server.url(),
    );
    let evidence = run_observer_with_config(def, "AZURE-AAD-2.01", &azure_config());

    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
}

// ===========================================================================
// AZURE-CA-1.01 — Conditional Access Policies / MFA
// ===========================================================================

fn ca101_mfa_policy(state: &str) -> serde_json::Value {
    serde_json::json!({
        "id": "policy-mfa",
        "displayName": "Require MFA",
        "state": state,
        "grantControls": {
            "operator": "OR",
            "builtInControls": ["mfa"]
        }
    })
}

#[test]
fn ca101_pass_policies_exist_and_mfa_required() {
    let policies = serde_json::json!({"value": [ca101_mfa_policy("enabled")]});
    let server = MockHTTPServer::new(vec![(200, policies.to_string())]);

    let def = load_check_with_mock_urls(
        "azure",
        "AZURE-CA-1.01-conditional-access.check.yaml",
        &[AZURE_GRAPH_HOST],
        server.url(),
    );
    let evidence = run_observer_with_config(def, "AZURE-CA-1.01", &azure_config());

    assert_eq!(evidence.len(), 2);
    assert_eq!(evidence[0].status_id, StatusId::Effective, "ca_policies_exist");
    assert_eq!(evidence[1].status_id, StatusId::Effective, "mfa_policy_enabled");
}

#[test]
fn ca101_fail_no_policies() {
    let policies = serde_json::json!({"value": []});
    let server = MockHTTPServer::new(vec![(200, policies.to_string())]);

    let def = load_check_with_mock_urls(
        "azure",
        "AZURE-CA-1.01-conditional-access.check.yaml",
        &[AZURE_GRAPH_HOST],
        server.url(),
    );
    let evidence = run_observer_with_config(def, "AZURE-CA-1.01", &azure_config());

    assert_eq!(evidence.len(), 2);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective, "ca_policies_exist");
    assert_eq!(evidence[1].status_id, StatusId::Ineffective, "mfa_policy_enabled");
}

// ===========================================================================
// AZURE-KV-1.01 — Key Vault Soft Delete / Purge Protection
// ===========================================================================

fn kv101_vault(soft_delete: bool, purge_protection: bool) -> serde_json::Value {
    serde_json::json!({
        "id": "/subscriptions/test-sub-id/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1",
        "name": "kv1",
        "properties": {
            "enableSoftDelete": soft_delete,
            "enablePurgeProtection": purge_protection
        }
    })
}

#[test]
fn kv101_pass_all_vaults_protected() {
    let vaults = serde_json::json!({"value": [kv101_vault(true, true)]});
    let server = MockHTTPServer::new(vec![(200, vaults.to_string())]);

    let def = load_check_with_mock_urls(
        "azure",
        "AZURE-KV-1.01-soft-delete.check.yaml",
        &[AZURE_ARM_HOST],
        server.url(),
    );
    let evidence = run_observer_with_config(def, "AZURE-KV-1.01", &azure_config());

    assert_eq!(evidence.len(), 2);
    assert_eq!(evidence[0].status_id, StatusId::Effective, "soft_delete");
    assert_eq!(evidence[1].status_id, StatusId::Effective, "purge_protection");
}

#[test]
fn kv101_fail_vault_missing_protections() {
    let vaults = serde_json::json!({"value": [kv101_vault(false, false)]});
    let server = MockHTTPServer::new(vec![(200, vaults.to_string())]);

    let def = load_check_with_mock_urls(
        "azure",
        "AZURE-KV-1.01-soft-delete.check.yaml",
        &[AZURE_ARM_HOST],
        server.url(),
    );
    let evidence = run_observer_with_config(def, "AZURE-KV-1.01", &azure_config());

    assert_eq!(evidence.len(), 2);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective, "soft_delete");
    assert_eq!(evidence[1].status_id, StatusId::Ineffective, "purge_protection");
}

// ===========================================================================
// AZURE-LOG-1.01 — Diagnostic Settings on Subscription
// ===========================================================================

#[test]
fn log101_pass_settings_with_log_categories() {
    let setting = serde_json::json!({
        "id": "/subscriptions/test-sub-id/providers/microsoft.insights/diagnosticSettings/ds1",
        "name": "ds1",
        "properties": {
            "logs": [
                {"category": "Administrative", "enabled": true},
                {"category": "Security", "enabled": true}
            ]
        }
    });
    let settings = serde_json::json!({"value": [setting]});
    let server = MockHTTPServer::new(vec![(200, settings.to_string())]);

    let def = load_check_with_mock_urls(
        "azure",
        "AZURE-LOG-1.01-diagnostic-settings.check.yaml",
        &[AZURE_ARM_HOST],
        server.url(),
    );
    let evidence = run_observer_with_config(def, "AZURE-LOG-1.01", &azure_config());

    assert_eq!(evidence.len(), 2);
    assert_eq!(evidence[0].status_id, StatusId::Effective, "diagnostic_settings_exist");
    assert_eq!(evidence[1].status_id, StatusId::Effective, "diagnostic_settings_capture_security");
}

#[test]
fn log101_fail_no_diagnostic_settings() {
    let settings = serde_json::json!({"value": []});
    let server = MockHTTPServer::new(vec![(200, settings.to_string())]);

    let def = load_check_with_mock_urls(
        "azure",
        "AZURE-LOG-1.01-diagnostic-settings.check.yaml",
        &[AZURE_ARM_HOST],
        server.url(),
    );
    let evidence = run_observer_with_config(def, "AZURE-LOG-1.01", &azure_config());

    assert_eq!(evidence.len(), 2);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective, "diagnostic_settings_exist");
    assert_eq!(evidence[1].status_id, StatusId::Ineffective, "diagnostic_settings_capture_security");
}

// ===========================================================================
// AZURE-MFA-1.01 — MFA Bypass (active tester, two chained steps)
// ===========================================================================

fn mfa101_policy_with_exclusion(has_exclusion: bool) -> serde_json::Value {
    let mut conditions = serde_json::json!({});
    if has_exclusion {
        conditions = serde_json::json!({"users": {"excludeUsers": ["break-glass-user-id"]}});
    }
    serde_json::json!({
        "id": "policy-mfa",
        "displayName": "Require MFA",
        "state": "enabled",
        "conditions": conditions,
        "grantControls": {
            "operator": "OR",
            "builtInControls": ["mfa"]
        }
    })
}

#[test]
fn mfa101_pass_mfa_enforced_no_exclusions() {
    let policies = serde_json::json!({"value": [mfa101_policy_with_exclusion(false)]});
    let security_defaults = serde_json::json!({"isEnabled": false});
    let server = MockHTTPServer::new(vec![
        (200, policies.to_string()),
        (200, security_defaults.to_string()),
    ]);

    let def = load_check_with_mock_urls(
        "azure",
        "AZURE-MFA-1.01-mfa-bypass.check.yaml",
        &[AZURE_GRAPH_HOST],
        server.url(),
    );
    let evidence = run_tester_with_config(
        def,
        "AZURE-MFA-1.01",
        azure_config(),
        EnvironmentScope::Staging,
    );

    assert_eq!(evidence.len(), 2);
    assert_eq!(evidence[0].status_id, StatusId::Effective, "mfa_enforcement_exists");
    assert_eq!(evidence[1].status_id, StatusId::Effective, "no_broad_mfa_exclusions");
}

#[test]
fn mfa101_fail_no_mfa_enforcement() {
    let policies = serde_json::json!({"value": []});
    let security_defaults = serde_json::json!({"isEnabled": false});
    let server = MockHTTPServer::new(vec![
        (200, policies.to_string()),
        (200, security_defaults.to_string()),
    ]);

    let def = load_check_with_mock_urls(
        "azure",
        "AZURE-MFA-1.01-mfa-bypass.check.yaml",
        &[AZURE_GRAPH_HOST],
        server.url(),
    );
    let evidence = run_tester_with_config(
        def,
        "AZURE-MFA-1.01",
        azure_config(),
        EnvironmentScope::Staging,
    );

    assert_eq!(evidence.len(), 2);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective, "mfa_enforcement_exists");
}

#[test]
fn mfa101_fail_broad_exclusion_on_mfa_policy() {
    let policies = serde_json::json!({"value": [mfa101_policy_with_exclusion(true)]});
    let security_defaults = serde_json::json!({"isEnabled": false});
    let server = MockHTTPServer::new(vec![
        (200, policies.to_string()),
        (200, security_defaults.to_string()),
    ]);

    let def = load_check_with_mock_urls(
        "azure",
        "AZURE-MFA-1.01-mfa-bypass.check.yaml",
        &[AZURE_GRAPH_HOST],
        server.url(),
    );
    let evidence = run_tester_with_config(
        def,
        "AZURE-MFA-1.01",
        azure_config(),
        EnvironmentScope::Staging,
    );

    assert_eq!(evidence.len(), 2);
    assert_eq!(evidence[0].status_id, StatusId::Effective, "mfa_enforcement_exists");
    assert_eq!(evidence[1].status_id, StatusId::Ineffective, "no_broad_mfa_exclusions");
}

// ===========================================================================
// AZURE-NSG-1.01 — Unrestricted Inbound SSH/RDP
// ===========================================================================

fn nsg101_nsg(direction: &str, access: &str, port: &str, source: &str) -> serde_json::Value {
    serde_json::json!({
        "id": "/subscriptions/test-sub-id/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg1",
        "name": "nsg1",
        "properties": {
            "securityRules": [
                {
                    "name": "rule1",
                    "properties": {
                        "direction": direction,
                        "access": access,
                        "destinationPortRange": port,
                        "sourceAddressPrefix": source,
                        "protocol": "Tcp"
                    }
                }
            ]
        }
    })
}

#[test]
fn nsg101_pass_no_unrestricted_rules() {
    let nsgs = serde_json::json!({"value": [nsg101_nsg("Inbound", "Allow", "443", "10.0.0.0/16")]});
    let server = MockHTTPServer::new(vec![(200, nsgs.to_string())]);

    let def = load_check_with_mock_urls(
        "azure",
        "AZURE-NSG-1.01-unrestricted-inbound.check.yaml",
        &[AZURE_ARM_HOST],
        server.url(),
    );
    let evidence = run_observer_with_config(def, "AZURE-NSG-1.01", &azure_config());

    assert_eq!(evidence.len(), 2);
    assert_eq!(evidence[0].status_id, StatusId::Effective, "no_unrestricted_ssh");
    assert_eq!(evidence[1].status_id, StatusId::Effective, "no_unrestricted_rdp");
}

#[test]
fn nsg101_fail_unrestricted_ssh_and_rdp() {
    let nsgs = serde_json::json!({
        "value": [
            nsg101_nsg("Inbound", "Allow", "22", "0.0.0.0/0"),
            nsg101_nsg("Inbound", "Allow", "3389", "Internet")
        ]
    });
    let server = MockHTTPServer::new(vec![(200, nsgs.to_string())]);

    let def = load_check_with_mock_urls(
        "azure",
        "AZURE-NSG-1.01-unrestricted-inbound.check.yaml",
        &[AZURE_ARM_HOST],
        server.url(),
    );
    let evidence = run_observer_with_config(def, "AZURE-NSG-1.01", &azure_config());

    assert_eq!(evidence.len(), 2);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective, "no_unrestricted_ssh");
    assert_eq!(evidence[1].status_id, StatusId::Ineffective, "no_unrestricted_rdp");
}

// ===========================================================================
// GH-2.03 — Organization Rulesets
// ===========================================================================

#[test]
fn gh203_pass_has_active_ruleset() {
    let rulesets = serde_json::json!([
        {"id": 1, "name": "default-protection", "enforcement": "active"}
    ]);
    let server = MockHTTPServer::new(vec![(200, rulesets.to_string())]);

    let def = load_check_with_mock_urls(
        "github",
        "GH-2.03-org-rulesets.check.yaml",
        &[GITHUB_HOST],
        server.url(),
    );
    let evidence = run_observer_with_config(def, "GH-2.03", &github_config());

    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn gh203_fail_no_active_ruleset() {
    let rulesets = serde_json::json!([
        {"id": 1, "name": "draft-ruleset", "enforcement": "disabled"}
    ]);
    let server = MockHTTPServer::new(vec![(200, rulesets.to_string())]);

    let def = load_check_with_mock_urls(
        "github",
        "GH-2.03-org-rulesets.check.yaml",
        &[GITHUB_HOST],
        server.url(),
    );
    let evidence = run_observer_with_config(def, "GH-2.03", &github_config());

    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
}

// ===========================================================================
// GH-5.01 — Organization Webhooks
// ===========================================================================

fn gh501_webhook(url: &str, insecure_ssl: &str) -> serde_json::Value {
    serde_json::json!({
        "id": 1,
        "config": {
            "url": url,
            "content_type": "json",
            "insecure_ssl": insecure_ssl
        }
    })
}

#[test]
fn gh501_pass_https_and_ssl_verified() {
    let webhooks = serde_json::json!([gh501_webhook("https://example.com/webhook", "0")]);
    let server = MockHTTPServer::new(vec![(200, webhooks.to_string())]);

    let def = load_check_with_mock_urls(
        "github",
        "GH-5.01-org-webhooks.check.yaml",
        &[GITHUB_HOST],
        server.url(),
    );
    let evidence = run_observer_with_config(def, "GH-5.01", &github_config());

    assert_eq!(evidence.len(), 2);
    assert_eq!(evidence[0].status_id, StatusId::Effective, "webhooks_use_https");
    assert_eq!(evidence[1].status_id, StatusId::Effective, "webhooks_ssl_verification");
}

#[test]
fn gh501_fail_http_and_insecure_ssl() {
    let webhooks = serde_json::json!([gh501_webhook("http://example.com/webhook", "1")]);
    let server = MockHTTPServer::new(vec![(200, webhooks.to_string())]);

    let def = load_check_with_mock_urls(
        "github",
        "GH-5.01-org-webhooks.check.yaml",
        &[GITHUB_HOST],
        server.url(),
    );
    let evidence = run_observer_with_config(def, "GH-5.01", &github_config());

    assert_eq!(evidence.len(), 2);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective, "webhooks_use_https");
    assert_eq!(evidence[1].status_id, StatusId::Ineffective, "webhooks_ssl_verification");
}

// ===========================================================================
// OKTA-1.07 — Phishing-Resistant Authenticators
// ===========================================================================

#[test]
fn okta107_pass_webauthn_configured() {
    let authenticators = serde_json::json!([
        {"key": "webauthn", "type": "security_key", "status": "ACTIVE"},
        {"key": "okta_verify", "type": "app", "status": "ACTIVE"}
    ]);
    let server = MockHTTPServer::new(vec![(200, authenticators.to_string())]);

    let def = load_check_with_mock_urls(
        "okta",
        "OKTA-1.07-authenticators.check.yaml",
        &[OKTA_HOST],
        server.url(),
    );
    let evidence = run_observer_with_config(def, "OKTA-1.07", &okta_config());

    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn okta107_fail_no_phishing_resistant_authenticator() {
    let authenticators = serde_json::json!([
        {"key": "okta_verify", "type": "app", "status": "ACTIVE"},
        {"key": "google_otp", "type": "app", "status": "ACTIVE"}
    ]);
    let server = MockHTTPServer::new(vec![(200, authenticators.to_string())]);

    let def = load_check_with_mock_urls(
        "okta",
        "OKTA-1.07-authenticators.check.yaml",
        &[OKTA_HOST],
        server.url(),
    );
    let evidence = run_observer_with_config(def, "OKTA-1.07", &okta_config());

    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
}

// ===========================================================================
// OKTA-5.04 — Behavior Detection
// ===========================================================================

#[test]
fn okta504_pass_active_behavior_rule() {
    let behaviors = serde_json::json!([
        {"id": "beh1", "name": "New Device", "status": "ACTIVE"}
    ]);
    let server = MockHTTPServer::new(vec![(200, behaviors.to_string())]);

    let def = load_check_with_mock_urls(
        "okta",
        "OKTA-5.04-behavior-detection.check.yaml",
        &[OKTA_HOST],
        server.url(),
    );
    let evidence = run_observer_with_config(def, "OKTA-5.04", &okta_config());

    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Effective);
}

#[test]
fn okta504_fail_no_active_behavior_rules() {
    let behaviors = serde_json::json!([
        {"id": "beh1", "name": "New Device", "status": "INACTIVE"}
    ]);
    let server = MockHTTPServer::new(vec![(200, behaviors.to_string())]);

    let def = load_check_with_mock_urls(
        "okta",
        "OKTA-5.04-behavior-detection.check.yaml",
        &[OKTA_HOST],
        server.url(),
    );
    let evidence = run_observer_with_config(def, "OKTA-5.04", &okta_config());

    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
}
