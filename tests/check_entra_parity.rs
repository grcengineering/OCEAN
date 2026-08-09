// Integration tests: Microsoft Entra ID (HTH parity) checks under checks/azure/.
//
// Mirrors the MockHTTPServer TDD pattern from tests/check_pipeline.rs. Each
// authored check gets a pass case and a fail case built from Microsoft Graph
// documented response shapes. A load-all test guards the whole checks/azure/
// directory for parse errors and duplicate IDs.

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

fn azure_check_path(filename: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("checks/azure")
        .join(filename)
}

/// Load a check file and rewrite both Graph (`graph.microsoft.com`) and ARM
/// (`management.azure.com`) hosts to the mock server base URL.
fn load_check_with_mock_urls(filename: &str, mock_base: &str) -> CheckDefinition {
    let path = azure_check_path(filename);
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
    let rewritten = content
        .replace("https://graph.microsoft.com", mock_base)
        .replace("https://management.azure.com", mock_base);
    serde_yaml::from_str(&rewritten)
        .unwrap_or_else(|e| panic!("parse rewritten {}: {}", filename, e))
}

fn azure_test_config() -> HashMap<String, String> {
    let mut cfg = HashMap::new();
    cfg.insert("AZURE_CLIENT_ID".to_string(), "test-client-id".to_string());
    cfg.insert("AZURE_CLIENT_SECRET".to_string(), "test-secret".to_string());
    cfg.insert("AZURE_TENANT_ID".to_string(), "test-tenant-id".to_string());
    cfg.insert("AZURE_SUBSCRIPTION_ID".to_string(), "test-sub-id".to_string());
    cfg
}

fn run_observer(def: CheckDefinition, id: &str) -> Vec<ocean::evidence::Evidence> {
    let registry = Arc::new(Registry::new());
    register_check(&registry, def);
    let executor = Executor::new(Arc::clone(&registry));
    executor
        .execute_observer(id, &azure_test_config())
        .unwrap_or_else(|e| panic!("execute observer {}: {}", id, e))
}

// ===========================================================================
// AZURE-CA-2.06 — Block Device Code Flow
// ===========================================================================

fn ca_policy_device_code_block(state: &str) -> serde_json::Value {
    serde_json::json!({
        "id": "policy-device-code",
        "displayName": "Block device code flow",
        "state": state,
        "conditions": {
            "clientAppTypes": ["all"],
            "authenticationFlows": {
                "transferMethods": "deviceCodeFlow"
            },
            "users": {"includeUsers": ["All"], "excludeGroups": ["break-glass-group-id"]}
        },
        "grantControls": {
            "operator": "OR",
            "builtInControls": ["block"]
        }
    })
}

#[test]
fn ca206_pass_device_code_flow_blocked() {
    let policies = serde_json::json!({"value": [ca_policy_device_code_block("enabled")]});
    let server = MockHTTPServer::new(vec![(200, policies.to_string())]);

    let def = load_check_with_mock_urls("AZURE-CA-2.06-block-device-code-flow.check.yaml", server.url());
    let evidence = run_observer(def, "AZURE-CA-2.06");

    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Effective, "status: {}", evidence[0].status);
    assert!(evidence[0].findings.is_empty());
}

#[test]
fn ca206_fail_no_blocking_policy() {
    // Only a report-only (not enabled) policy exists — must not satisfy the assertion.
    let policies = serde_json::json!({"value": [ca_policy_device_code_block("enabledForReportingButNotEnforced")]});
    let server = MockHTTPServer::new(vec![(200, policies.to_string())]);

    let def = load_check_with_mock_urls("AZURE-CA-2.06-block-device-code-flow.check.yaml", server.url());
    let evidence = run_observer(def, "AZURE-CA-2.06");

    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status_id, StatusId::Ineffective, "status: {}", evidence[0].status);
    assert!(!evidence[0].findings.is_empty());
}

#[test]
fn ca206_fail_empty_policy_list() {
    let policies = serde_json::json!({"value": []});
    let server = MockHTTPServer::new(vec![(200, policies.to_string())]);

    let def = load_check_with_mock_urls("AZURE-CA-2.06-block-device-code-flow.check.yaml", server.url());
    let evidence = run_observer(def, "AZURE-CA-2.06");

    assert_eq!(evidence[0].status_id, StatusId::Ineffective);
}

// ===========================================================================
// AZURE-CA-1.02 — Maintain the Emergency Access Exclusion Group
// ===========================================================================

fn ca_policy_with_exclude_groups(state: &str, exclude_groups: Vec<&str>) -> serde_json::Value {
    serde_json::json!({
        "id": "policy-1",
        "displayName": "Require MFA for all users",
        "state": state,
        "conditions": {
            "users": {"includeUsers": ["All"], "excludeGroups": exclude_groups},
            "applications": {"includeApplications": ["All"]}
        },
        "grantControls": {"operator": "OR", "builtInControls": ["mfa"]}
    })
}

#[test]
fn ca102_pass_all_enabled_policies_exclude_group() {
    let policies = serde_json::json!({"value": [
        ca_policy_with_exclude_groups("enabled", vec!["break-glass-group"]),
        ca_policy_with_exclude_groups("enabled", vec!["break-glass-group"]),
    ]});
    let server = MockHTTPServer::new(vec![(200, policies.to_string())]);
    let def = load_check_with_mock_urls("AZURE-CA-1.02-emergency-access-exclusion.check.yaml", server.url());
    let evidence = run_observer(def, "AZURE-CA-1.02");

    assert_eq!(evidence[0].status_id, StatusId::Effective, "status: {}", evidence[0].status);
    assert!(evidence[0].findings.is_empty());
}

#[test]
fn ca102_fail_enabled_policy_missing_exclusion() {
    let policies = serde_json::json!({"value": [
        ca_policy_with_exclude_groups("enabled", vec!["break-glass-group"]),
        ca_policy_with_exclude_groups("enabled", vec![]),
    ]});
    let server = MockHTTPServer::new(vec![(200, policies.to_string())]);
    let def = load_check_with_mock_urls("AZURE-CA-1.02-emergency-access-exclusion.check.yaml", server.url());
    let evidence = run_observer(def, "AZURE-CA-1.02");

    assert_eq!(evidence[0].status_id, StatusId::Ineffective, "status: {}", evidence[0].status);
    assert!(!evidence[0].findings.is_empty());
}

// ===========================================================================
// AZURE-CA-2.03 — Require Compliant Devices for Admins
// ===========================================================================

fn ca_policy_compliant_device(state: &str, include_apps: Vec<&str>, controls: Vec<&str>) -> serde_json::Value {
    serde_json::json!({
        "id": "policy-admin-device",
        "displayName": "HTH-AdminPortal-ComplianceRequired",
        "state": state,
        "conditions": {
            "users": {"includeRoles": ["62e90394-69f5-4237-9190-012177145e10"]},
            "applications": {"includeApplications": include_apps}
        },
        "grantControls": {"operator": "AND", "builtInControls": controls}
    })
}

#[test]
fn ca203_pass_compliant_device_required_for_graph() {
    let policies = serde_json::json!({"value": [
        ca_policy_compliant_device(
            "enabled",
            vec!["c44b4083-3bb0-49c1-b47d-974e53cbdf3c", "00000003-0000-0000-c000-000000000000"],
            vec!["compliantDevice"],
        )
    ]});
    let server = MockHTTPServer::new(vec![(200, policies.to_string())]);
    let def = load_check_with_mock_urls("AZURE-CA-2.03-compliant-device-admins.check.yaml", server.url());
    let evidence = run_observer(def, "AZURE-CA-2.03");

    assert_eq!(evidence[0].status_id, StatusId::Effective, "status: {}", evidence[0].status);
}

#[test]
fn ca203_fail_graph_not_targeted() {
    // Policy exists and requires compliant device, but does not target Microsoft Graph.
    let policies = serde_json::json!({"value": [
        ca_policy_compliant_device(
            "enabled",
            vec!["c44b4083-3bb0-49c1-b47d-974e53cbdf3c"],
            vec!["compliantDevice"],
        )
    ]});
    let server = MockHTTPServer::new(vec![(200, policies.to_string())]);
    let def = load_check_with_mock_urls("AZURE-CA-2.03-compliant-device-admins.check.yaml", server.url());
    let evidence = run_observer(def, "AZURE-CA-2.03");

    assert_eq!(evidence[0].status_id, StatusId::Ineffective, "status: {}", evidence[0].status);
}

// ===========================================================================
// AZURE-CA-2.04 — Block High-Risk Sign-Ins
// ===========================================================================

fn ca_policy_risk(state: &str, risk_levels: Vec<&str>, controls: Vec<&str>) -> serde_json::Value {
    serde_json::json!({
        "id": "policy-risk",
        "displayName": "HTH: Block high-risk sign-ins",
        "state": state,
        "conditions": {
            "users": {"includeUsers": ["All"]},
            "applications": {"includeApplications": ["All"]},
            "signInRiskLevels": risk_levels
        },
        "grantControls": {"operator": "OR", "builtInControls": controls}
    })
}

#[test]
fn ca204_pass_high_risk_blocked() {
    let policies = serde_json::json!({"value": [ca_policy_risk("enabled", vec!["high"], vec!["block"])]});
    let server = MockHTTPServer::new(vec![(200, policies.to_string())]);
    let def = load_check_with_mock_urls("AZURE-CA-2.04-block-high-risk-signins.check.yaml", server.url());
    let evidence = run_observer(def, "AZURE-CA-2.04");

    assert_eq!(evidence[0].status_id, StatusId::Effective, "status: {}", evidence[0].status);
}

#[test]
fn ca204_fail_only_medium_risk_covered() {
    let policies = serde_json::json!({"value": [ca_policy_risk("enabled", vec!["medium"], vec!["mfa"])]});
    let server = MockHTTPServer::new(vec![(200, policies.to_string())]);
    let def = load_check_with_mock_urls("AZURE-CA-2.04-block-high-risk-signins.check.yaml", server.url());
    let evidence = run_observer(def, "AZURE-CA-2.04");

    assert_eq!(evidence[0].status_id, StatusId::Ineffective, "status: {}", evidence[0].status);
}

// ===========================================================================
// AZURE-PIM-3.02 — Configure Access Reviews
// ===========================================================================

#[test]
fn pim302_pass_review_exists() {
    let reviews = serde_json::json!({"value": [
        {"id": "review-1", "displayName": "Quarterly Privileged Role Review"}
    ]});
    let server = MockHTTPServer::new(vec![(200, reviews.to_string())]);
    let def = load_check_with_mock_urls("AZURE-PIM-3.02-access-reviews.check.yaml", server.url());
    let evidence = run_observer(def, "AZURE-PIM-3.02");

    assert_eq!(evidence[0].status_id, StatusId::Effective, "status: {}", evidence[0].status);
}

#[test]
fn pim302_fail_no_reviews() {
    let reviews = serde_json::json!({"value": []});
    let server = MockHTTPServer::new(vec![(200, reviews.to_string())]);
    let def = load_check_with_mock_urls("AZURE-PIM-3.02-access-reviews.check.yaml", server.url());
    let evidence = run_observer(def, "AZURE-PIM-3.02");

    assert_eq!(evidence[0].status_id, StatusId::Ineffective, "status: {}", evidence[0].status);
}

// ===========================================================================
// AZURE-PIM-3.03 — Restricted Management Administrative Units
// ===========================================================================

#[test]
fn pim303_pass_restricted_au_exists() {
    let units = serde_json::json!({"value": [
        {"id": "au-1", "displayName": "Protected Accounts", "isMemberManagementRestricted": true},
        {"id": "au-2", "displayName": "Regional AU", "isMemberManagementRestricted": false}
    ]});
    let server = MockHTTPServer::new(vec![(200, units.to_string())]);
    let def = load_check_with_mock_urls("AZURE-PIM-3.03-restricted-management-au.check.yaml", server.url());
    let evidence = run_observer(def, "AZURE-PIM-3.03");

    assert_eq!(evidence[0].status_id, StatusId::Effective, "status: {}", evidence[0].status);
}

#[test]
fn pim303_fail_no_restricted_au() {
    let units = serde_json::json!({"value": [
        {"id": "au-2", "displayName": "Regional AU", "isMemberManagementRestricted": false}
    ]});
    let server = MockHTTPServer::new(vec![(200, units.to_string())]);
    let def = load_check_with_mock_urls("AZURE-PIM-3.03-restricted-management-au.check.yaml", server.url());
    let evidence = run_observer(def, "AZURE-PIM-3.03");

    assert_eq!(evidence[0].status_id, StatusId::Ineffective, "status: {}", evidence[0].status);
}

// ===========================================================================
// AZURE-APP-4.01 — Restrict User Consent to Applications
// ===========================================================================

#[test]
fn app401_pass_no_grant_policies_assigned() {
    let policy = serde_json::json!({
        "defaultUserRolePermissions": {"permissionGrantPoliciesAssigned": []}
    });
    let server = MockHTTPServer::new(vec![(200, policy.to_string())]);
    let def = load_check_with_mock_urls("AZURE-APP-4.01-restrict-user-consent.check.yaml", server.url());
    let evidence = run_observer(def, "AZURE-APP-4.01");

    assert_eq!(evidence[0].status_id, StatusId::Effective, "status: {}", evidence[0].status);
}

#[test]
fn app401_fail_grant_policy_assigned() {
    let policy = serde_json::json!({
        "defaultUserRolePermissions": {"permissionGrantPoliciesAssigned": ["ManagePermissionGrantsForSelf.microsoft-user-default-legacy"]}
    });
    let server = MockHTTPServer::new(vec![(200, policy.to_string())]);
    let def = load_check_with_mock_urls("AZURE-APP-4.01-restrict-user-consent.check.yaml", server.url());
    let evidence = run_observer(def, "AZURE-APP-4.01");

    assert_eq!(evidence[0].status_id, StatusId::Ineffective, "status: {}", evidence[0].status);
}

// ===========================================================================
// AZURE-APP-4.03 — Retire Azure AD Graph API Usage
// ===========================================================================

#[test]
fn app403_pass_no_legacy_signins() {
    let signins = serde_json::json!({"value": []});
    let server = MockHTTPServer::new(vec![(200, signins.to_string())]);
    let def = load_check_with_mock_urls("AZURE-APP-4.03-retire-azure-ad-graph.check.yaml", server.url());
    let evidence = run_observer(def, "AZURE-APP-4.03");

    assert_eq!(evidence[0].status_id, StatusId::Effective, "status: {}", evidence[0].status);
}

#[test]
fn app403_fail_legacy_signin_found() {
    let signins = serde_json::json!({"value": [
        {"id": "signin-1", "appId": "00000002-0000-0000-c000-000000000000", "appDisplayName": "Windows Azure Active Directory"}
    ]});
    let server = MockHTTPServer::new(vec![(200, signins.to_string())]);
    let def = load_check_with_mock_urls("AZURE-APP-4.03-retire-azure-ad-graph.check.yaml", server.url());
    let evidence = run_observer(def, "AZURE-APP-4.03");

    assert_eq!(evidence[0].status_id, StatusId::Ineffective, "status: {}", evidence[0].status);
}

// ===========================================================================
// AZURE-MON-5.01 — Export Entra ID Sign-In and Audit Logs
// ===========================================================================

#[test]
fn mon501_pass_signin_logs_exported() {
    let settings = serde_json::json!({"value": [
        {
            "id": "diag-1",
            "name": "Send to Log Analytics",
            "properties": {
                "workspaceId": "/subscriptions/x/resourceGroups/y/providers/Microsoft.OperationalInsights/workspaces/z",
                "logs": [
                    {"category": "SignInLogs", "enabled": true},
                    {"category": "AuditLogs", "enabled": true}
                ]
            }
        }
    ]});
    let server = MockHTTPServer::new(vec![(200, settings.to_string())]);
    let def = load_check_with_mock_urls("AZURE-MON-5.01-export-signin-audit-logs.check.yaml", server.url());
    let evidence = run_observer(def, "AZURE-MON-5.01");

    assert_eq!(evidence.len(), 2);
    for ev in &evidence {
        assert_eq!(ev.status_id, StatusId::Effective, "status: {}", ev.status);
    }
}

#[test]
fn mon501_fail_no_diagnostic_setting() {
    let settings = serde_json::json!({"value": []});
    let server = MockHTTPServer::new(vec![(200, settings.to_string())]);
    let def = load_check_with_mock_urls("AZURE-MON-5.01-export-signin-audit-logs.check.yaml", server.url());
    let evidence = run_observer(def, "AZURE-MON-5.01");

    assert_eq!(evidence.len(), 2);
    for ev in &evidence {
        assert_eq!(ev.status_id, StatusId::Ineffective, "status: {}", ev.status);
    }
}

#[test]
fn mon501_fail_signin_logs_category_not_enabled() {
    // Diagnostic setting exists but only exports AuditLogs, not SignInLogs.
    let settings = serde_json::json!({"value": [
        {
            "id": "diag-1",
            "name": "Partial export",
            "properties": {
                "logs": [
                    {"category": "AuditLogs", "enabled": true}
                ]
            }
        }
    ]});
    let server = MockHTTPServer::new(vec![(200, settings.to_string())]);
    let def = load_check_with_mock_urls("AZURE-MON-5.01-export-signin-audit-logs.check.yaml", server.url());
    let evidence = run_observer(def, "AZURE-MON-5.01");

    assert_eq!(evidence.len(), 2);
    assert_eq!(evidence[0].status_id, StatusId::Effective); // diagnostic_setting_exists
    assert_eq!(evidence[1].status_id, StatusId::Ineffective); // signin_logs_category_enabled
}

// ===========================================================================
// AZURE-MON-5.02 — Monitor Identity Secure Score
// ===========================================================================

#[test]
fn mon502_pass_score_above_target() {
    let scores = serde_json::json!({"value": [
        {"id": "score-1", "currentScore": 75.5, "maxScore": 100.0}
    ]});
    let server = MockHTTPServer::new(vec![(200, scores.to_string())]);
    let def = load_check_with_mock_urls("AZURE-MON-5.02-identity-secure-score.check.yaml", server.url());
    let evidence = run_observer(def, "AZURE-MON-5.02");

    assert_eq!(evidence[0].status_id, StatusId::Effective, "status: {}", evidence[0].status);
}

#[test]
fn mon502_fail_score_below_target() {
    let scores = serde_json::json!({"value": [
        {"id": "score-1", "currentScore": 42.0, "maxScore": 100.0}
    ]});
    let server = MockHTTPServer::new(vec![(200, scores.to_string())]);
    let def = load_check_with_mock_urls("AZURE-MON-5.02-identity-secure-score.check.yaml", server.url());
    let evidence = run_observer(def, "AZURE-MON-5.02");

    assert_eq!(evidence[0].status_id, StatusId::Ineffective, "status: {}", evidence[0].status);
}

// ===========================================================================
// Load-all test: every checks/azure/*.check.yaml must parse and have a
// unique id.
// ===========================================================================

#[test]
fn all_azure_checks_load_and_have_unique_ids() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("checks/azure");
    let mut ids = std::collections::HashSet::new();
    let mut count = 0;
    for entry in std::fs::read_dir(&dir).expect("read checks/azure dir") {
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
        count += 1;
    }
    assert!(count >= 8, "expected at least the original 8 azure checks, found {count}");
}
