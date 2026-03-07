use std::collections::HashMap;

use anyhow::{anyhow, Result};
use chrono::Utc;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId,
};
use crate::module::{observer::Observer, CredentialReq, Module};

// ─── Microsoft Graph HTTP helpers ────────────────────────────────────────────

/// Performs an authenticated GET to the Microsoft Graph API.
/// `base_url` defaults to `https://graph.microsoft.com` but can be overridden
/// via `AZURE_BASE_URL` for testing with a mock server.
fn graph_get(token: &str, base_url: &str, path: &str) -> Result<(Value, u16)> {
    let url = format!("{}{}", base_url.trim_end_matches('/'), path);
    let resp = ureq::get(&url)
        .set("Authorization", &format!("Bearer {}", token))
        .set("Accept", "application/json")
        .call();

    match resp {
        Ok(r) => {
            let status = r.status();
            let body: Value = r
                .into_json()
                .map_err(|e| anyhow!("parsing Graph JSON: {}", e))?;
            Ok((body, status))
        }
        Err(ureq::Error::Status(code, r)) => {
            let body: Value = r
                .into_json()
                .unwrap_or_else(|_| json!({"error": {"code": "unknown", "message": "error"}}));
            Ok((body, code))
        }
        Err(e) => Err(anyhow!("Graph API request failed: {}", e)),
    }
}

/// Obtains an OAuth2 access token via client credentials flow.
/// `login_base` defaults to `https://login.microsoftonline.com` but can be
/// overridden via `AZURE_LOGIN_BASE` for testing.
fn get_access_token(
    tenant_id: &str,
    client_id: &str,
    client_secret: &str,
    login_base: &str,
) -> Result<String> {
    let url = format!(
        "{}/{}/oauth2/v2.0/token",
        login_base.trim_end_matches('/'),
        tenant_id
    );

    let resp = ureq::post(&url)
        .set("Content-Type", "application/x-www-form-urlencoded")
        .send_string(&format!(
            "grant_type=client_credentials&client_id={}&client_secret={}&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default",
            client_id, client_secret
        ));

    match resp {
        Ok(r) => {
            let body: Value = r
                .into_json()
                .map_err(|e| anyhow!("parsing token JSON: {}", e))?;
            body.get("access_token")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .ok_or_else(|| anyhow!("no access_token in token response"))
        }
        Err(ureq::Error::Status(code, _)) => {
            Err(anyhow!("token request failed with HTTP {}", code))
        }
        Err(e) => Err(anyhow!("token request failed: {}", e)),
    }
}

/// Fetches all pages of a paginated Graph API collection.
fn graph_get_all_pages(token: &str, base_url: &str, path: &str) -> Result<Vec<Value>> {
    let mut all_items: Vec<Value> = Vec::new();
    let (body, status) = graph_get(token, base_url, path)?;

    if status != 200 {
        return Err(anyhow!(
            "Graph API returned status {} querying {}",
            status,
            path
        ));
    }

    if let Some(items) = body.get("value").and_then(|v| v.as_array()) {
        all_items.extend(items.iter().cloned());
    }

    // Follow @odata.nextLink for pagination.
    let mut next_link = body
        .get("@odata.nextLink")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    while let Some(link) = next_link.take() {
        // nextLink is a full URL; strip base_url prefix to get the path.
        let next_path = if link.starts_with(base_url.trim_end_matches('/')) {
            link[base_url.trim_end_matches('/').len()..].to_string()
        } else {
            // For mock servers, the nextLink may be a full URL already.
            link.clone()
        };

        let (page_body, page_status) = if next_path.starts_with("http") {
            // Full URL — call directly.
            let resp = ureq::get(&next_path)
                .set("Authorization", &format!("Bearer {}", token))
                .set("Accept", "application/json")
                .call();
            match resp {
                Ok(r) => {
                    let s = r.status();
                    let b: Value = r.into_json().map_err(|e| anyhow!("parsing JSON: {}", e))?;
                    (b, s)
                }
                Err(ureq::Error::Status(code, r)) => {
                    let b: Value = r.into_json().unwrap_or(json!({}));
                    (b, code)
                }
                Err(e) => return Err(anyhow!("pagination request failed: {}", e)),
            }
        } else {
            graph_get(token, base_url, &next_path)?
        };

        if page_status != 200 {
            break;
        }

        if let Some(items) = page_body.get("value").and_then(|v| v.as_array()) {
            all_items.extend(items.iter().cloned());
        }

        next_link = page_body
            .get("@odata.nextLink")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
    }

    Ok(all_items)
}

// ─── ConditionalAccessObserver ───────────────────────────────────────────────

/// Queries Microsoft Graph API for Azure AD / Entra ID Conditional Access
/// policies and normalizes them into OCEAN evidence. Generates findings for
/// disabled policies or policies without MFA grant controls.
///
/// Required config: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`.
/// Optional: `AZURE_BASE_URL` (Graph API override), `AZURE_LOGIN_BASE` (login override).
pub struct ConditionalAccessObserver;

impl Module for ConditionalAccessObserver {
    fn id(&self) -> &str {
        "azure.conditional_access"
    }
    fn name(&self) -> &str {
        "Azure AD Conditional Access Observer"
    }
    fn version(&self) -> &str {
        "0.1.0"
    }
    fn source_system(&self) -> &str {
        "azure_ad"
    }
    fn evidence_types(&self) -> &[i32] {
        &[1001]
    }

    fn credential_requirements(&self) -> Vec<CredentialReq> {
        vec![
            CredentialReq {
                name: "AZURE_TENANT_ID".to_string(),
                cred_type: "tenant_id".to_string(),
                description: "Azure AD tenant ID".to_string(),
                required: true,
            },
            CredentialReq {
                name: "AZURE_CLIENT_ID".to_string(),
                cred_type: "client_id".to_string(),
                description: "App registration client ID".to_string(),
                required: true,
            },
            CredentialReq {
                name: "AZURE_CLIENT_SECRET".to_string(),
                cred_type: "client_secret".to_string(),
                description: "App registration client secret".to_string(),
                required: true,
            },
        ]
    }
}

impl Observer for ConditionalAccessObserver {
    fn observe(&self, config: &HashMap<String, String>) -> Result<Vec<Evidence>> {
        let tenant_id = config
            .get("AZURE_TENANT_ID")
            .ok_or_else(|| anyhow!("AZURE_TENANT_ID is required"))?;
        let client_id = config
            .get("AZURE_CLIENT_ID")
            .ok_or_else(|| anyhow!("AZURE_CLIENT_ID is required"))?;
        let client_secret = config
            .get("AZURE_CLIENT_SECRET")
            .ok_or_else(|| anyhow!("AZURE_CLIENT_SECRET is required"))?;

        let graph_base = config
            .get("AZURE_BASE_URL")
            .cloned()
            .unwrap_or_else(|| "https://graph.microsoft.com".to_string());
        let login_base = config
            .get("AZURE_LOGIN_BASE")
            .cloned()
            .unwrap_or_else(|| "https://login.microsoftonline.com".to_string());

        let now = Utc::now();
        let path = "/v1.0/identity/conditionalAccess/policies";
        let endpoint = format!("{}{}", graph_base.trim_end_matches('/'), path);

        // Obtain access token.
        let token = get_access_token(tenant_id, client_id, client_secret, &login_base)?;

        // Fetch all CA policies (with pagination).
        let policies = graph_get_all_pages(&token, &graph_base, path)?;

        let mut findings: Vec<Finding> = Vec::new();
        let mut observables: Vec<Observable> = Vec::new();
        let mut disabled_count = 0usize;
        let mut policies_without_mfa = 0usize;
        let mut mfa_policy_count = 0usize;
        let mut device_compliance_count = 0usize;
        let mut sign_in_risk_count = 0usize;

        for policy in &policies {
            let display_name = policy
                .get("displayName")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let state = policy
                .get("state")
                .and_then(|v| v.as_str())
                .unwrap_or("disabled");
            let policy_id = policy
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");

            observables.push(Observable {
                obs_type: "resource".to_string(),
                value: format!("ca_policy:{}", policy_id),
                name: String::new(),
            });

            if state != "enabled" {
                disabled_count += 1;
                findings.push(Finding {
                    title: "Disabled Conditional Access Policy".to_string(),
                    description: format!(
                        "CA policy {:?} is in state {:?} instead of enabled",
                        display_name, state
                    ),
                    severity_id: 3,
                });
                continue;
            }

            // Check grant controls for MFA requirement.
            let grant_controls = policy.get("grantControls");
            let has_mfa = grant_controls
                .and_then(|gc| gc.get("builtInControls"))
                .and_then(|c| c.as_array())
                .map(|controls| controls.iter().any(|c| c.as_str() == Some("mfa")))
                .unwrap_or(false);

            // Check for device compliance.
            let has_device_compliance = grant_controls
                .and_then(|gc| gc.get("builtInControls"))
                .and_then(|c| c.as_array())
                .map(|controls| {
                    controls
                        .iter()
                        .any(|c| c.as_str() == Some("compliantDevice"))
                })
                .unwrap_or(false);

            // Check for sign-in risk conditions.
            let has_sign_in_risk = policy
                .get("conditions")
                .and_then(|c| c.get("signInRiskLevels"))
                .and_then(|r| r.as_array())
                .map(|levels| !levels.is_empty())
                .unwrap_or(false);

            if has_mfa {
                mfa_policy_count += 1;
            }
            if has_device_compliance {
                device_compliance_count += 1;
            }
            if has_sign_in_risk {
                sign_in_risk_count += 1;
            }

            if !has_mfa && !has_device_compliance {
                policies_without_mfa += 1;
                findings.push(Finding {
                    title: "No MFA or Device Compliance Required".to_string(),
                    description: format!(
                        "CA policy {:?} does not require MFA or device compliance in grant controls",
                        display_name
                    ),
                    severity_id: 2,
                });
            }
        }

        if findings.is_empty() {
            findings.push(Finding {
                title: "Conditional Access Policies Compliant".to_string(),
                description: format!(
                    "All {} CA policies are enabled with MFA or device compliance controls",
                    policies.len()
                ),
                severity_id: 0,
            });
        }

        let (status_id, status_text) = if disabled_count > 0 || policies_without_mfa > 0 {
            (
                StatusId::Ineffective,
                format!(
                    "{} disabled CA policies, {} without MFA/device compliance out of {} total",
                    disabled_count,
                    policies_without_mfa,
                    policies.len()
                ),
            )
        } else if policies.is_empty() {
            (
                StatusId::Ineffective,
                "No Conditional Access policies found".to_string(),
            )
        } else {
            (
                StatusId::Effective,
                format!(
                    "All {} CA policies are enabled with appropriate grant controls",
                    policies.len()
                ),
            )
        };

        let raw_data = json!({
            "total_policies": policies.len(),
            "disabled_policies": disabled_count,
            "policies_without_mfa": policies_without_mfa,
            "mfa_policy_count": mfa_policy_count,
            "device_compliance_count": device_compliance_count,
            "sign_in_risk_count": sign_in_risk_count,
            "policies": Value::Array(policies),
        });

        Ok(vec![Evidence {
            id: Uuid::new_v4(),
            control_id: "conditional_access.policy".to_string(),
            class_uid: 1001,
            category_uid: 1,
            activity_id: 1,
            time: now,
            confidence_level: ConfidenceLevel::PassiveObservation,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "azure.conditional_access".to_string(),
                    version: "0.1.0".to_string(),
                    module_type: "observer".to_string(),
                },
                source: SourceInfo {
                    system: "azure_ad".to_string(),
                    api_version: "v1.0".to_string(),
                    endpoint,
                },
                original_time: None,
                processed_time: now,
                safety_classification: None,
            },
            observables,
            status_id,
            status: status_text,
            raw_data,
            findings,
            test_transcript: None,
            enrichments: vec![],
        }])
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny HTTP server that responds to multiple requests (token + API calls).
    /// Returns responses in order from a provided list.
    fn mock_server_multi(responses: Vec<(u16, String)>) -> String {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::{Arc, Mutex};
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let responses = Arc::new(Mutex::new(responses.into_iter()));

        thread::spawn(move || {
            for stream_result in listener.incoming() {
                let Ok(mut stream) = stream_result else {
                    break;
                };
                let mut buf = [0u8; 8192];
                let _ = stream.read(&mut buf);

                let (status, body) = {
                    let mut iter = responses.lock().unwrap();
                    iter.next()
                        .unwrap_or((500, r#"{"error":"no more responses"}"#.to_string()))
                };

                let resp = format!(
                    "HTTP/1.1 {} OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                    status,
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.shutdown(std::net::Shutdown::Write);
                let mut drain = [0u8; 256];
                while matches!(stream.read(&mut drain), Ok(n) if n > 0) {}
            }
        });

        format!("http://127.0.0.1:{}", addr.port())
    }

    fn token_response() -> (u16, String) {
        (
            200,
            r#"{"access_token":"mock_token","token_type":"Bearer","expires_in":3600}"#.to_string(),
        )
    }

    fn base_config(base_url: &str) -> HashMap<String, String> {
        HashMap::from([
            ("AZURE_TENANT_ID".to_string(), "test-tenant".to_string()),
            ("AZURE_CLIENT_ID".to_string(), "test-client".to_string()),
            (
                "AZURE_CLIENT_SECRET".to_string(),
                "test-secret".to_string(),
            ),
            ("AZURE_BASE_URL".to_string(), base_url.to_string()),
            ("AZURE_LOGIN_BASE".to_string(), base_url.to_string()),
        ])
    }

    const ENABLED_MFA_POLICY: &str = r#"{"value":[
        {
            "id": "ca1",
            "displayName": "Require MFA for all users",
            "state": "enabled",
            "conditions": {
                "users": {"includeUsers": ["All"]},
                "signInRiskLevels": []
            },
            "grantControls": {
                "operator": "OR",
                "builtInControls": ["mfa"]
            }
        }
    ]}"#;

    const DISABLED_POLICY: &str = r#"{"value":[
        {
            "id": "ca2",
            "displayName": "Old Policy",
            "state": "disabled",
            "conditions": {},
            "grantControls": {
                "operator": "OR",
                "builtInControls": ["mfa"]
            }
        }
    ]}"#;

    const NO_MFA_POLICY: &str = r#"{"value":[
        {
            "id": "ca3",
            "displayName": "Block Legacy Auth",
            "state": "enabled",
            "conditions": {},
            "grantControls": {
                "operator": "OR",
                "builtInControls": ["block"]
            }
        }
    ]}"#;

    const DEVICE_COMPLIANCE_POLICY: &str = r#"{"value":[
        {
            "id": "ca4",
            "displayName": "Require Compliant Device",
            "state": "enabled",
            "conditions": {},
            "grantControls": {
                "operator": "OR",
                "builtInControls": ["compliantDevice"]
            }
        }
    ]}"#;

    const SIGN_IN_RISK_POLICY: &str = r#"{"value":[
        {
            "id": "ca5",
            "displayName": "Block High Risk Sign-ins",
            "state": "enabled",
            "conditions": {
                "signInRiskLevels": ["high", "medium"]
            },
            "grantControls": {
                "operator": "OR",
                "builtInControls": ["mfa"]
            }
        }
    ]}"#;

    const EMPTY_POLICIES: &str = r#"{"value":[]}"#;

    // ── Metadata ─────────────────────────────────────────────────────────────

    #[test]
    fn ca_observer_id() {
        assert_eq!(ConditionalAccessObserver.id(), "azure.conditional_access");
    }

    #[test]
    fn ca_observer_name() {
        assert_eq!(
            ConditionalAccessObserver.name(),
            "Azure AD Conditional Access Observer"
        );
    }

    #[test]
    fn ca_observer_version() {
        assert_eq!(ConditionalAccessObserver.version(), "0.1.0");
    }

    #[test]
    fn ca_observer_source_system() {
        assert_eq!(ConditionalAccessObserver.source_system(), "azure_ad");
    }

    #[test]
    fn ca_observer_evidence_types() {
        assert_eq!(ConditionalAccessObserver.evidence_types(), &[1001]);
    }

    #[test]
    fn ca_observer_credential_requirements() {
        let reqs = ConditionalAccessObserver.credential_requirements();
        assert_eq!(reqs.len(), 3);
        assert!(reqs
            .iter()
            .any(|r| r.name == "AZURE_TENANT_ID" && r.required));
        assert!(reqs
            .iter()
            .any(|r| r.name == "AZURE_CLIENT_ID" && r.required));
        assert!(reqs
            .iter()
            .any(|r| r.name == "AZURE_CLIENT_SECRET" && r.required));
    }

    // ── Config validation ────────────────────────────────────────────────────

    #[test]
    fn missing_tenant_id_errors() {
        let config = HashMap::from([
            ("AZURE_CLIENT_ID".to_string(), "c".to_string()),
            ("AZURE_CLIENT_SECRET".to_string(), "s".to_string()),
        ]);
        let err = ConditionalAccessObserver.observe(&config).unwrap_err();
        assert!(err.to_string().contains("AZURE_TENANT_ID"));
    }

    #[test]
    fn missing_client_id_errors() {
        let config = HashMap::from([
            ("AZURE_TENANT_ID".to_string(), "t".to_string()),
            ("AZURE_CLIENT_SECRET".to_string(), "s".to_string()),
        ]);
        let err = ConditionalAccessObserver.observe(&config).unwrap_err();
        assert!(err.to_string().contains("AZURE_CLIENT_ID"));
    }

    #[test]
    fn missing_client_secret_errors() {
        let config = HashMap::from([
            ("AZURE_TENANT_ID".to_string(), "t".to_string()),
            ("AZURE_CLIENT_ID".to_string(), "c".to_string()),
        ]);
        let err = ConditionalAccessObserver.observe(&config).unwrap_err();
        assert!(err.to_string().contains("AZURE_CLIENT_SECRET"));
    }

    // ── HTTP integration ─────────────────────────────────────────────────────

    #[test]
    fn enabled_mfa_policy_is_effective() {
        let srv = mock_server_multi(vec![
            token_response(),
            (200, ENABLED_MFA_POLICY.to_string()),
        ]);
        let ev = &ConditionalAccessObserver
            .observe(&base_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert_eq!(ev.control_id, "conditional_access.policy");
        assert_eq!(ev.class_uid, 1001);
        assert_eq!(ev.observables.len(), 1);
    }

    #[test]
    fn disabled_policy_is_ineffective() {
        let srv = mock_server_multi(vec![
            token_response(),
            (200, DISABLED_POLICY.to_string()),
        ]);
        let ev = &ConditionalAccessObserver
            .observe(&base_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "Disabled Conditional Access Policy"));
    }

    #[test]
    fn no_mfa_policy_is_ineffective() {
        let srv = mock_server_multi(vec![
            token_response(),
            (200, NO_MFA_POLICY.to_string()),
        ]);
        let ev = &ConditionalAccessObserver
            .observe(&base_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "No MFA or Device Compliance Required"));
    }

    #[test]
    fn device_compliance_policy_is_effective() {
        let srv = mock_server_multi(vec![
            token_response(),
            (200, DEVICE_COMPLIANCE_POLICY.to_string()),
        ]);
        let ev = &ConditionalAccessObserver
            .observe(&base_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert_eq!(ev.raw_data["device_compliance_count"], 1);
    }

    #[test]
    fn sign_in_risk_policy_counted() {
        let srv = mock_server_multi(vec![
            token_response(),
            (200, SIGN_IN_RISK_POLICY.to_string()),
        ]);
        let ev = &ConditionalAccessObserver
            .observe(&base_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.raw_data["sign_in_risk_count"], 1);
    }

    #[test]
    fn empty_policies_is_ineffective() {
        let srv = mock_server_multi(vec![
            token_response(),
            (200, EMPTY_POLICIES.to_string()),
        ]);
        let ev = &ConditionalAccessObserver
            .observe(&base_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev.status.contains("No Conditional Access policies"));
    }

    #[test]
    fn api_error_returns_err() {
        let srv = mock_server_multi(vec![
            token_response(),
            (
                403,
                r#"{"error":{"code":"Authorization_RequestDenied","message":"Forbidden"}}"#
                    .to_string(),
            ),
        ]);
        let result = ConditionalAccessObserver.observe(&base_config(&srv));
        assert!(result.is_err());
    }

    #[test]
    fn token_error_returns_err() {
        let srv = mock_server_multi(vec![(
            401,
            r#"{"error":"invalid_client","error_description":"bad secret"}"#.to_string(),
        )]);
        let result = ConditionalAccessObserver.observe(&base_config(&srv));
        assert!(result.is_err());
    }

    #[test]
    fn raw_data_has_expected_keys() {
        let srv = mock_server_multi(vec![
            token_response(),
            (200, ENABLED_MFA_POLICY.to_string()),
        ]);
        let ev = &ConditionalAccessObserver
            .observe(&base_config(&srv))
            .unwrap()[0];
        assert!(ev.raw_data.get("total_policies").is_some());
        assert!(ev.raw_data.get("disabled_policies").is_some());
        assert!(ev.raw_data.get("policies_without_mfa").is_some());
        assert!(ev.raw_data.get("mfa_policy_count").is_some());
    }

    #[test]
    fn observer_does_not_set_test_transcript() {
        let srv = mock_server_multi(vec![
            token_response(),
            (200, EMPTY_POLICIES.to_string()),
        ]);
        let ev = &ConditionalAccessObserver
            .observe(&base_config(&srv))
            .unwrap()[0];
        assert!(ev.test_transcript.is_none());
    }

    // ── Pagination ───────────────────────────────────────────────────────────

    #[test]
    fn handles_pagination() {
        // We need the mock server URL in the nextLink, so build dynamically.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let base = format!("http://127.0.0.1:{}", addr.port());

        let page1 = format!(
            r#"{{"value":[{{"id":"ca1","displayName":"P1","state":"enabled","conditions":{{}},"grantControls":{{"operator":"OR","builtInControls":["mfa"]}}}}],"@odata.nextLink":"{}/v1.0/identity/conditionalAccess/policies?$skiptoken=page2"}}"#,
            base
        );
        let page2 = r#"{"value":[{"id":"ca2","displayName":"P2","state":"enabled","conditions":{},"grantControls":{"operator":"OR","builtInControls":["mfa"]}}]}"#;

        let responses = vec![
            token_response(),
            (200, page1),
            (200, page2.to_string()),
        ];

        use std::io::{Read, Write};
        use std::sync::{Arc, Mutex};
        use std::thread;

        let responses = Arc::new(Mutex::new(responses.into_iter()));

        thread::spawn(move || {
            for stream_result in listener.incoming() {
                let Ok(mut stream) = stream_result else {
                    break;
                };
                let mut buf = [0u8; 8192];
                let _ = stream.read(&mut buf);

                let (status, body) = {
                    let mut iter = responses.lock().unwrap();
                    iter.next()
                        .unwrap_or((500, r#"{"error":"done"}"#.to_string()))
                };

                let resp = format!(
                    "HTTP/1.1 {} OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                    status,
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.shutdown(std::net::Shutdown::Write);
                let mut drain = [0u8; 256];
                while matches!(stream.read(&mut drain), Ok(n) if n > 0) {}
            }
        });

        let ev = &ConditionalAccessObserver
            .observe(&base_config(&base))
            .unwrap()[0];
        assert_eq!(ev.raw_data["total_policies"], 2);
        assert_eq!(ev.observables.len(), 2);
        assert_eq!(ev.status_id, StatusId::Effective);
    }
}
