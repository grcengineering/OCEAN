use std::collections::HashMap;

use anyhow::{anyhow, Result};
use chrono::Utc;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId,
};
use crate::module::{observer::Observer, CredentialReq, Module};

// ─── Microsoft Graph HTTP helpers ─────────────────────────────────────────────

/// Obtains a bearer token via the client-credentials flow.
///
/// `login_base_url` defaults to `https://login.microsoftonline.com` and can be
/// overridden via `AZURE_LOGIN_BASE_URL` for test mocking.
fn get_token(
    tenant_id: &str,
    client_id: &str,
    client_secret: &str,
    login_base_url: &str,
) -> Result<String> {
    let url = format!(
        "{}/{}/oauth2/v2.0/token",
        login_base_url.trim_end_matches('/'),
        tenant_id
    );
    let body = format!(
        "grant_type=client_credentials&client_id={}&client_secret={}&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default",
        client_id, client_secret
    );
    let resp = ureq::post(&url)
        .set("Content-Type", "application/x-www-form-urlencoded")
        .send_string(&body)
        .map_err(|e| anyhow!("Azure token request failed: {}", e))?;

    let data: Value = resp
        .into_json()
        .map_err(|e| anyhow!("parsing Azure token response: {}", e))?;

    data.get("access_token")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| {
            let err = data
                .get("error_description")
                .or_else(|| data.get("error"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error");
            anyhow!("Azure token response missing access_token: {}", err)
        })
}

/// Performs an authenticated GET against the Microsoft Graph API.
///
/// `graph_base_url` defaults to `https://graph.microsoft.com` and can be
/// overridden via `AZURE_GRAPH_BASE_URL` for test mocking.
fn graph_get(token: &str, graph_base_url: &str, path: &str) -> Result<(Value, u16)> {
    let url = format!("{}{}", graph_base_url.trim_end_matches('/'), path);
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
                .unwrap_or_else(|_| json!({"error": "unknown"}));
            Ok((body, code))
        }
        Err(e) => Err(anyhow!("Graph API request failed: {}", e)),
    }
}

// ─── ConditionalAccessObserver ────────────────────────────────────────────────

/// Queries Microsoft Entra ID (Azure AD) Conditional Access policies via the
/// Graph API and normalizes them into OCEAN evidence.
///
/// Generates findings for:
/// - Disabled policies
/// - Enabled policies that do not require MFA (missing `mfa` grant control)
///
/// Required config: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`.
/// Optional: `AZURE_LOGIN_BASE_URL` (default: `https://login.microsoftonline.com`),
///           `AZURE_GRAPH_BASE_URL`  (default: `https://graph.microsoft.com`).
pub struct ConditionalAccessObserver;

impl Module for ConditionalAccessObserver {
    fn id(&self) -> &str {
        "azure.conditional_access"
    }
    fn name(&self) -> &str {
        "Azure Conditional Access Observer"
    }
    fn version(&self) -> &str {
        "0.1.0"
    }
    fn source_system(&self) -> &str {
        "azure"
    }
    fn evidence_types(&self) -> &[i32] {
        &[1001]
    }

    fn credential_requirements(&self) -> Vec<CredentialReq> {
        vec![
            CredentialReq {
                name: "AZURE_TENANT_ID".to_string(),
                cred_type: "tenant_id".to_string(),
                description: "Azure AD tenant ID (GUID or domain)".to_string(),
                required: true,
            },
            CredentialReq {
                name: "AZURE_CLIENT_ID".to_string(),
                cred_type: "client_id".to_string(),
                description: "App registration client ID with Policy.Read.All permission"
                    .to_string(),
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

        let login_base_url = config
            .get("AZURE_LOGIN_BASE_URL")
            .map(|s| s.as_str())
            .unwrap_or("https://login.microsoftonline.com");
        let graph_base_url = config
            .get("AZURE_GRAPH_BASE_URL")
            .map(|s| s.as_str())
            .unwrap_or("https://graph.microsoft.com");

        let now = Utc::now();
        let path = "/v1.0/identity/conditionalAccess/policies";
        let endpoint = format!("{}{}", graph_base_url.trim_end_matches('/'), path);

        let token = get_token(tenant_id, client_id, client_secret, login_base_url)?;
        let (body, status) = graph_get(&token, graph_base_url, path)?;

        if status != 200 {
            return Err(anyhow!(
                "Graph API returned status {} querying Conditional Access policies",
                status
            ));
        }

        let policies = body
            .get("value")
            .and_then(|v| v.as_array())
            .ok_or_else(|| anyhow!("expected 'value' array from Graph CA policies endpoint"))?;

        let mut findings: Vec<Finding> = Vec::new();
        let mut observables: Vec<Observable> = Vec::new();
        let mut disabled_count = 0usize;
        let mut no_mfa_count = 0usize;

        for policy in policies {
            let name = policy
                .get("displayName")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let policy_id = policy
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let state = policy
                .get("state")
                .and_then(|v| v.as_str())
                .unwrap_or("disabled");

            observables.push(Observable {
                obs_type: "resource".to_string(),
                value: format!("policy:{}", policy_id),
                name: String::new(),
            });

            if state != "enabled" {
                disabled_count += 1;
                findings.push(Finding {
                    title: "Disabled Conditional Access Policy".to_string(),
                    description: format!(
                        "Conditional Access policy {:?} is in state {:?} instead of enabled",
                        name, state
                    ),
                    severity_id: 2,
                });
                continue;
            }

            // Check whether the grant controls include "mfa".
            let requires_mfa = policy
                .get("grantControls")
                .and_then(|gc| gc.get("builtInControls"))
                .and_then(|c| c.as_array())
                .map(|controls| {
                    controls
                        .iter()
                        .any(|c| c.as_str() == Some("mfa") || c.as_str() == Some("compliantDevice"))
                })
                .unwrap_or(false);

            if !requires_mfa {
                no_mfa_count += 1;
                findings.push(Finding {
                    title: "Conditional Access Policy Lacks MFA Requirement".to_string(),
                    description: format!(
                        "Enabled policy {:?} does not include 'mfa' or 'compliantDevice' in grant controls",
                        name
                    ),
                    severity_id: 2,
                });
            }
        }

        if findings.is_empty() {
            findings.push(Finding {
                title: "Conditional Access Policies Compliant".to_string(),
                description: format!(
                    "All {} Conditional Access policies are enabled and require MFA",
                    policies.len()
                ),
                severity_id: 0,
            });
        }

        let (status_id, status_text) = if disabled_count > 0 || no_mfa_count > 0 {
            (
                StatusId::Ineffective,
                format!(
                    "{} disabled policies, {} without MFA requirement out of {} total",
                    disabled_count,
                    no_mfa_count,
                    policies.len()
                ),
            )
        } else {
            (
                StatusId::Effective,
                format!(
                    "All {} Conditional Access policies are enabled and require MFA",
                    policies.len()
                ),
            )
        };

        let raw_data = json!({
            "total_policies": policies.len(),
            "disabled_policies": disabled_count,
            "policies_without_mfa_requirement": no_mfa_count,
            "policies": policies,
        });

        Ok(vec![Evidence {
            id: Uuid::new_v4(),
            control_id: "iam.mfa_enforcement".to_string(),
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
                    system: "azure".to_string(),
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

    /// Spawns a single-request HTTP mock server. Returns the base URL.
    ///
    /// Handles two sequential requests on two separate connections so that the
    /// observer can first hit the token endpoint and then the Graph endpoint,
    /// both served by the same mock port (the token endpoint is ignored/stubbed
    /// by routing on path prefix in the real impl; here we just return the body
    /// twice for simplicity by accepting a second connection).
    fn mock_server(token_body: &str, graph_body: &str) -> String {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let token_body = token_body.to_string();
        let graph_body = graph_body.to_string();

        thread::spawn(move || {
            for body in [&token_body, &graph_body] {
                if let Ok((mut stream, _)) = listener.accept() {
                    let mut buf = [0u8; 8192];
                    let _ = stream.read(&mut buf);
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
                        len = body.len()
                    );
                    let _ = stream.write_all(resp.as_bytes());
                    let _ = stream.shutdown(std::net::Shutdown::Write);
                    let mut drain = [0u8; 256];
                    while matches!(stream.read(&mut drain), Ok(n) if n > 0) {}
                }
            }
        });

        format!("http://127.0.0.1:{}", addr.port())
    }

    /// Mock that returns an HTTP error on the second (Graph) request.
    fn mock_server_graph_error(status: u16) -> String {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        thread::spawn(move || {
            let token_body = r#"{"access_token":"test_tok","token_type":"Bearer"}"#;
            let error_body = r#"{"error":{"code":"Authorization_RequestDenied"}}"#;
            let bodies: [(&str, u16); 2] = [(token_body, 200), (error_body, status)];

            for (body, code) in bodies {
                if let Ok((mut stream, _)) = listener.accept() {
                    let mut buf = [0u8; 8192];
                    let _ = stream.read(&mut buf);
                    let resp = format!(
                        "HTTP/1.1 {code} OK\r\nContent-Type: application/json\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
                        len = body.len()
                    );
                    let _ = stream.write_all(resp.as_bytes());
                    let _ = stream.shutdown(std::net::Shutdown::Write);
                    let mut drain = [0u8; 256];
                    while matches!(stream.read(&mut drain), Ok(n) if n > 0) {}
                }
            }
        });

        format!("http://127.0.0.1:{}", addr.port())
    }

    const TOKEN_RESPONSE: &str =
        r#"{"access_token":"test_token","token_type":"Bearer","expires_in":3600}"#;

    fn base_config(base_url: &str) -> HashMap<String, String> {
        HashMap::from([
            ("AZURE_TENANT_ID".to_string(), "test-tenant-id".to_string()),
            ("AZURE_CLIENT_ID".to_string(), "test-client-id".to_string()),
            (
                "AZURE_CLIENT_SECRET".to_string(),
                "test-client-secret".to_string(),
            ),
            ("AZURE_LOGIN_BASE_URL".to_string(), base_url.to_string()),
            ("AZURE_GRAPH_BASE_URL".to_string(), base_url.to_string()),
        ])
    }

    // ── Metadata ─────────────────────────────────────────────────────────────

    #[test]
    fn ca_observer_id() {
        assert_eq!(ConditionalAccessObserver.id(), "azure.conditional_access");
    }

    #[test]
    fn ca_observer_name() {
        assert_eq!(
            ConditionalAccessObserver.name(),
            "Azure Conditional Access Observer"
        );
    }

    #[test]
    fn ca_observer_version() {
        assert_eq!(ConditionalAccessObserver.version(), "0.1.0");
    }

    #[test]
    fn ca_observer_source_system() {
        assert_eq!(ConditionalAccessObserver.source_system(), "azure");
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
            ("AZURE_CLIENT_ID".to_string(), "cid".to_string()),
            ("AZURE_CLIENT_SECRET".to_string(), "sec".to_string()),
        ]);
        let err = ConditionalAccessObserver.observe(&config).unwrap_err();
        assert!(err.to_string().contains("AZURE_TENANT_ID"));
    }

    #[test]
    fn missing_client_id_errors() {
        let config = HashMap::from([
            ("AZURE_TENANT_ID".to_string(), "tid".to_string()),
            ("AZURE_CLIENT_SECRET".to_string(), "sec".to_string()),
        ]);
        let err = ConditionalAccessObserver.observe(&config).unwrap_err();
        assert!(err.to_string().contains("AZURE_CLIENT_ID"));
    }

    #[test]
    fn missing_client_secret_errors() {
        let config = HashMap::from([
            ("AZURE_TENANT_ID".to_string(), "tid".to_string()),
            ("AZURE_CLIENT_ID".to_string(), "cid".to_string()),
        ]);
        let err = ConditionalAccessObserver.observe(&config).unwrap_err();
        assert!(err.to_string().contains("AZURE_CLIENT_SECRET"));
    }

    // ── HTTP integration ─────────────────────────────────────────────────────

    const EMPTY_POLICIES: &str = r#"{"value":[]}"#;

    const ENABLED_MFA_POLICIES: &str = r#"{
        "value": [
            {
                "id": "pol1",
                "displayName": "Require MFA for All Users",
                "state": "enabled",
                "grantControls": {
                    "operator": "OR",
                    "builtInControls": ["mfa"]
                }
            }
        ]
    }"#;

    const DISABLED_POLICY: &str = r#"{
        "value": [
            {
                "id": "pol2",
                "displayName": "Old Policy",
                "state": "disabled",
                "grantControls": {
                    "operator": "OR",
                    "builtInControls": ["mfa"]
                }
            }
        ]
    }"#;

    const NO_MFA_POLICY: &str = r#"{
        "value": [
            {
                "id": "pol3",
                "displayName": "Terms of Use Only",
                "state": "enabled",
                "grantControls": {
                    "operator": "OR",
                    "builtInControls": ["approvedApplication"]
                }
            }
        ]
    }"#;

    const COMPLIANT_DEVICE_POLICY: &str = r#"{
        "value": [
            {
                "id": "pol4",
                "displayName": "Require Compliant Device",
                "state": "enabled",
                "grantControls": {
                    "operator": "OR",
                    "builtInControls": ["compliantDevice"]
                }
            }
        ]
    }"#;

    #[test]
    fn empty_policies_is_effective() {
        let srv = mock_server(TOKEN_RESPONSE, EMPTY_POLICIES);
        let ev = &ConditionalAccessObserver
            .observe(&base_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert_eq!(
            ev.findings[0].title,
            "Conditional Access Policies Compliant"
        );
    }

    #[test]
    fn enabled_mfa_policy_is_effective() {
        let srv = mock_server(TOKEN_RESPONSE, ENABLED_MFA_POLICIES);
        let ev = &ConditionalAccessObserver
            .observe(&base_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert_eq!(ev.control_id, "iam.mfa_enforcement");
        assert_eq!(ev.class_uid, 1001);
        assert_eq!(ev.observables.len(), 1);
    }

    #[test]
    fn disabled_policy_is_ineffective() {
        let srv = mock_server(TOKEN_RESPONSE, DISABLED_POLICY);
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
        let srv = mock_server(TOKEN_RESPONSE, NO_MFA_POLICY);
        let ev = &ConditionalAccessObserver
            .observe(&base_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "Conditional Access Policy Lacks MFA Requirement"));
    }

    #[test]
    fn compliant_device_policy_is_effective() {
        let srv = mock_server(TOKEN_RESPONSE, COMPLIANT_DEVICE_POLICY);
        let ev = &ConditionalAccessObserver
            .observe(&base_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
    }

    #[test]
    fn graph_api_error_returns_err() {
        let srv = mock_server_graph_error(403);
        let result = ConditionalAccessObserver.observe(&base_config(&srv));
        assert!(result.is_err());
    }

    #[test]
    fn raw_data_has_expected_keys() {
        let srv = mock_server(TOKEN_RESPONSE, ENABLED_MFA_POLICIES);
        let ev = &ConditionalAccessObserver
            .observe(&base_config(&srv))
            .unwrap()[0];
        assert!(ev.raw_data.get("total_policies").is_some());
        assert!(ev.raw_data.get("disabled_policies").is_some());
        assert!(ev
            .raw_data
            .get("policies_without_mfa_requirement")
            .is_some());
    }

    #[test]
    fn observer_does_not_set_test_transcript() {
        let srv = mock_server(TOKEN_RESPONSE, EMPTY_POLICIES);
        let ev = &ConditionalAccessObserver
            .observe(&base_config(&srv))
            .unwrap()[0];
        assert!(ev.test_transcript.is_none());
    }
}
