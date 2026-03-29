use std::collections::HashMap;

use anyhow::{anyhow, Result};
use chrono::Utc;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId,
};
use crate::module::{observer::Observer, CredentialReq, Module};

fn okta_get(token: &str, base_url: &str, path: &str) -> Result<(Value, u16)> {
    let url = format!("{}{}", base_url.trim_end_matches('/'), path);
    let resp = ureq::get(&url)
        .set("Authorization", &format!("SSWS {}", token))
        .set("Accept", "application/json")
        .call();

    match resp {
        Ok(r) => {
            let status = r.status();
            let body: Value = r
                .into_json()
                .map_err(|e| anyhow!("parsing Okta JSON: {}", e))?;
            Ok((body, status))
        }
        Err(ureq::Error::Status(code, r)) => {
            let body: Value = r
                .into_json()
                .unwrap_or_else(|_| json!({"errorCode": "unknown", "errorSummary": "error"}));
            Ok((body, code))
        }
        Err(e) => Err(anyhow!("Okta API request failed: {}", e)),
    }
}

/// Queries Okta OKTA_SIGN_ON policies and checks session lifetime and idle timeout settings.
///
/// Controls: OKTA-4.1 (max session lifetime <= 8h), OKTA-4.2 (idle timeout <= 2h),
///           OKTA-4.3 (no persistent cookie / re-auth on new device).
/// Required config: `OKTA_API_TOKEN`, `OKTA_DOMAIN`.
/// Optional: `OKTA_BASE_URL` (test override).
pub struct SessionPolicyObserver;

impl Module for SessionPolicyObserver {
    fn id(&self) -> &str {
        "okta.session_policy"
    }
    fn name(&self) -> &str {
        "Okta Session Policy Observer"
    }
    fn version(&self) -> &str {
        "0.1.0"
    }
    fn source_system(&self) -> &str {
        "okta"
    }
    fn evidence_types(&self) -> &[i32] {
        &[1001]
    }

    fn credential_requirements(&self) -> Vec<CredentialReq> {
        vec![
            CredentialReq {
                name: "OKTA_API_TOKEN".to_string(),
                cred_type: "api_token".to_string(),
                description: "Okta API token with read access to policies".to_string(),
                required: true,
            },
            CredentialReq {
                name: "OKTA_DOMAIN".to_string(),
                cred_type: "domain".to_string(),
                description: "Okta organization domain (e.g., example.okta.com)".to_string(),
                required: true,
            },
        ]
    }
}

impl Observer for SessionPolicyObserver {
    fn observe(&self, config: &HashMap<String, String>) -> Result<Vec<Evidence>> {
        let token = config
            .get("OKTA_API_TOKEN")
            .ok_or_else(|| anyhow!("OKTA_API_TOKEN is required"))?;
        let domain = config
            .get("OKTA_DOMAIN")
            .ok_or_else(|| anyhow!("OKTA_DOMAIN is required"))?;
        let base_url = config
            .get("OKTA_BASE_URL")
            .map(|s| s.as_str())
            .unwrap_or_else(|| domain.as_str());

        let base_url = if base_url.starts_with("http") {
            base_url.to_string()
        } else {
            format!("https://{}", base_url)
        };

        let now = Utc::now();
        let path = "/api/v1/policies?type=OKTA_SIGN_ON";
        let endpoint = format!("{}{}", base_url.trim_end_matches('/'), path);

        let (body, status) = okta_get(token, &base_url, path)?;

        if status != 200 {
            return Err(anyhow!(
                "Okta API returned status {} querying OKTA_SIGN_ON policies",
                status
            ));
        }

        let policies = body
            .as_array()
            .ok_or_else(|| anyhow!("expected JSON array from Okta policies endpoint"))?;

        if policies.is_empty() {
            return Err(anyhow!("No OKTA_SIGN_ON policies found"));
        }

        // Use DEFAULT policy if present, otherwise first ACTIVE policy
        let policy = policies
            .iter()
            .find(|p| {
                p.get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    == "Default Policy"
                    && p.get("status")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        == "ACTIVE"
            })
            .or_else(|| {
                policies.iter().find(|p| {
                    p.get("status")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        == "ACTIVE"
                })
            })
            .ok_or_else(|| anyhow!("No active OKTA_SIGN_ON policy found"))?;

        let policy_id = policy
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        // Session settings live in rule actions, not policy-level settings.
        // Fetch the policy's rules and use the highest-priority (lowest number) rule.
        let rules_path = format!("/api/v1/policies/{}/rules", policy_id);
        let (rules_body, rules_status) = okta_get(token, &base_url, &rules_path)?;

        if rules_status != 200 {
            return Err(anyhow!(
                "Okta API returned status {} querying rules for policy {}",
                rules_status,
                policy_id
            ));
        }

        let rules = rules_body
            .as_array()
            .ok_or_else(|| anyhow!("expected JSON array from policy rules endpoint"))?;

        // Pick the first ACTIVE rule (rules are returned in priority order)
        let active_rule = rules
            .iter()
            .find(|r| {
                r.get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    == "ACTIVE"
            })
            .ok_or_else(|| anyhow!("No active rules found for policy {}", policy_id))?;

        let session = active_rule
            .get("actions")
            .and_then(|a| a.get("signon"))
            .and_then(|s| s.get("session"));

        let max_session_lifetime = session
            .and_then(|s| s.get("maxSessionLifetimeMinutes"))
            .and_then(|v| v.as_i64())
            .unwrap_or(0);

        let max_session_idle = session
            .and_then(|s| s.get("maxSessionIdleMinutes"))
            .and_then(|v| v.as_i64())
            .unwrap_or(0);

        let use_persistent_cookie = session
            .and_then(|s| s.get("usePersistentCookie"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let mut findings: Vec<Finding> = Vec::new();

        // OKTA-4.1: max session lifetime <= 480 minutes (8h); 0 = unlimited = fail
        let lifetime_ok = max_session_lifetime > 0 && max_session_lifetime <= 480;
        if !lifetime_ok {
            findings.push(Finding {
                title: "Session Lifetime Exceeds Maximum".to_string(),
                description: format!(
                    "Session policy {:?} has maxSessionLifetimeMinutes={} (must be 1-480; 0=unlimited)",
                    policy_id, max_session_lifetime
                ),
                severity_id: 3,
            });
        }

        // OKTA-4.2: idle timeout <= 120 minutes (2h)
        let idle_ok = max_session_idle > 0 && max_session_idle <= 120;
        if !idle_ok {
            findings.push(Finding {
                title: "Session Idle Timeout Too Long".to_string(),
                description: format!(
                    "Session policy {:?} has maxSessionIdleMinutes={} (must be 1-120)",
                    policy_id, max_session_idle
                ),
                severity_id: 3,
            });
        }

        // OKTA-4.3: persistent cookie must be disabled
        let persistent_ok = !use_persistent_cookie;
        if !persistent_ok {
            findings.push(Finding {
                title: "Persistent Session Cookie Enabled".to_string(),
                description: format!(
                    "Session policy {:?} has usePersistentCookie=true (must be false for re-auth on new device)",
                    policy_id
                ),
                severity_id: 3,
            });
        }

        if findings.is_empty() {
            findings.push(Finding {
                title: "Session Policy Compliant".to_string(),
                description: "Session policy meets OKTA-4.1, OKTA-4.2, and OKTA-4.3 requirements"
                    .to_string(),
                severity_id: 0,
            });
        }

        let all_ok = lifetime_ok && idle_ok && persistent_ok;
        let status_id = if all_ok {
            StatusId::Effective
        } else {
            StatusId::Ineffective
        };

        let status_text = if all_ok {
            "Session policy meets all lifetime, idle, and persistence requirements".to_string()
        } else {
            format!(
                "Session policy violations: lifetime_ok={}, idle_ok={}, persistent_ok={}",
                lifetime_ok, idle_ok, persistent_ok
            )
        };

        let raw_data = json!({
            "maxSessionLifetimeMinutes": max_session_lifetime,
            "maxSessionIdleMinutes": max_session_idle,
            "usePersistentCookie": use_persistent_cookie,
        });

        Ok(vec![Evidence {
            id: Uuid::new_v4(),
            control_id: "okta.session_policy".to_string(),
            class_uid: 1001,
            category_uid: 1,
            activity_id: 1,
            time: now,
            confidence_level: ConfidenceLevel::PassiveObservation,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "okta.session_policy".to_string(),
                    version: "0.1.0".to_string(),
                    module_type: "observer".to_string(),
                },
                source: SourceInfo {
                    system: "okta".to_string(),
                    api_version: "v1".to_string(),
                    endpoint,
                },
                original_time: None,
                processed_time: now,
                safety_classification: None,
            },
            observables: vec![Observable {
                obs_type: "policy".to_string(),
                name: "session_policy_id".to_string(),
                value: policy_id.to_string(),
            }],
            status_id,
            status: status_text,
            raw_data,
            findings,
            test_transcript: None,
            enrichments: vec![],
        }])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Multi-request mock server: responds to sequential requests with different bodies.
    /// First request gets `policies_body`, second gets `rules_body`.
    fn mock_server_multi(policies_body: &str, rules_body: &str) -> String {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let policies = policies_body.to_string();
        let rules = rules_body.to_string();

        thread::spawn(move || {
            let responses = [policies, rules];
            for body in &responses {
                if let Ok((mut stream, _)) = listener.accept() {
                    let mut buf = [0u8; 8192];
                    let _ = stream.read(&mut buf);
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
                        len = body.len()
                    );
                    let _ = stream.write_all(resp.as_bytes());
                }
            }
        });

        format!("http://127.0.0.1:{}", addr.port())
    }

    /// Single-request mock server (for error/empty cases where rules aren't fetched).
    fn mock_server(status: u16, body: &str) -> String {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let body = body.to_string();

        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 8192];
                let _ = stream.read(&mut buf);
                let resp = format!(
                    "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
                    len = body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });

        format!("http://127.0.0.1:{}", addr.port())
    }

    fn base_config(base_url: &str) -> HashMap<String, String> {
        HashMap::from([
            ("OKTA_API_TOKEN".to_string(), "test_token".to_string()),
            ("OKTA_DOMAIN".to_string(), "example.okta.com".to_string()),
            ("OKTA_BASE_URL".to_string(), base_url.to_string()),
        ])
    }

    const POLICY_WITH_ID: &str = r#"[{
        "id": "pol1",
        "name": "Default Policy",
        "status": "ACTIVE"
    }]"#;

    const STRICT_SESSION_RULE: &str = r#"[{
        "id": "rule1",
        "name": "Default Rule",
        "status": "ACTIVE",
        "actions": {
            "signon": {
                "session": {
                    "maxSessionLifetimeMinutes": 480,
                    "maxSessionIdleMinutes": 120,
                    "usePersistentCookie": false
                }
            }
        }
    }]"#;

    const UNLIMITED_SESSION_RULE: &str = r#"[{
        "id": "rule2",
        "name": "Default Rule",
        "status": "ACTIVE",
        "actions": {
            "signon": {
                "session": {
                    "maxSessionLifetimeMinutes": 0,
                    "maxSessionIdleMinutes": 120,
                    "usePersistentCookie": false
                }
            }
        }
    }]"#;

    #[test]
    fn strict_session_policy_is_effective() {
        let srv = mock_server_multi(POLICY_WITH_ID, STRICT_SESSION_RULE);
        let ev = &SessionPolicyObserver.observe(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert_eq!(ev.findings[0].title, "Session Policy Compliant");
    }

    #[test]
    fn unlimited_session_is_ineffective() {
        let srv = mock_server_multi(POLICY_WITH_ID, UNLIMITED_SESSION_RULE);
        let ev = &SessionPolicyObserver.observe(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "Session Lifetime Exceeds Maximum"));
    }

    #[test]
    fn empty_policies_returns_err() {
        let srv = mock_server(200, "[]");
        let result = SessionPolicyObserver.observe(&base_config(&srv));
        assert!(result.is_err());
    }
}
