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

/// Queries Okta PASSWORD policies and checks minimum length and complexity requirements.
///
/// Controls: OKTA-1.4 (min length >= 12), OKTA-1.5 (complexity requirements).
/// Required config: `OKTA_API_TOKEN`, `OKTA_DOMAIN`.
/// Optional: `OKTA_BASE_URL` (test override).
pub struct PasswordPolicyObserver;

impl Module for PasswordPolicyObserver {
    fn id(&self) -> &str {
        "okta.password_policy"
    }
    fn name(&self) -> &str {
        "Okta Password Policy Observer"
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

impl Observer for PasswordPolicyObserver {
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
        let path = "/api/v1/policies?type=PASSWORD";
        let endpoint = format!("{}{}", base_url.trim_end_matches('/'), path);

        let (body, status) = okta_get(token, &base_url, path)?;

        if status != 200 {
            return Err(anyhow!(
                "Okta API returned status {} querying PASSWORD policies",
                status
            ));
        }

        let policies = body
            .as_array()
            .ok_or_else(|| anyhow!("expected JSON array from Okta policies endpoint"))?;

        let mut findings: Vec<Finding> = Vec::new();
        let mut observables: Vec<Observable> = Vec::new();
        let mut policy_count = 0usize;
        let mut length_ok = true;
        let mut complexity_ok = true;
        let mut min_length_found = 0i64;
        let mut complexity_flags = json!({});

        for policy in policies {
            let status_str = policy
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("INACTIVE");

            if status_str != "ACTIVE" {
                continue;
            }

            let policy_id = policy
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");

            policy_count += 1;

            observables.push(Observable {
                obs_type: "policy".to_string(),
                name: "password_policy_id".to_string(),
                value: policy_id.to_string(),
            });

            let complexity = policy
                .get("settings")
                .and_then(|s| s.get("password"))
                .and_then(|p| p.get("complexity"));

            let min_length = complexity
                .and_then(|c| c.get("minLength"))
                .and_then(|v| v.as_i64())
                .unwrap_or(0);

            let min_lower = complexity
                .and_then(|c| c.get("minLowerCase"))
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            let min_upper = complexity
                .and_then(|c| c.get("minUpperCase"))
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            let min_number = complexity
                .and_then(|c| c.get("minNumber"))
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            let min_symbol = complexity
                .and_then(|c| c.get("minSymbol"))
                .and_then(|v| v.as_i64())
                .unwrap_or(0);

            min_length_found = min_length;
            complexity_flags = json!({
                "minLowerCase": min_lower,
                "minUpperCase": min_upper,
                "minNumber": min_number,
                "minSymbol": min_symbol,
            });

            // OKTA-1.4: minimum length >= 12
            if min_length < 12 {
                length_ok = false;
                findings.push(Finding {
                    title: "Password Minimum Length Too Short".to_string(),
                    description: format!(
                        "Password policy {:?} requires minimum length of {} (must be >= 12)",
                        policy_id, min_length
                    ),
                    severity_id: 3,
                });
            }

            // OKTA-1.5: at least 3 of 4 complexity types enabled
            let complexity_count =
                (if min_lower > 0 { 1 } else { 0 })
                + (if min_upper > 0 { 1 } else { 0 })
                + (if min_number > 0 { 1 } else { 0 })
                + (if min_symbol > 0 { 1 } else { 0 });

            if complexity_count < 3 {
                complexity_ok = false;
                findings.push(Finding {
                    title: "Insufficient Password Complexity".to_string(),
                    description: format!(
                        "Password policy {:?} has only {} of 4 complexity types enabled (need >= 3: lower, upper, number, symbol)",
                        policy_id, complexity_count
                    ),
                    severity_id: 3,
                });
            }
        }

        if findings.is_empty() {
            findings.push(Finding {
                title: "Password Policy Compliant".to_string(),
                description: format!(
                    "All {} active password policies meet minimum length and complexity requirements",
                    policy_count
                ),
                severity_id: 0,
            });
        }

        let status_id = if length_ok && complexity_ok {
            StatusId::Effective
        } else {
            StatusId::Ineffective
        };

        let status_text = if length_ok && complexity_ok {
            format!(
                "All {} active password policies meet OKTA-1.4 and OKTA-1.5 requirements",
                policy_count
            )
        } else {
            format!(
                "Password policy violations found: length_ok={}, complexity_ok={}",
                length_ok, complexity_ok
            )
        };

        let raw_data = json!({
            "policy_count": policy_count,
            "min_length": min_length_found,
            "complexity_flags": complexity_flags,
        });

        Ok(vec![Evidence {
            id: Uuid::new_v4(),
            control_id: "okta.password_policy".to_string(),
            class_uid: 1001,
            category_uid: 1,
            activity_id: 1,
            time: now,
            confidence_level: ConfidenceLevel::PassiveObservation,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "okta.password_policy".to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;

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

    const STRONG_POLICY: &str = r#"[{
        "id": "pol1",
        "name": "Strong Password Policy",
        "status": "ACTIVE",
        "settings": {
            "password": {
                "complexity": {
                    "minLength": 14,
                    "minLowerCase": 1,
                    "minUpperCase": 1,
                    "minNumber": 1,
                    "minSymbol": 1
                }
            }
        }
    }]"#;

    const WEAK_LENGTH_POLICY: &str = r#"[{
        "id": "pol2",
        "name": "Weak Password Policy",
        "status": "ACTIVE",
        "settings": {
            "password": {
                "complexity": {
                    "minLength": 8,
                    "minLowerCase": 1,
                    "minUpperCase": 1,
                    "minNumber": 1,
                    "minSymbol": 1
                }
            }
        }
    }]"#;

    #[test]
    fn strong_policy_is_effective() {
        let srv = mock_server(200, STRONG_POLICY);
        let ev = &PasswordPolicyObserver.observe(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert_eq!(ev.findings[0].title, "Password Policy Compliant");
    }

    #[test]
    fn weak_length_policy_is_ineffective_with_finding() {
        let srv = mock_server(200, WEAK_LENGTH_POLICY);
        let ev = &PasswordPolicyObserver.observe(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "Password Minimum Length Too Short"));
    }

    #[test]
    fn api_error_returns_err() {
        let srv = mock_server(403, r#"{"errorCode":"E0000006","errorSummary":"Unauthorized"}"#);
        let result = PasswordPolicyObserver.observe(&base_config(&srv));
        assert!(result.is_err());
    }
}
