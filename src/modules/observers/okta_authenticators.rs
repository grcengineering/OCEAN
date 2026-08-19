use std::collections::HashMap;

use anyhow::{anyhow, Result};
use chrono::Utc;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId,
    EVIDENCE_SCHEMA_VERSION,
};
use crate::module::{observer::Observer, CredentialReq, Module};

// ─── Okta HTTP client ─────────────────────────────────────────────────────────

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

// ─── AuthenticatorsObserver ───────────────────────────────────────────────────

/// Queries Okta authenticator configurations and validates FIDO2/WebAuthn is active
/// and flags SMS (phone_number) authenticator if also active.
///
/// Controls: OKTA-1.7 (FIDO2/WebAuthn authenticator enabled),
///           OKTA-1.8 (weak authenticators disabled)
/// Required config: `OKTA_API_TOKEN`, `OKTA_DOMAIN`.
/// Optional: `OKTA_BASE_URL` (test override — defaults to `https://{OKTA_DOMAIN}`).
pub struct AuthenticatorsObserver;

impl Module for AuthenticatorsObserver {
    fn id(&self) -> &str {
        "okta.authenticators"
    }
    fn name(&self) -> &str {
        "Okta Authenticators Observer"
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
                description: "Okta API token with read access to authenticator configurations"
                    .to_string(),
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

impl Observer for AuthenticatorsObserver {
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
        let path = "/api/v1/authenticators";
        let endpoint = format!("{}{}", base_url.trim_end_matches('/'), path);

        let (body, status) = okta_get(token, &base_url, path)?;

        if status != 200 {
            return Err(anyhow!(
                "Okta API returned status {} querying authenticators",
                status
            ));
        }

        let authenticators = body
            .as_array()
            .ok_or_else(|| anyhow!("expected JSON array from Okta authenticators endpoint"))?;

        let webauthn_active = authenticators.iter().any(|a| {
            let key = a.get("key").and_then(|v| v.as_str()).unwrap_or("");
            let status_str = a.get("status").and_then(|v| v.as_str()).unwrap_or("");
            key == "webauthn" && status_str == "ACTIVE"
        });

        let sms_active = authenticators.iter().any(|a| {
            let key = a.get("key").and_then(|v| v.as_str()).unwrap_or("");
            let status_str = a.get("status").and_then(|v| v.as_str()).unwrap_or("");
            key == "phone_number" && status_str == "ACTIVE"
        });

        let authenticator_list: Vec<Value> = authenticators
            .iter()
            .map(|a| {
                json!({
                    "key": a.get("key").and_then(|v| v.as_str()).unwrap_or("unknown"),
                    "status": a.get("status").and_then(|v| v.as_str()).unwrap_or("unknown"),
                    "name": a.get("name").and_then(|v| v.as_str()).unwrap_or("unknown"),
                })
            })
            .collect();

        let mut findings: Vec<Finding> = Vec::new();

        let (status_id, status_text) = if webauthn_active {
            (
                StatusId::Effective,
                "FIDO2/WebAuthn authenticator is active (OKTA-1.7 satisfied)".to_string(),
            )
        } else {
            findings.push(Finding {
                title: "FIDO2/WebAuthn Authenticator Not Active".to_string(),
                description:
                    "The webauthn authenticator is not in ACTIVE status. OKTA-1.7 requires \
                     FIDO2/WebAuthn to be enabled as a phishing-resistant authenticator."
                        .to_string(),
                severity_id: 4,
            });
            (
                StatusId::Ineffective,
                "FIDO2/WebAuthn authenticator is not active (OKTA-1.7 not satisfied)".to_string(),
            )
        };

        if sms_active {
            findings.push(Finding {
                title: "SMS Authenticator Active (OKTA-1.8 Concern)".to_string(),
                description:
                    "The phone_number (SMS) authenticator is ACTIVE. SMS-based authentication \
                     is phishable and should be disabled or restricted per OKTA-1.8. \
                     Review policies to ensure SMS is not permitted as a standalone MFA factor."
                        .to_string(),
                severity_id: 2,
            });
        }

        let observables: Vec<Observable> = vec![
            Observable {
                obs_type: "config".to_string(),
                value: webauthn_active.to_string(),
                name: "webauthn_active".to_string(),
            },
            Observable {
                obs_type: "config".to_string(),
                value: sms_active.to_string(),
                name: "sms_active".to_string(),
            },
        ];

        let raw_data = json!({
            "webauthn_active": webauthn_active,
            "sms_active": sms_active,
            "authenticators": authenticator_list,
        });

        Ok(vec![Evidence {
            schema_version: EVIDENCE_SCHEMA_VERSION.to_string(),
            connected_account: None,
            population: None,
            evaluation: None,
            id: Uuid::new_v4(),
            control_id: "OKTA-1.7".to_string(),
            class_uid: 1001,
            category_uid: 1,
            activity_id: 1,
            time: now,
            confidence_level: ConfidenceLevel::PassiveObservation,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "okta.authenticators".to_string(),
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

// ─── Tests ────────────────────────────────────────────────────────────────────

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

    #[test]
    fn okta_authenticators_webauthn_active_sms_inactive_is_effective_no_findings() {
        let body = r#"[
            {"key":"webauthn","status":"ACTIVE","name":"FIDO2 (WebAuthn)"},
            {"key":"phone_number","status":"INACTIVE","name":"Phone"},
            {"key":"okta_verify","status":"ACTIVE","name":"Okta Verify"}
        ]"#;
        let url = mock_server(200, body);
        let cfg = base_config(&url);
        let ev = AuthenticatorsObserver.observe(&cfg).unwrap();
        assert_eq!(ev[0].status_id, StatusId::Effective);
        assert!(ev[0].findings.is_empty());
        assert_eq!(ev[0].raw_data["webauthn_active"].as_bool().unwrap(), true);
        assert_eq!(ev[0].raw_data["sms_active"].as_bool().unwrap(), false);
    }

    #[test]
    fn okta_authenticators_webauthn_inactive_is_ineffective_critical() {
        let body = r#"[
            {"key":"webauthn","status":"INACTIVE","name":"FIDO2 (WebAuthn)"},
            {"key":"okta_verify","status":"ACTIVE","name":"Okta Verify"}
        ]"#;
        let url = mock_server(200, body);
        let cfg = base_config(&url);
        let ev = AuthenticatorsObserver.observe(&cfg).unwrap();
        assert_eq!(ev[0].status_id, StatusId::Ineffective);
        assert!(ev[0]
            .findings
            .iter()
            .any(|f| f.title.contains("FIDO2/WebAuthn") && f.severity_id == 4));
    }

    #[test]
    fn okta_authenticators_webauthn_active_sms_active_is_effective_with_info_finding() {
        let body = r#"[
            {"key":"webauthn","status":"ACTIVE","name":"FIDO2 (WebAuthn)"},
            {"key":"phone_number","status":"ACTIVE","name":"Phone"},
            {"key":"okta_verify","status":"ACTIVE","name":"Okta Verify"}
        ]"#;
        let url = mock_server(200, body);
        let cfg = base_config(&url);
        let ev = AuthenticatorsObserver.observe(&cfg).unwrap();
        assert_eq!(ev[0].status_id, StatusId::Effective);
        assert!(
            ev[0]
                .findings
                .iter()
                .any(|f| f.title.contains("SMS") && f.severity_id == 2),
            "expected informational SMS finding"
        );
    }
}
