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

/// Queries Okta PASSWORD policies and checks account recovery factor settings.
///
/// Control: OKTA-1.10 (account recovery requires secure verification — email only, no SMS).
/// Required config: `OKTA_API_TOKEN`, `OKTA_DOMAIN`.
/// Optional: `OKTA_BASE_URL` (test override).
pub struct RecoveryPolicyObserver;

impl Module for RecoveryPolicyObserver {
    fn id(&self) -> &str {
        "okta.recovery_policy"
    }
    fn name(&self) -> &str {
        "Okta Recovery Policy Observer"
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

impl Observer for RecoveryPolicyObserver {
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

        if policies.is_empty() {
            return Err(anyhow!("No PASSWORD policies found"));
        }

        let mut findings: Vec<Finding> = Vec::new();
        let mut observables: Vec<Observable> = Vec::new();
        let mut sms_recovery_enabled = false;
        let mut email_recovery_enabled = false;

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

            observables.push(Observable {
                obs_type: "policy".to_string(),
                name: "recovery_policy_id".to_string(),
                value: policy_id.to_string(),
            });

            let recovery_factors = policy
                .get("settings")
                .and_then(|s| s.get("recovery"))
                .and_then(|r| r.get("factors"));

            let email_status = recovery_factors
                .and_then(|f| f.get("okta_email"))
                .and_then(|e| e.get("status"))
                .and_then(|v| v.as_str())
                .unwrap_or("INACTIVE");

            let sms_status = recovery_factors
                .and_then(|f| f.get("okta_sms"))
                .and_then(|s| s.get("status"))
                .and_then(|v| v.as_str())
                .unwrap_or("INACTIVE");

            if email_status == "ACTIVE" {
                email_recovery_enabled = true;
            }

            if sms_status == "ACTIVE" {
                sms_recovery_enabled = true;
                findings.push(Finding {
                    title: "SMS Recovery Factor Enabled".to_string(),
                    description: format!(
                        "Password policy {:?} has SMS recovery enabled (okta_sms status=ACTIVE); SMS is phishable and must be disabled per OKTA-1.10",
                        policy_id
                    ),
                    severity_id: 3,
                });
            }
        }

        if findings.is_empty() {
            findings.push(Finding {
                title: "Recovery Policy Compliant".to_string(),
                description:
                    "Account recovery uses secure factors only (no SMS); OKTA-1.10 met".to_string(),
                severity_id: 0,
            });
        }

        // Effective if SMS is not enabled (email-only or Okta Verify recovery is acceptable)
        let status_id = if sms_recovery_enabled {
            StatusId::Ineffective
        } else {
            StatusId::Effective
        };

        let status_text = if sms_recovery_enabled {
            "SMS recovery is enabled — insecure recovery factor detected (OKTA-1.10 violation)"
                .to_string()
        } else {
            "Account recovery does not allow SMS; OKTA-1.10 requirements met".to_string()
        };

        let raw_data = json!({
            "sms_recovery_enabled": sms_recovery_enabled,
            "email_recovery_enabled": email_recovery_enabled,
        });

        Ok(vec![Evidence {
            id: Uuid::new_v4(),
            control_id: "okta.recovery_policy".to_string(),
            class_uid: 1001,
            category_uid: 1,
            activity_id: 1,
            time: now,
            confidence_level: ConfidenceLevel::PassiveObservation,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "okta.recovery_policy".to_string(),
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

    const EMAIL_ONLY_POLICY: &str = r#"[{
        "id": "pol1",
        "name": "Default Policy",
        "status": "ACTIVE",
        "settings": {
            "recovery": {
                "factors": {
                    "okta_email": { "status": "ACTIVE" },
                    "okta_sms": { "status": "INACTIVE" }
                }
            }
        }
    }]"#;

    const SMS_RECOVERY_POLICY: &str = r#"[{
        "id": "pol2",
        "name": "Default Policy",
        "status": "ACTIVE",
        "settings": {
            "recovery": {
                "factors": {
                    "okta_email": { "status": "ACTIVE" },
                    "okta_sms": { "status": "ACTIVE" }
                }
            }
        }
    }]"#;

    #[test]
    fn email_only_recovery_is_effective() {
        let srv = mock_server(200, EMAIL_ONLY_POLICY);
        let ev = &RecoveryPolicyObserver.observe(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert_eq!(ev.findings[0].title, "Recovery Policy Compliant");
    }

    #[test]
    fn sms_recovery_is_ineffective_with_finding() {
        let srv = mock_server(200, SMS_RECOVERY_POLICY);
        let ev = &RecoveryPolicyObserver.observe(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "SMS Recovery Factor Enabled"));
    }

    #[test]
    fn empty_policy_list_returns_err() {
        let srv = mock_server(200, "[]");
        let result = RecoveryPolicyObserver.observe(&base_config(&srv));
        assert!(result.is_err());
    }

    #[test]
    fn metadata_complete() {
        use crate::module::Module;
        let obs = RecoveryPolicyObserver;
        assert_eq!(obs.id(), "okta.recovery_policy");
        assert!(!obs.name().is_empty());
        assert_eq!(obs.version(), "0.1.0");
        assert_eq!(obs.source_system(), "okta");
        assert!(!obs.evidence_types().is_empty());
        let creds = obs.credential_requirements();
        assert!(creds.len() >= 2);
        assert!(creds.iter().any(|c| c.name == "OKTA_API_TOKEN"));
        assert!(creds.iter().any(|c| c.name == "OKTA_DOMAIN"));
    }

    #[test]
    fn domain_only_uses_https_prefix() {
        let cfg = HashMap::from([
            ("OKTA_API_TOKEN".to_string(), "test_token".to_string()),
            ("OKTA_DOMAIN".to_string(), "localhost".to_string()),
        ]);
        let result = RecoveryPolicyObserver.observe(&cfg);
        assert!(result.is_err());
    }

    #[test]
    fn missing_token_errors() {
        let cfg = HashMap::from([
            ("OKTA_DOMAIN".to_string(), "example.okta.com".to_string()),
        ]);
        let result = RecoveryPolicyObserver.observe(&cfg);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("OKTA_API_TOKEN"));
    }

    #[test]
    fn missing_domain_errors() {
        let cfg = HashMap::from([
            ("OKTA_API_TOKEN".to_string(), "test".to_string()),
        ]);
        let result = RecoveryPolicyObserver.observe(&cfg);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("OKTA_DOMAIN"));
    }

    #[test]
    fn api_returns_403_errors() {
        let srv = mock_server(403, r#"{"errorCode":"E0000006","errorSummary":"forbidden"}"#);
        let result = RecoveryPolicyObserver.observe(&base_config(&srv));
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("403"));
    }

    #[test]
    fn api_connection_refused_returns_error() {
        let cfg = base_config("http://127.0.0.1:1");
        let result = RecoveryPolicyObserver.observe(&cfg);
        assert!(result.is_err());
    }

    #[test]
    fn non_json_array_body_errors() {
        let srv = mock_server(200, r#""not an array""#);
        let result = RecoveryPolicyObserver.observe(&base_config(&srv));
        assert!(result.is_err());
    }

    #[test]
    fn inactive_policy_only_is_effective_with_no_sms() {
        // All inactive policies are skipped; result should show email_recovery_enabled=false
        // and sms_recovery_enabled=false → Effective (no SMS found in any active policy)
        let body = r#"[{
            "id": "pol_inactive",
            "name": "Old Policy",
            "status": "INACTIVE",
            "settings": {
                "recovery": {
                    "factors": {
                        "okta_email": { "status": "ACTIVE" },
                        "okta_sms": { "status": "ACTIVE" }
                    }
                }
            }
        }]"#;
        let srv = mock_server(200, body);
        let ev = &RecoveryPolicyObserver.observe(&base_config(&srv)).unwrap()[0];
        // No active policies processed, so SMS is never detected → Effective
        assert_eq!(ev.status_id, StatusId::Effective);
        assert_eq!(ev.raw_data["sms_recovery_enabled"], false);
    }
}
