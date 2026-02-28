use std::collections::HashMap;

use anyhow::{anyhow, Result};
use chrono::Utc;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId,
};
use crate::module::{collector::Collector, CredentialReq, Module};

// ─── Okta HTTP client ─────────────────────────────────────────────────────────

/// Performs an authenticated GET to the Okta API.
/// `base_url` defaults to `https://{domain}` but can be overridden in config
/// via `OKTA_BASE_URL` for testing with a mock server.
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

// ─── MfaPolicyCollector ───────────────────────────────────────────────────────

/// Queries Okta MFA enrollment policies and normalizes them into OCEAN evidence.
/// Generates findings for inactive policies or policies without required factors.
///
/// Required config: `OKTA_API_TOKEN`, `OKTA_DOMAIN`.
/// Optional: `OKTA_BASE_URL` (test override — defaults to `https://{OKTA_DOMAIN}`).
pub struct MfaPolicyCollector;

impl Module for MfaPolicyCollector {
    fn id(&self) -> &str {
        "okta.mfa_policy"
    }
    fn name(&self) -> &str {
        "Okta MFA Policy Collector"
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

impl Collector for MfaPolicyCollector {
    fn collect(&self, config: &HashMap<String, String>) -> Result<Vec<Evidence>> {
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

        // Normalise base_url: if it doesn't start with http, prepend https://
        let base_url = if base_url.starts_with("http") {
            base_url.to_string()
        } else {
            format!("https://{}", base_url)
        };

        let now = Utc::now();
        let path = "/api/v1/policies?type=MFA_ENROLL";
        let endpoint = format!("{}{}", base_url.trim_end_matches('/'), path);

        let (body, status) = okta_get(token, &base_url, path)?;

        if status != 200 {
            return Err(anyhow!(
                "Okta API returned status {} querying MFA policies",
                status
            ));
        }

        let policies = body
            .as_array()
            .ok_or_else(|| anyhow!("expected JSON array from Okta policies endpoint"))?;

        let mut findings: Vec<Finding> = Vec::new();
        let mut observables: Vec<Observable> = Vec::new();
        let mut inactive_count = 0usize;
        let mut policies_without_required_factors = 0usize;

        for policy in policies {
            let name = policy
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let status_str = policy
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("INACTIVE");
            let policy_id = policy
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");

            observables.push(Observable {
                obs_type: "resource".to_string(),
                value: format!("policy:{}", policy_id),
                name: String::new(),
            });

            if status_str != "ACTIVE" {
                inactive_count += 1;
                findings.push(Finding {
                    title: "Inactive MFA Policy".to_string(),
                    description: format!(
                        "MFA enrollment policy {:?} is in status {:?} instead of ACTIVE",
                        name, status_str
                    ),
                    severity_id: 3,
                });
                continue;
            }

            // Check whether any factor has REQUIRED enrollment.
            let has_required_factor = policy
                .get("settings")
                .and_then(|s| s.get("factors"))
                .and_then(|f| f.as_object())
                .map(|factors| {
                    factors.values().any(|factor| {
                        factor
                            .get("enroll")
                            .and_then(|e| e.get("self"))
                            .and_then(|v| v.as_str())
                            == Some("REQUIRED")
                    })
                })
                .unwrap_or(false);

            if !has_required_factor {
                policies_without_required_factors += 1;
                findings.push(Finding {
                    title: "No Required MFA Factors".to_string(),
                    description: format!(
                        "MFA enrollment policy {:?} has no factors set to REQUIRED enrollment",
                        name
                    ),
                    severity_id: 2,
                });
            }
        }

        if findings.is_empty() {
            findings.push(Finding {
                title: "MFA Policies Compliant".to_string(),
                description: format!(
                    "All {} MFA enrollment policies are active with required factor enrollment",
                    policies.len()
                ),
                severity_id: 0,
            });
        }

        let (status_id, status_text) =
            if inactive_count > 0 || policies_without_required_factors > 0 {
                (
                    StatusId::Ineffective,
                    format!(
                        "{} inactive MFA policies, {} without required factors out of {} total",
                        inactive_count,
                        policies_without_required_factors,
                        policies.len()
                    ),
                )
            } else {
                (
                    StatusId::Effective,
                    format!(
                        "All {} MFA policies are active with required factor enrollment",
                        policies.len()
                    ),
                )
            };

        let raw_data = json!({
            "total_policies": policies.len(),
            "inactive_policies": inactive_count,
            "policies_without_required_factors": policies_without_required_factors,
            "policies": body,
        });

        Ok(vec![Evidence {
            id: Uuid::new_v4(),
            control_id: "mfa.enrollment_policy".to_string(),
            class_uid: 1001,
            category_uid: 1,
            activity_id: 1,
            time: now,
            confidence_level: ConfidenceLevel::PassiveObservation,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "okta.mfa_policy".to_string(),
                    version: "0.1.0".to_string(),
                    module_type: "collector".to_string(),
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

    // ── Metadata ─────────────────────────────────────────────────────────────

    #[test]
    fn mfa_policy_id() {
        assert_eq!(MfaPolicyCollector.id(), "okta.mfa_policy");
    }

    #[test]
    fn mfa_policy_name() {
        assert_eq!(MfaPolicyCollector.name(), "Okta MFA Policy Collector");
    }

    #[test]
    fn mfa_policy_version() {
        assert_eq!(MfaPolicyCollector.version(), "0.1.0");
    }

    #[test]
    fn mfa_policy_source_system() {
        assert_eq!(MfaPolicyCollector.source_system(), "okta");
    }

    #[test]
    fn mfa_policy_evidence_types() {
        assert_eq!(MfaPolicyCollector.evidence_types(), &[1001]);
    }

    #[test]
    fn mfa_policy_credential_requirements() {
        let reqs = MfaPolicyCollector.credential_requirements();
        assert_eq!(reqs.len(), 2);
        assert!(reqs
            .iter()
            .any(|r| r.name == "OKTA_API_TOKEN" && r.required));
        assert!(reqs.iter().any(|r| r.name == "OKTA_DOMAIN" && r.required));
    }

    // ── Config validation ────────────────────────────────────────────────────

    #[test]
    fn missing_api_token_errors() {
        let err = MfaPolicyCollector
            .collect(&HashMap::from([(
                "OKTA_DOMAIN".to_string(),
                "example.okta.com".to_string(),
            )]))
            .unwrap_err();
        assert!(err.to_string().contains("OKTA_API_TOKEN"));
    }

    #[test]
    fn missing_domain_errors() {
        let err = MfaPolicyCollector
            .collect(&HashMap::from([(
                "OKTA_API_TOKEN".to_string(),
                "tok".to_string(),
            )]))
            .unwrap_err();
        assert!(err.to_string().contains("OKTA_DOMAIN"));
    }

    // ── HTTP integration ─────────────────────────────────────────────────────

    const ACTIVE_REQUIRED_POLICY: &str = r#"[
        {
            "id": "pol1",
            "name": "Default MFA Policy",
            "status": "ACTIVE",
            "settings": {
                "factors": {
                    "okta_otp": { "enroll": { "self": "REQUIRED" } },
                    "okta_push": { "enroll": { "self": "OPTIONAL" } }
                }
            }
        }
    ]"#;

    const INACTIVE_POLICY: &str = r#"[
        {
            "id": "pol2",
            "name": "Old Policy",
            "status": "INACTIVE",
            "settings": {}
        }
    ]"#;

    const ACTIVE_NO_REQUIRED_POLICY: &str = r#"[
        {
            "id": "pol3",
            "name": "Weak Policy",
            "status": "ACTIVE",
            "settings": {
                "factors": {
                    "okta_otp": { "enroll": { "self": "OPTIONAL" } }
                }
            }
        }
    ]"#;

    const EMPTY_POLICIES: &str = "[]";

    #[test]
    fn empty_policies_is_effective() {
        let srv = mock_server(200, EMPTY_POLICIES);
        let ev = &MfaPolicyCollector.collect(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert_eq!(ev.findings[0].title, "MFA Policies Compliant");
    }

    #[test]
    fn active_required_policy_is_effective() {
        let srv = mock_server(200, ACTIVE_REQUIRED_POLICY);
        let ev = &MfaPolicyCollector.collect(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert_eq!(ev.control_id, "mfa.enrollment_policy");
        assert_eq!(ev.class_uid, 1001);
        assert_eq!(ev.observables.len(), 1);
    }

    #[test]
    fn inactive_policy_is_ineffective() {
        let srv = mock_server(200, INACTIVE_POLICY);
        let ev = &MfaPolicyCollector.collect(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev.findings.iter().any(|f| f.title == "Inactive MFA Policy"));
    }

    #[test]
    fn active_no_required_factor_is_ineffective() {
        let srv = mock_server(200, ACTIVE_NO_REQUIRED_POLICY);
        let ev = &MfaPolicyCollector.collect(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "No Required MFA Factors"));
    }

    #[test]
    fn api_error_returns_err() {
        let srv = mock_server(
            403,
            r#"{"errorCode":"E0000006","errorSummary":"Unauthorized"}"#,
        );
        let result = MfaPolicyCollector.collect(&base_config(&srv));
        assert!(result.is_err());
    }

    #[test]
    fn raw_data_has_expected_keys() {
        let srv = mock_server(200, ACTIVE_REQUIRED_POLICY);
        let ev = &MfaPolicyCollector.collect(&base_config(&srv)).unwrap()[0];
        assert!(ev.raw_data.get("total_policies").is_some());
        assert!(ev.raw_data.get("inactive_policies").is_some());
        assert!(ev
            .raw_data
            .get("policies_without_required_factors")
            .is_some());
    }

    #[test]
    fn collector_does_not_set_test_transcript() {
        let srv = mock_server(200, EMPTY_POLICIES);
        let ev = &MfaPolicyCollector.collect(&base_config(&srv)).unwrap()[0];
        assert!(ev.test_transcript.is_none());
    }
}
