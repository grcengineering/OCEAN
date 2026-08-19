use std::collections::HashMap;

use anyhow::{anyhow, Result};
use chrono::Utc;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId,
};
use crate::module::{observer::Observer, CredentialReq, Module};

// ─── Factor taxonomy ─────────────────────────────────────────────────────────

/// Phishing-resistant factor IDs (FIDO2/WebAuthn, SmartCard).
const PR_FACTORS: [&str; 3] = ["fido_webauthn", "smart_card_idp", "webauthn"];

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

// ─── MfaPolicyObserver ───────────────────────────────────────────────────────

/// Queries Okta MFA enrollment policies and normalizes them into OCEAN evidence.
/// Generates findings for inactive policies or policies without required factors.
///
/// Required config: `OKTA_API_TOKEN`, `OKTA_DOMAIN`.
/// Optional: `OKTA_BASE_URL` (test override — defaults to `https://{OKTA_DOMAIN}`).
pub struct MfaPolicyObserver;

impl Module for MfaPolicyObserver {
    fn id(&self) -> &str {
        "okta.mfa_policy"
    }
    fn name(&self) -> &str {
        "Okta MFA Policy Observer"
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

impl Observer for MfaPolicyObserver {
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
            // Supports both legacy `settings.factors` (object) and newer
            // `settings.authenticators` (array) formats.
            let settings = policy.get("settings");
            let has_required_factor = settings
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
                .unwrap_or(false)
                || settings
                    .and_then(|s| s.get("authenticators"))
                    .and_then(|a| a.as_array())
                    .map(|auths| {
                        auths.iter().any(|auth| {
                            let key = auth.get("key").and_then(|v| v.as_str()).unwrap_or("");
                            // Only count non-password authenticators as MFA factors
                            key != "okta_password"
                                && auth
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

        // ── iam_auth: factor classification from first active policy ─────────
        let mut required_factors: Vec<String> = Vec::new();
        let mut optional_factors: Vec<String> = Vec::new();
        let mut not_allowed_factors: Vec<String> = Vec::new();
        let mut first_active_policy_name = String::new();

        let first_active = policies
            .iter()
            .find(|p| p.get("status").and_then(|v| v.as_str()).unwrap_or("") == "ACTIVE");

        if let Some(active_policy) = first_active {
            first_active_policy_name = active_policy
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let active_settings = active_policy.get("settings");

            // Legacy `settings.factors` (object keyed by factor ID)
            if let Some(factors_obj) = active_settings
                .and_then(|s| s.get("factors"))
                .and_then(|f| f.as_object())
            {
                for (factor_id, factor_val) in factors_obj {
                    let enroll_state = factor_val
                        .get("enroll")
                        .and_then(|e| e.get("self"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("NOT_ALLOWED");

                    match enroll_state {
                        "REQUIRED" => required_factors.push(factor_id.clone()),
                        "OPTIONAL" => optional_factors.push(factor_id.clone()),
                        _ => not_allowed_factors.push(factor_id.clone()),
                    }
                }
            }

            // Newer `settings.authenticators` (array of {key, enroll} objects)
            if let Some(auths_arr) = active_settings
                .and_then(|s| s.get("authenticators"))
                .and_then(|a| a.as_array())
            {
                // Only process if factors didn't populate (avoid double-counting)
                if required_factors.is_empty()
                    && optional_factors.is_empty()
                    && not_allowed_factors.is_empty()
                {
                    for auth in auths_arr {
                        let key = auth
                            .get("key")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown")
                            .to_string();
                        let enroll_state = auth
                            .get("enroll")
                            .and_then(|e| e.get("self"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("NOT_ALLOWED");

                        match enroll_state {
                            "REQUIRED" => required_factors.push(key),
                            "OPTIONAL" => optional_factors.push(key),
                            _ => not_allowed_factors.push(key),
                        }
                    }
                }
            }
        }

        let pr_required = required_factors
            .iter()
            .any(|f| PR_FACTORS.contains(&f.as_str()));

        let phishable_in_required_or_optional = required_factors
            .iter()
            .chain(optional_factors.iter())
            .any(|f| !PR_FACTORS.contains(&f.as_str()));

        let pr_exclusive = !phishable_in_required_or_optional;
        let phishable_allowed = phishable_in_required_or_optional;

        let policy_type = if pr_exclusive && pr_required {
            "phishing_resistant"
        } else {
            "mfa"
        };

        // ── existing findings / status logic (unchanged) ─────────────────────

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
            "iam_auth": {
                "policy_layer": "enrollment",
                "policy_type": policy_type,
                "provider": "okta",
                "policy_name": first_active_policy_name,
                "policy_scope": "all",
                "factor_policy": {
                    "required": required_factors,
                    "optional": optional_factors,
                    "not_allowed": not_allowed_factors,
                },
                "phishing_resistant_required": pr_required,
                "phishing_resistant_exclusive": pr_exclusive,
                "phishable_factors_allowed": phishable_allowed,
            },
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

    // ── Metadata ─────────────────────────────────────────────────────────────

    #[test]
    fn mfa_policy_id() {
        assert_eq!(MfaPolicyObserver.id(), "okta.mfa_policy");
    }

    #[test]
    fn mfa_policy_name() {
        assert_eq!(MfaPolicyObserver.name(), "Okta MFA Policy Observer");
    }

    #[test]
    fn mfa_policy_version() {
        assert_eq!(MfaPolicyObserver.version(), "0.1.0");
    }

    #[test]
    fn mfa_policy_source_system() {
        assert_eq!(MfaPolicyObserver.source_system(), "okta");
    }

    #[test]
    fn mfa_policy_evidence_types() {
        assert_eq!(MfaPolicyObserver.evidence_types(), &[1001]);
    }

    #[test]
    fn mfa_policy_credential_requirements() {
        let reqs = MfaPolicyObserver.credential_requirements();
        assert_eq!(reqs.len(), 2);
        assert!(reqs
            .iter()
            .any(|r| r.name == "OKTA_API_TOKEN" && r.required));
        assert!(reqs.iter().any(|r| r.name == "OKTA_DOMAIN" && r.required));
    }

    // ── Config validation ────────────────────────────────────────────────────

    #[test]
    fn missing_api_token_errors() {
        let err = MfaPolicyObserver
            .observe(&HashMap::from([(
                "OKTA_DOMAIN".to_string(),
                "example.okta.com".to_string(),
            )]))
            .unwrap_err();
        assert!(err.to_string().contains("OKTA_API_TOKEN"));
    }

    #[test]
    fn missing_domain_errors() {
        let err = MfaPolicyObserver
            .observe(&HashMap::from([(
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
        let ev = &MfaPolicyObserver.observe(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert_eq!(ev.findings[0].title, "MFA Policies Compliant");
    }

    #[test]
    fn active_required_policy_is_effective() {
        let srv = mock_server(200, ACTIVE_REQUIRED_POLICY);
        let ev = &MfaPolicyObserver.observe(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert_eq!(ev.control_id, "mfa.enrollment_policy");
        assert_eq!(ev.class_uid, 1001);
        assert_eq!(ev.observables.len(), 1);
    }

    #[test]
    fn inactive_policy_is_ineffective() {
        let srv = mock_server(200, INACTIVE_POLICY);
        let ev = &MfaPolicyObserver.observe(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev.findings.iter().any(|f| f.title == "Inactive MFA Policy"));
    }

    #[test]
    fn active_no_required_factor_is_ineffective() {
        let srv = mock_server(200, ACTIVE_NO_REQUIRED_POLICY);
        let ev = &MfaPolicyObserver.observe(&base_config(&srv)).unwrap()[0];
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
        let result = MfaPolicyObserver.observe(&base_config(&srv));
        assert!(result.is_err());
    }

    #[test]
    fn raw_data_has_expected_keys() {
        let srv = mock_server(200, ACTIVE_REQUIRED_POLICY);
        let ev = &MfaPolicyObserver.observe(&base_config(&srv)).unwrap()[0];
        assert!(ev.raw_data.get("total_policies").is_some());
        assert!(ev.raw_data.get("inactive_policies").is_some());
        assert!(ev
            .raw_data
            .get("policies_without_required_factors")
            .is_some());
    }

    #[test]
    fn observer_does_not_set_test_transcript() {
        let srv = mock_server(200, EMPTY_POLICIES);
        let ev = &MfaPolicyObserver.observe(&base_config(&srv)).unwrap()[0];
        assert!(ev.test_transcript.is_none());
    }

    // ── iam_auth schema attribute fixtures ───────────────────────────────

    const PR_EXCLUSIVE_POLICY: &str = r#"[{
      "id": "pol_pr", "name": "PR Only Policy", "status": "ACTIVE",
      "settings": { "factors": {
        "fido_webauthn": { "enroll": { "self": "REQUIRED" } },
        "okta_otp": { "enroll": { "self": "NOT_ALLOWED" } },
        "okta_push": { "enroll": { "self": "NOT_ALLOWED" } }
      }}
    }]"#;

    const PR_WITH_FALLBACK_POLICY: &str = r#"[{
      "id": "pol_mixed", "name": "PR With Fallback", "status": "ACTIVE",
      "settings": { "factors": {
        "fido_webauthn": { "enroll": { "self": "REQUIRED" } },
        "okta_otp": { "enroll": { "self": "OPTIONAL" } }
      }}
    }]"#;

    const TOTP_ONLY_POLICY: &str = r#"[{
      "id": "pol_totp", "name": "TOTP Policy", "status": "ACTIVE",
      "settings": { "factors": {
        "okta_otp": { "enroll": { "self": "REQUIRED" } },
        "okta_push": { "enroll": { "self": "OPTIONAL" } }
      }}
    }]"#;

    // ── iam_auth tests ──────────────────────────────────────────────────

    #[test]
    fn pr_exclusive_policy_sets_booleans() {
        let srv = mock_server(200, PR_EXCLUSIVE_POLICY);
        let ev = &MfaPolicyObserver.observe(&base_config(&srv)).unwrap()[0];
        let iam = &ev.raw_data["iam_auth"];
        assert_eq!(iam["phishing_resistant_exclusive"], true);
        assert_eq!(iam["phishable_factors_allowed"], false);
    }

    #[test]
    fn pr_with_fallback_sets_phishable_allowed() {
        let srv = mock_server(200, PR_WITH_FALLBACK_POLICY);
        let ev = &MfaPolicyObserver.observe(&base_config(&srv)).unwrap()[0];
        let iam = &ev.raw_data["iam_auth"];
        assert_eq!(iam["phishable_factors_allowed"], true);
    }

    #[test]
    fn totp_only_sets_pr_required_false() {
        let srv = mock_server(200, TOTP_ONLY_POLICY);
        let ev = &MfaPolicyObserver.observe(&base_config(&srv)).unwrap()[0];
        let iam = &ev.raw_data["iam_auth"];
        assert_eq!(iam["phishing_resistant_required"], false);
    }

    #[test]
    fn raw_data_has_iam_auth_object() {
        let srv = mock_server(200, ACTIVE_REQUIRED_POLICY);
        let ev = &MfaPolicyObserver.observe(&base_config(&srv)).unwrap()[0];
        assert!(ev.raw_data.get("iam_auth").is_some());
        assert!(ev.raw_data["iam_auth"].get("factor_policy").is_some());
    }

    #[test]
    fn policy_type_phishing_resistant_when_exclusive() {
        let srv = mock_server(200, PR_EXCLUSIVE_POLICY);
        let ev = &MfaPolicyObserver.observe(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.raw_data["iam_auth"]["policy_type"], "phishing_resistant");
    }

    #[test]
    fn policy_type_mfa_when_phishable_allowed() {
        let srv = mock_server(200, PR_WITH_FALLBACK_POLICY);
        let ev = &MfaPolicyObserver.observe(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.raw_data["iam_auth"]["policy_type"], "mfa");
    }

    #[test]
    fn factor_policy_required_populated() {
        let srv = mock_server(200, PR_EXCLUSIVE_POLICY);
        let ev = &MfaPolicyObserver.observe(&base_config(&srv)).unwrap()[0];
        let required = ev.raw_data["iam_auth"]["factor_policy"]["required"]
            .as_array()
            .unwrap();
        let values: Vec<&str> = required.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(values.contains(&"fido_webauthn"));
    }

    #[test]
    fn factor_policy_not_allowed_populated() {
        let srv = mock_server(200, PR_EXCLUSIVE_POLICY);
        let ev = &MfaPolicyObserver.observe(&base_config(&srv)).unwrap()[0];
        let not_allowed = ev.raw_data["iam_auth"]["factor_policy"]["not_allowed"]
            .as_array()
            .unwrap();
        let values: Vec<&str> = not_allowed.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(values.contains(&"okta_otp"));
    }

    #[test]
    fn metadata_complete() {
        use crate::module::Module;
        let obs = MfaPolicyObserver;
        assert_eq!(obs.id(), "okta.mfa_policy");
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
        let result = MfaPolicyObserver.observe(&cfg);
        assert!(result.is_err());
    }

    #[test]
    fn api_connection_refused_returns_error() {
        let cfg = base_config("http://127.0.0.1:1");
        let result = MfaPolicyObserver.observe(&cfg);
        assert!(result.is_err());
    }

    #[test]
    fn non_json_array_body_errors() {
        let srv = mock_server(200, r#""not an array""#);
        let result = MfaPolicyObserver.observe(&base_config(&srv));
        assert!(result.is_err());
    }

    // Authenticators-format policy (newer API response shape)
    const AUTHENTICATORS_POLICY: &str = r#"[{
        "id": "pol_auth",
        "name": "Auth Policy",
        "status": "ACTIVE",
        "settings": {
            "authenticators": [
                {"key": "webauthn", "enroll": {"self": "REQUIRED"}},
                {"key": "okta_password", "enroll": {"self": "REQUIRED"}},
                {"key": "okta_email", "enroll": {"self": "OPTIONAL"}}
            ]
        }
    }]"#;

    #[test]
    fn authenticators_format_policy_is_effective() {
        let srv = mock_server(200, AUTHENTICATORS_POLICY);
        let ev = &MfaPolicyObserver.observe(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        let iam = &ev.raw_data["iam_auth"];
        // webauthn is PR; okta_password is excluded; okta_email is optional phishable
        assert_eq!(iam["phishable_factors_allowed"], true);
    }

    #[test]
    fn authenticators_format_policy_type_is_mfa_when_phishable_optional() {
        let srv = mock_server(200, AUTHENTICATORS_POLICY);
        let ev = &MfaPolicyObserver.observe(&base_config(&srv)).unwrap()[0];
        let iam = &ev.raw_data["iam_auth"];
        assert_eq!(iam["policy_type"], "mfa");
    }

    // Policy where factors are all NOT_ALLOWED (no required or optional)
    const ALL_NOT_ALLOWED_POLICY: &str = r#"[{
        "id": "pol_none",
        "name": "No Factors Policy",
        "status": "ACTIVE",
        "settings": {
            "factors": {
                "okta_otp": {"enroll": {"self": "NOT_ALLOWED"}},
                "okta_push": {"enroll": {"self": "NOT_ALLOWED"}}
            }
        }
    }]"#;

    #[test]
    fn policy_with_no_required_factors_not_allowed_is_ineffective() {
        let srv = mock_server(200, ALL_NOT_ALLOWED_POLICY);
        let ev = &MfaPolicyObserver.observe(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "No Required MFA Factors"));
        let iam = &ev.raw_data["iam_auth"];
        assert_eq!(iam["phishing_resistant_required"], false);
        assert_eq!(iam["phishable_factors_allowed"], false);
        assert_eq!(iam["policy_type"], "mfa");
    }

    #[test]
    fn not_allowed_factors_are_populated_in_factor_policy() {
        let srv = mock_server(200, ALL_NOT_ALLOWED_POLICY);
        let ev = &MfaPolicyObserver.observe(&base_config(&srv)).unwrap()[0];
        let not_allowed = ev.raw_data["iam_auth"]["factor_policy"]["not_allowed"]
            .as_array()
            .unwrap();
        assert!(!not_allowed.is_empty());
    }

    #[test]
    fn authenticators_format_requires_webauthn_is_pr_required() {
        // Only webauthn required; okta_password excluded from count
        let body = r#"[{
            "id": "pol_pr_auth",
            "name": "PR Auth Policy",
            "status": "ACTIVE",
            "settings": {
                "authenticators": [
                    {"key": "webauthn", "enroll": {"self": "REQUIRED"}},
                    {"key": "okta_password", "enroll": {"self": "REQUIRED"}}
                ]
            }
        }]"#;
        let srv = mock_server(200, body);
        let ev = &MfaPolicyObserver.observe(&base_config(&srv)).unwrap()[0];
        let iam = &ev.raw_data["iam_auth"];
        assert_eq!(iam["phishing_resistant_required"], true);
    }

    #[test]
    fn factors_format_takes_priority_over_authenticators() {
        // Policy has BOTH factors and authenticators — factors takes priority
        let body = r#"[{
            "id": "pol_dual",
            "name": "Dual Format",
            "status": "ACTIVE",
            "settings": {
                "factors": {
                    "fido_webauthn": {"enroll": {"self": "REQUIRED"}}
                },
                "authenticators": [
                    {"key": "okta_otp", "enroll": {"self": "REQUIRED"}}
                ]
            }
        }]"#;
        let srv = mock_server(200, body);
        let ev = &MfaPolicyObserver.observe(&base_config(&srv)).unwrap()[0];
        let required = ev.raw_data["iam_auth"]["factor_policy"]["required"]
            .as_array()
            .unwrap();
        let values: Vec<&str> = required.iter().map(|v| v.as_str().unwrap()).collect();
        // Should contain fido_webauthn from factors; authenticators are skipped
        assert!(values.contains(&"fido_webauthn"));
        // okta_otp from authenticators should NOT appear (double-count prevention)
        assert!(!values.contains(&"okta_otp"));
    }

    #[test]
    fn policy_name_is_captured_in_iam_auth() {
        let srv = mock_server(200, ACTIVE_REQUIRED_POLICY);
        let ev = &MfaPolicyObserver.observe(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.raw_data["iam_auth"]["policy_name"], "Default MFA Policy");
    }

    #[test]
    fn okta_get_invalid_json_on_200_exercises_closure() {
        let srv = mock_server(200, "not json {");
        let _ = MfaPolicyObserver.observe(&base_config(&srv));
    }

    #[test]
    fn okta_get_invalid_json_on_error_status_exercises_closure() {
        let srv = mock_server(500, "<html>500</html>");
        let _ = MfaPolicyObserver.observe(&base_config(&srv));
    }
}
