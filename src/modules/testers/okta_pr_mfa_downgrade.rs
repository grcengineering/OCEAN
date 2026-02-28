use std::collections::HashMap;

use anyhow::{anyhow, Result};
use chrono::Utc;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId,
    TranscriptRecorder,
};
use crate::module::{
    tester::Tester, CredentialReq, EnvironmentScope, Module, SafetyClassification,
};

// ─── Factor classification ──────────────────────────────────────────────────

/// Factor types considered phishing-resistant (FIDO2 / WebAuthn).
const PR_FACTOR_TYPES: [&str; 1] = ["webauthn"];

/// Factor types vulnerable to real-time phishing (adversary-in-the-middle).
const PHISHABLE_FACTOR_TYPES: [&str; 6] = [
    "token:software:totp",
    "push",
    "sms",
    "call",
    "email",
    "token:hotp",
];

// ─── PrMfaDowngradeTester ───────────────────────────────────────────────────

/// Verifies that when a user signs in to Okta, ONLY phishing-resistant MFA
/// factors are offered in the MFA challenge — no phishable fallbacks (TOTP,
/// push, SMS, etc.).
///
/// The attack it detects: an adversary-in-the-middle proxy can capture TOTP
/// codes in real time. If TOTP is offered alongside WebAuthn, the attacker can
/// use TOTP to complete authentication. This tester proves whether that
/// downgrade path exists.
///
/// Required config: `OKTA_API_TOKEN`, `OKTA_DOMAIN`, `OKTA_TEST_USER`,
/// `OKTA_TEST_PASSWORD`.
/// Optional: `OKTA_BASE_URL` (test override — defaults to `https://{OKTA_DOMAIN}`).
pub struct PrMfaDowngradeTester;

impl Module for PrMfaDowngradeTester {
    fn id(&self) -> &str {
        "okta.pr_mfa_downgrade"
    }
    fn name(&self) -> &str {
        "Okta Phishing-Resistant MFA Downgrade Tester"
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
                description: "Okta API token for pre-flight check".to_string(),
                required: true,
            },
            CredentialReq {
                name: "OKTA_DOMAIN".to_string(),
                cred_type: "domain".to_string(),
                description: "Okta org domain e.g. example.okta.com".to_string(),
                required: true,
            },
            CredentialReq {
                name: "OKTA_TEST_USER".to_string(),
                cred_type: "username".to_string(),
                description: "Test user username".to_string(),
                required: true,
            },
            CredentialReq {
                name: "OKTA_TEST_PASSWORD".to_string(),
                cred_type: "password".to_string(),
                description: "Test user password".to_string(),
                required: true,
            },
        ]
    }
}

impl Tester for PrMfaDowngradeTester {
    fn safety_class(&self) -> SafetyClassification {
        SafetyClassification::Safe
    }
    fn environment_scope(&self) -> EnvironmentScope {
        EnvironmentScope::Production
    }

    fn pre_flight_checks(&self) -> Vec<String> {
        vec![
            "verify Okta API reachable".to_string(),
            "verify test credentials configured".to_string(),
        ]
    }

    fn cleanup_procedures(&self) -> Vec<String> {
        vec![] // Safe read-only probe — no state changes, no cleanup needed.
    }

    fn test(&self, config: &HashMap<String, String>) -> Result<Vec<Evidence>> {
        let _token = config
            .get("OKTA_API_TOKEN")
            .ok_or_else(|| anyhow!("OKTA_API_TOKEN is required"))?;
        let domain = config
            .get("OKTA_DOMAIN")
            .ok_or_else(|| anyhow!("OKTA_DOMAIN is required"))?;
        let test_user = config
            .get("OKTA_TEST_USER")
            .ok_or_else(|| anyhow!("OKTA_TEST_USER is required for PR MFA downgrade testing"))?;
        let test_password = config.get("OKTA_TEST_PASSWORD").ok_or_else(|| {
            anyhow!("OKTA_TEST_PASSWORD is required for PR MFA downgrade testing")
        })?;

        // OKTA_BASE_URL overrides the default https://{domain} (used in tests).
        let base_url = config
            .get("OKTA_BASE_URL")
            .map(|s| {
                let trimmed = s.trim_end_matches('/');
                if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
                    trimmed.to_string()
                } else {
                    format!("https://{}", trimmed)
                }
            })
            .unwrap_or_else(|| format!("https://{}", domain));

        let now = Utc::now();
        let mut recorder = TranscriptRecorder::new();
        let endpoint = "/api/v1/authn";
        let url = format!("{}{}", base_url, endpoint);

        recorder.record_action(
            "initiate primary authentication without MFA factor",
            Some(json!({
                "target": domain,
                "user": test_user,
                "endpoint": endpoint,
            })),
        );

        recorder.record_action(
            "submit credentials to check offered MFA factors",
            Some(json!({
                "credentials": "redacted",
                "checking": "offered_factors_in_mfa_challenge",
            })),
        );

        // POST credentials — observe which factors are offered in the challenge.
        let post_resp = ureq::post(&url)
            .set("Content-Type", "application/json")
            .set("Accept", "application/json")
            .send_json(json!({
                "username": test_user,
                "password": test_password,
            }));

        let (http_status, authn_status, body): (u16, String, Value) = match post_resp {
            Ok(r) => {
                let code = r.status();
                let b: Value = r.into_json().unwrap_or(json!({}));
                let s = b
                    .get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                (code, s, b)
            }
            Err(ureq::Error::Status(code, r)) => {
                let b: Value = r.into_json().unwrap_or(json!({}));
                let s = b
                    .get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                (code, s, b)
            }
            Err(e) => return Err(anyhow!("Okta authn request failed: {}", e)),
        };

        // ── Parse offered factors from _embedded.factors ────────────────────
        let offered_factors: Vec<String> = body
            .get("_embedded")
            .and_then(|e| e.get("factors"))
            .and_then(|f| f.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|f| f.get("factorType").and_then(|ft| ft.as_str()))
                    .map(|s| s.to_string())
                    .collect()
            })
            .unwrap_or_default();

        // ── Classify factors ────────────────────────────────────────────────
        let pr_offered: Vec<String> = offered_factors
            .iter()
            .filter(|f| PR_FACTOR_TYPES.contains(&f.as_str()))
            .cloned()
            .collect();
        let phishable_offered: Vec<String> = offered_factors
            .iter()
            .filter(|f| PHISHABLE_FACTOR_TYPES.contains(&f.as_str()))
            .cloned()
            .collect();
        let mut downgrade_possible = !phishable_offered.is_empty();

        // ── Determine outcome ───────────────────────────────────────────────
        let (status_id, status_text, findings) =
            if http_status == 401 || http_status == 403 {
                downgrade_possible = false;
                (
                    StatusId::Effective,
                    "Primary authentication rejected — no factor challenge needed".to_string(),
                    vec![Finding {
                        title: "Authentication Rejected Before Factor Challenge".to_string(),
                        description: format!(
                            "Authentication rejected with HTTP {} — no MFA factor challenge reached",
                            http_status
                        ),
                        severity_id: 0,
                    }],
                )
            } else if authn_status == "SUCCESS" {
                downgrade_possible = true;
                (
                    StatusId::Ineffective,
                    "MFA not required at sign-in".to_string(),
                    vec![Finding {
                        title: "MFA Not Required at Sign-In".to_string(),
                        description: "Authentication succeeded without any MFA challenge"
                            .to_string(),
                        severity_id: 4,
                    }],
                )
            } else if authn_status == "MFA_ENROLL" {
                (
                    StatusId::Ineffective,
                    "MFA enrollment incomplete for test user".to_string(),
                    vec![Finding {
                        title: "MFA Enrollment Incomplete".to_string(),
                        description: "Test user not enrolled in any MFA factor".to_string(),
                        severity_id: 2,
                    }],
                )
            } else if authn_status == "MFA_REQUIRED"
                || authn_status == "MFA_CHALLENGE"
                || http_status == 200
            {
                if downgrade_possible {
                    (
                        StatusId::Ineffective,
                        format!("Phishable MFA factors offered: {:?}", phishable_offered),
                        vec![Finding {
                            title: "Phishable MFA Factors Available at Sign-In".to_string(),
                            description: format!(
                                "Phishable factors offered: {:?}. Downgrade attack possible.",
                                phishable_offered
                            ),
                            severity_id: 3,
                        }],
                    )
                } else {
                    (
                        StatusId::Effective,
                        "Only phishing-resistant factors offered in MFA challenge".to_string(),
                        vec![Finding {
                            title: "Only Phishing-Resistant Factors Offered".to_string(),
                            description:
                                "MFA challenge only offers phishing-resistant factors — no downgrade path"
                                    .to_string(),
                            severity_id: 0,
                        }],
                    )
                }
            } else {
                (
                    StatusId::Effective,
                    format!(
                        "Auth did not succeed: HTTP {} {:?}",
                        http_status, authn_status
                    ),
                    vec![Finding {
                        title: "No Downgrade Path Detected".to_string(),
                        description: format!(
                            "Authentication did not succeed (HTTP {}, status: {:?})",
                            http_status, authn_status
                        ),
                        severity_id: 0,
                    }],
                )
            };

        // ── Observations ────────────────────────────────────────────────────
        recorder.record_observation(
            format!("HTTP {} authn_status: {:?}", http_status, authn_status),
            !downgrade_possible,
        );
        recorder.record_observation(
            format!("offered factors: {:?}", offered_factors),
            true,
        );
        recorder.record_observation(
            format!("phishable factors offered: {:?}", phishable_offered),
            phishable_offered.is_empty(),
        );

        let transcript = recorder.finalize();

        let raw_data = json!({
            "test_scenario": "pr_mfa_downgrade_check",
            "target_system": domain,
            "offered_factors": offered_factors,
            "pr_factors_offered": pr_offered,
            "phishable_factors_offered": phishable_offered,
            "downgrade_possible": downgrade_possible,
            "authn_status": authn_status,
            "http_status": http_status,
        });

        Ok(vec![Evidence {
            id: Uuid::new_v4(),
            control_id: "mfa.phishing_resistant_enforcement".to_string(),
            class_uid: 1001,
            category_uid: 1,
            activity_id: 4,
            time: now,
            confidence_level: ConfidenceLevel::ActiveVerification,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "okta.pr_mfa_downgrade".to_string(),
                    version: "0.1.0".to_string(),
                    module_type: "tester".to_string(),
                },
                source: SourceInfo {
                    system: "okta".to_string(),
                    api_version: "v1".to_string(),
                    endpoint: endpoint.to_string(),
                },
                original_time: None,
                processed_time: now,
                safety_classification: Some("safe".to_string()),
            },
            observables: vec![
                Observable {
                    obs_type: "resource".to_string(),
                    value: "okta_sign_on_policy".to_string(),
                    name: String::new(),
                },
                Observable {
                    obs_type: "user".to_string(),
                    value: test_user.clone(),
                    name: String::new(),
                },
            ],
            status_id,
            status: status_text,
            raw_data,
            findings,
            test_transcript: Some(transcript),
            enrichments: vec![],
        }])
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Response fixtures ────────────────────────────────────────────────

    const MFA_REQUIRED_WITH_WEBAUTHN_ONLY: &str = r#"{"status":"MFA_REQUIRED","_embedded":{"factors":[{"factorType":"webauthn","id":"f1","status":"ACTIVE"}]}}"#;

    const MFA_REQUIRED_WITH_PHISHABLE: &str = r#"{"status":"MFA_REQUIRED","_embedded":{"factors":[{"factorType":"webauthn","id":"f1","status":"ACTIVE"},{"factorType":"token:software:totp","id":"f2","status":"ACTIVE"}]}}"#;

    const MFA_REQUIRED_TOTP_ONLY: &str = r#"{"status":"MFA_REQUIRED","_embedded":{"factors":[{"factorType":"token:software:totp","id":"f3","status":"ACTIVE"}]}}"#;

    const MFA_REQUIRED_NO_FACTORS: &str = r#"{"status":"MFA_REQUIRED"}"#;

    const SUCCESS_RESPONSE: &str = r#"{"status":"SUCCESS","sessionToken":"tok123"}"#;

    const MFA_ENROLL_RESPONSE: &str = r#"{"status":"MFA_ENROLL"}"#;

    const UNAUTH_RESPONSE: &str =
        r#"{"errorCode":"E0000004","errorSummary":"Authentication failed"}"#;

    // ── Mock server (same pattern as okta.rs) ────────────────────────────

    fn mock_server(status: u16, body: &str) -> String {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let body = body.to_string();

        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                // Drain the full request to avoid Windows TCP RST on close.
                let mut buf = [0u8; 8192];
                let _ = stream.read(&mut buf);
                let resp = format!(
                    "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {len}\r\nConnection: close\r\n\r\n{body}",
                    len = body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
                // Graceful shutdown: send FIN, drain remaining data, then drop.
                let _ = stream.shutdown(std::net::Shutdown::Write);
                let mut drain = [0u8; 256];
                while matches!(stream.read(&mut drain), Ok(n) if n > 0) {}
            }
        });

        format!("http://127.0.0.1:{}", addr.port())
    }

    fn base_config(base_url: &str) -> HashMap<String, String> {
        HashMap::from([
            ("OKTA_API_TOKEN".to_string(), "test_token".to_string()),
            ("OKTA_DOMAIN".to_string(), "example.okta.com".to_string()),
            ("OKTA_TEST_USER".to_string(), "test@example.com".to_string()),
            ("OKTA_TEST_PASSWORD".to_string(), "TestPass123!".to_string()),
            ("OKTA_BASE_URL".to_string(), base_url.to_string()),
        ])
    }

    // ── Metadata tests ──────────────────────────────────────────────────

    #[test]
    fn pr_mfa_downgrade_id() {
        assert_eq!(PrMfaDowngradeTester.id(), "okta.pr_mfa_downgrade");
    }

    #[test]
    fn pr_mfa_downgrade_name() {
        assert_eq!(
            PrMfaDowngradeTester.name(),
            "Okta Phishing-Resistant MFA Downgrade Tester"
        );
    }

    #[test]
    fn pr_mfa_downgrade_safety_class() {
        assert_eq!(
            PrMfaDowngradeTester.safety_class(),
            SafetyClassification::Safe
        );
    }

    #[test]
    fn pr_mfa_downgrade_environment_scope() {
        assert_eq!(
            PrMfaDowngradeTester.environment_scope(),
            EnvironmentScope::Production
        );
    }

    #[test]
    fn pr_mfa_downgrade_preflight_nonempty() {
        assert!(!PrMfaDowngradeTester.pre_flight_checks().is_empty());
    }

    #[test]
    fn pr_mfa_downgrade_cleanup_empty() {
        assert!(PrMfaDowngradeTester.cleanup_procedures().is_empty());
    }

    #[test]
    fn pr_mfa_downgrade_credential_requirements_count() {
        let reqs = PrMfaDowngradeTester.credential_requirements();
        assert_eq!(reqs.len(), 4);
    }

    // ── HTTP integration tests ──────────────────────────────────────────

    #[test]
    fn only_pr_factors_offered_is_effective() {
        let srv = mock_server(200, MFA_REQUIRED_WITH_WEBAUTHN_ONLY);
        let ev = &PrMfaDowngradeTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
    }

    #[test]
    fn phishable_factor_offered_is_ineffective() {
        let srv = mock_server(200, MFA_REQUIRED_WITH_PHISHABLE);
        let ev = &PrMfaDowngradeTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
    }

    #[test]
    fn totp_only_is_ineffective() {
        let srv = mock_server(200, MFA_REQUIRED_TOTP_ONLY);
        let ev = &PrMfaDowngradeTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
    }

    #[test]
    fn no_factors_offered_is_effective() {
        let srv = mock_server(200, MFA_REQUIRED_NO_FACTORS);
        let ev = &PrMfaDowngradeTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
    }

    #[test]
    fn success_response_is_ineffective() {
        let srv = mock_server(200, SUCCESS_RESPONSE);
        let ev = &PrMfaDowngradeTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
    }

    #[test]
    fn mfa_enroll_response_is_ineffective() {
        let srv = mock_server(200, MFA_ENROLL_RESPONSE);
        let ev = &PrMfaDowngradeTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
    }

    #[test]
    fn http_401_is_effective() {
        let srv = mock_server(401, UNAUTH_RESPONSE);
        let ev = &PrMfaDowngradeTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
    }

    #[test]
    fn http_403_is_effective() {
        let srv = mock_server(403, r#"{"errorCode":"E0000006","errorSummary":"Forbidden"}"#);
        let ev = &PrMfaDowngradeTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
    }

    #[test]
    fn has_test_transcript() {
        let srv = mock_server(200, MFA_REQUIRED_WITH_PHISHABLE);
        let ev = &PrMfaDowngradeTester.test(&base_config(&srv)).unwrap()[0];
        let t = ev.test_transcript.as_ref().unwrap();
        assert!(!t.actions_attempted.is_empty());
    }

    #[test]
    fn raw_data_has_downgrade_possible_key() {
        let srv = mock_server(200, MFA_REQUIRED_WITH_PHISHABLE);
        let ev = &PrMfaDowngradeTester.test(&base_config(&srv)).unwrap()[0];
        assert!(ev.raw_data.get("downgrade_possible").is_some());
    }

    #[test]
    fn phishable_offered_severity_3() {
        let srv = mock_server(200, MFA_REQUIRED_WITH_PHISHABLE);
        let ev = &PrMfaDowngradeTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.findings[0].severity_id, 3);
    }

    #[test]
    fn no_mfa_severity_4() {
        let srv = mock_server(200, SUCCESS_RESPONSE);
        let ev = &PrMfaDowngradeTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.findings[0].severity_id, 4);
    }

    #[test]
    fn pr_only_severity_0() {
        let srv = mock_server(200, MFA_REQUIRED_WITH_WEBAUTHN_ONLY);
        let ev = &PrMfaDowngradeTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.findings[0].severity_id, 0);
    }

    #[test]
    fn downgrade_possible_false_when_pr_only() {
        let srv = mock_server(200, MFA_REQUIRED_WITH_WEBAUTHN_ONLY);
        let ev = &PrMfaDowngradeTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.raw_data["downgrade_possible"].as_bool(), Some(false));
    }

    #[test]
    fn downgrade_possible_true_when_phishable() {
        let srv = mock_server(200, MFA_REQUIRED_WITH_PHISHABLE);
        let ev = &PrMfaDowngradeTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.raw_data["downgrade_possible"].as_bool(), Some(true));
    }

    #[test]
    fn offered_factors_populated() {
        let srv = mock_server(200, MFA_REQUIRED_WITH_PHISHABLE);
        let ev = &PrMfaDowngradeTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(
            ev.raw_data["offered_factors"].as_array().unwrap().len(),
            2
        );
    }

    #[test]
    fn has_two_observables() {
        let srv = mock_server(200, MFA_REQUIRED_WITH_WEBAUTHN_ONLY);
        let ev = &PrMfaDowngradeTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.observables.len(), 2);
        assert!(ev.observables.iter().any(|o| o.obs_type == "resource"));
        assert!(ev.observables.iter().any(|o| o.obs_type == "user"));
    }

    #[test]
    fn missing_test_user_errors() {
        let config = HashMap::from([
            ("OKTA_API_TOKEN".to_string(), "tok".to_string()),
            ("OKTA_DOMAIN".to_string(), "example.okta.com".to_string()),
            ("OKTA_TEST_PASSWORD".to_string(), "p".to_string()),
        ]);
        let err = PrMfaDowngradeTester.test(&config).unwrap_err();
        assert!(err.to_string().contains("OKTA_TEST_USER"));
    }

    #[test]
    fn missing_test_password_errors() {
        let config = HashMap::from([
            ("OKTA_API_TOKEN".to_string(), "tok".to_string()),
            ("OKTA_DOMAIN".to_string(), "example.okta.com".to_string()),
            ("OKTA_TEST_USER".to_string(), "u".to_string()),
        ]);
        let err = PrMfaDowngradeTester.test(&config).unwrap_err();
        assert!(err.to_string().contains("OKTA_TEST_PASSWORD"));
    }
}
