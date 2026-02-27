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

// ─── MfaBypassTester ──────────────────────────────────────────────────────────

/// Attempts primary-factor authentication against Okta without providing an
/// MFA token to verify that MFA enforcement is working correctly. This is a
/// safe, read-only probe that makes no state changes — it only observes whether
/// the authentication attempt is properly blocked or requires MFA.
///
/// Required config: `OKTA_API_TOKEN`, `OKTA_DOMAIN`, `OKTA_TEST_USER`, `OKTA_TEST_PASSWORD`.
/// Optional: `OKTA_BASE_URL` (test override — defaults to `https://{OKTA_DOMAIN}`).
pub struct MfaBypassTester;

impl Module for MfaBypassTester {
    fn id(&self) -> &str { "okta.mfa_bypass" }
    fn name(&self) -> &str { "Okta MFA Bypass Tester" }
    fn version(&self) -> &str { "0.1.0" }
    fn source_system(&self) -> &str { "okta" }
    fn evidence_types(&self) -> &[i32] { &[1001] }

    fn credential_requirements(&self) -> Vec<CredentialReq> {
        vec![
            CredentialReq {
                name: "OKTA_API_TOKEN".to_string(),
                cred_type: "api_token".to_string(),
                description: "Okta API token (for pre-flight API reachability check)".to_string(),
                required: true,
            },
            CredentialReq {
                name: "OKTA_DOMAIN".to_string(),
                cred_type: "domain".to_string(),
                description: "Okta organization domain (e.g., example.okta.com)".to_string(),
                required: true,
            },
            CredentialReq {
                name: "OKTA_TEST_USER".to_string(),
                cred_type: "username".to_string(),
                description: "Test user username for MFA bypass attempt".to_string(),
                required: true,
            },
            CredentialReq {
                name: "OKTA_TEST_PASSWORD".to_string(),
                cred_type: "password".to_string(),
                description: "Test user password for MFA bypass attempt".to_string(),
                required: true,
            },
        ]
    }
}

impl Tester for MfaBypassTester {
    fn safety_class(&self) -> SafetyClassification { SafetyClassification::Safe }
    fn environment_scope(&self) -> EnvironmentScope { EnvironmentScope::Production }

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
            .ok_or_else(|| anyhow!("OKTA_TEST_USER is required for MFA bypass testing"))?;
        let test_password = config
            .get("OKTA_TEST_PASSWORD")
            .ok_or_else(|| anyhow!("OKTA_TEST_PASSWORD is required for MFA bypass testing"))?;

        // OKTA_BASE_URL overrides the default https://{domain} (used in tests).
        let base_url = config
            .get("OKTA_BASE_URL")
            .map(|s| s.trim_end_matches('/').to_string())
            .unwrap_or_else(|| format!("https://{}", domain));

        let now = Utc::now();
        let mut recorder = TranscriptRecorder::new();
        let safety_class = "safe".to_string();
        let endpoint = "/api/v1/authn";
        let url = format!("{}{}", base_url, endpoint);

        recorder.record_action(
            "initiate authentication without MFA token",
            Some(json!({
                "target": domain,
                "method": "primary_auth_only",
                "user": test_user,
                "endpoint": endpoint,
            })),
        );

        recorder.record_action(
            "submit credentials without MFA token",
            Some(json!({
                "credentials": "redacted",
                "mfa_token": "none",
            })),
        );

        // POST credentials without an MFA factor — observe the response.
        let post_resp = ureq::post(&url)
            .set("Content-Type", "application/json")
            .set("Accept", "application/json")
            .send_json(json!({
                "username": test_user,
                "password": test_password,
            }));

        let (http_status, authn_status): (u16, String) = match post_resp {
            Ok(r) => {
                let code = r.status();
                let body: Value = r.into_json().unwrap_or(json!({}));
                let status_str = body
                    .get("status")
                    .and_then(|s| s.as_str())
                    .unwrap_or("")
                    .to_string();
                (code, status_str)
            }
            Err(ureq::Error::Status(code, r)) => {
                let body: Value = r.into_json().unwrap_or(json!({}));
                let status_str = body
                    .get("status")
                    .and_then(|s| s.as_str())
                    .unwrap_or("")
                    .to_string();
                (code, status_str)
            }
            Err(e) => return Err(anyhow!("Okta authn request failed: {}", e)),
        };

        // Determine control effectiveness from the response.
        let (status_id, status_text, bypass_blocked) = if http_status == 401
            || http_status == 403
        {
            recorder.record_observation(
                &format!("authentication rejected with HTTP {}", http_status),
                true,
            );
            recorder.record_observation("MFA bypass attempt blocked", true);
            (
                StatusId::Effective,
                "MFA bypass attempt was correctly blocked".to_string(),
                true,
            )
        } else if authn_status == "MFA_REQUIRED" || authn_status == "MFA_ENROLL" {
            recorder.record_observation("Okta returned MFA_REQUIRED status", true);
            recorder.record_observation(
                "MFA challenge required before session can be established",
                true,
            );
            (
                StatusId::Effective,
                "MFA bypass attempt was correctly blocked".to_string(),
                true,
            )
        } else if authn_status == "SUCCESS" {
            recorder.record_observation(
                "authentication succeeded without MFA challenge",
                false,
            );
            recorder.record_observation(
                "session token issued without MFA verification",
                false,
            );
            (
                StatusId::Ineffective,
                "MFA bypass succeeded — authentication completed without MFA".to_string(),
                false,
            )
        } else {
            // Other statuses (LOCKED_OUT, PASSWORD_EXPIRED, etc.) mean bypass was blocked.
            recorder.record_observation(
                &format!(
                    "Okta returned status {:?} (HTTP {})",
                    authn_status, http_status
                ),
                true,
            );
            recorder.record_observation("authentication did not succeed without MFA", true);
            (
                StatusId::Effective,
                "MFA bypass attempt was correctly blocked".to_string(),
                true,
            )
        };

        let transcript = recorder.finalize();

        let findings = if bypass_blocked {
            vec![Finding {
                title: "MFA Bypass Blocked".to_string(),
                description: format!(
                    "Authentication attempt without MFA was blocked (HTTP {}, status: {:?})",
                    http_status, authn_status
                ),
                severity_id: 0,
            }]
        } else {
            vec![Finding {
                title: "MFA Bypass Succeeded".to_string(),
                description: "Authentication completed without MFA challenge — MFA enforcement is not working".to_string(),
                severity_id: 3,
            }]
        };

        let raw_data = json!({
            "test_scenario": "mfa_bypass_attempt",
            "target_system": domain,
            "test_result": if bypass_blocked { "blocked" } else { "bypassed" },
            "http_status": http_status,
            "authn_status": authn_status,
            "bypass_blocked": bypass_blocked,
        });

        Ok(vec![Evidence {
            id: Uuid::new_v4(),
            control_id: "mfa.enforcement".to_string(),
            class_uid: 1001,
            category_uid: 1,
            activity_id: 2,
            time: now,
            confidence_level: ConfidenceLevel::ActiveVerification,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "okta.mfa_bypass".to_string(),
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
                safety_classification: Some(safety_class),
            },
            observables: vec![
                Observable {
                    obs_type: "resource".to_string(),
                    value: "mfa_policy".to_string(),
                },
                Observable {
                    obs_type: "user".to_string(),
                    value: test_user.clone(),
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
                    "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {len}\r\nConnection: close\r\n\r\n{body}",
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
            ("OKTA_TEST_USER".to_string(), "test@example.com".to_string()),
            ("OKTA_TEST_PASSWORD".to_string(), "TestPass123!".to_string()),
            ("OKTA_BASE_URL".to_string(), base_url.to_string()),
        ])
    }

    // ── Metadata ─────────────────────────────────────────────────────────────

    #[test]
    fn mfa_bypass_id() { assert_eq!(MfaBypassTester.id(), "okta.mfa_bypass"); }

    #[test]
    fn mfa_bypass_name() { assert_eq!(MfaBypassTester.name(), "Okta MFA Bypass Tester"); }

    #[test]
    fn mfa_bypass_version() { assert_eq!(MfaBypassTester.version(), "0.1.0"); }

    #[test]
    fn mfa_bypass_source_system() { assert_eq!(MfaBypassTester.source_system(), "okta"); }

    #[test]
    fn mfa_bypass_evidence_types() { assert_eq!(MfaBypassTester.evidence_types(), &[1001]); }

    #[test]
    fn mfa_bypass_credential_requirements() {
        let reqs = MfaBypassTester.credential_requirements();
        assert_eq!(reqs.len(), 4);
        assert!(reqs.iter().any(|r| r.name == "OKTA_API_TOKEN" && r.required));
        assert!(reqs.iter().any(|r| r.name == "OKTA_DOMAIN" && r.required));
        assert!(reqs.iter().any(|r| r.name == "OKTA_TEST_USER" && r.required));
        assert!(reqs.iter().any(|r| r.name == "OKTA_TEST_PASSWORD" && r.required));
    }

    #[test]
    fn mfa_bypass_safety_class() {
        assert_eq!(MfaBypassTester.safety_class(), SafetyClassification::Safe);
    }

    #[test]
    fn mfa_bypass_environment_scope() {
        assert_eq!(MfaBypassTester.environment_scope(), EnvironmentScope::Production);
    }

    #[test]
    fn mfa_bypass_pre_flight_nonempty() {
        assert!(!MfaBypassTester.pre_flight_checks().is_empty());
    }

    #[test]
    fn mfa_bypass_cleanup_empty() {
        assert!(MfaBypassTester.cleanup_procedures().is_empty());
    }

    // ── Config validation ────────────────────────────────────────────────────

    #[test]
    fn missing_api_token_errors() {
        let config = HashMap::from([
            ("OKTA_DOMAIN".to_string(), "example.okta.com".to_string()),
            ("OKTA_TEST_USER".to_string(), "u".to_string()),
            ("OKTA_TEST_PASSWORD".to_string(), "p".to_string()),
        ]);
        let err = MfaBypassTester.test(&config).unwrap_err();
        assert!(err.to_string().contains("OKTA_API_TOKEN"));
    }

    #[test]
    fn missing_domain_errors() {
        let config = HashMap::from([
            ("OKTA_API_TOKEN".to_string(), "tok".to_string()),
            ("OKTA_TEST_USER".to_string(), "u".to_string()),
            ("OKTA_TEST_PASSWORD".to_string(), "p".to_string()),
        ]);
        let err = MfaBypassTester.test(&config).unwrap_err();
        assert!(err.to_string().contains("OKTA_DOMAIN"));
    }

    #[test]
    fn missing_test_user_errors() {
        let config = HashMap::from([
            ("OKTA_API_TOKEN".to_string(), "tok".to_string()),
            ("OKTA_DOMAIN".to_string(), "example.okta.com".to_string()),
            ("OKTA_TEST_PASSWORD".to_string(), "p".to_string()),
        ]);
        let err = MfaBypassTester.test(&config).unwrap_err();
        assert!(err.to_string().contains("OKTA_TEST_USER"));
    }

    #[test]
    fn missing_test_password_errors() {
        let config = HashMap::from([
            ("OKTA_API_TOKEN".to_string(), "tok".to_string()),
            ("OKTA_DOMAIN".to_string(), "example.okta.com".to_string()),
            ("OKTA_TEST_USER".to_string(), "u".to_string()),
        ]);
        let err = MfaBypassTester.test(&config).unwrap_err();
        assert!(err.to_string().contains("OKTA_TEST_PASSWORD"));
    }

    // ── HTTP integration ─────────────────────────────────────────────────────

    #[test]
    fn mfa_required_response_is_effective() {
        let srv = mock_server(200, r#"{"status":"MFA_REQUIRED","_links":{}}"#);
        let ev = &MfaBypassTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert!(ev.findings.iter().any(|f| f.title == "MFA Bypass Blocked"));
        assert_eq!(ev.class_uid, 1001);
        assert_eq!(ev.control_id, "mfa.enforcement");
    }

    #[test]
    fn mfa_enroll_response_is_effective() {
        let srv = mock_server(200, r#"{"status":"MFA_ENROLL"}"#);
        let ev = &MfaBypassTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert!(ev.findings.iter().any(|f| f.title == "MFA Bypass Blocked"));
    }

    #[test]
    fn success_response_is_ineffective() {
        let srv = mock_server(200, r#"{"status":"SUCCESS","sessionToken":"tok123"}"#);
        let ev = &MfaBypassTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev.findings.iter().any(|f| f.title == "MFA Bypass Succeeded"));
        assert_eq!(ev.findings[0].severity_id, 3);
    }

    #[test]
    fn http_401_is_effective() {
        let srv = mock_server(
            401,
            r#"{"errorCode":"E0000004","errorSummary":"Authentication failed"}"#,
        );
        let ev = &MfaBypassTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert!(ev.findings.iter().any(|f| f.title == "MFA Bypass Blocked"));
    }

    #[test]
    fn http_403_is_effective() {
        let srv = mock_server(403, r#"{"errorCode":"E0000006","errorSummary":"Unauthorized"}"#);
        let ev = &MfaBypassTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
    }

    #[test]
    fn locked_out_is_effective() {
        // LOCKED_OUT means bypass attempt still didn't succeed without MFA.
        let srv = mock_server(200, r#"{"status":"LOCKED_OUT"}"#);
        let ev = &MfaBypassTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
    }

    #[test]
    fn mfa_bypass_has_transcript() {
        let srv = mock_server(200, r#"{"status":"MFA_REQUIRED"}"#);
        let ev = &MfaBypassTester.test(&base_config(&srv)).unwrap()[0];
        let t = ev.test_transcript.as_ref().unwrap();
        assert!(!t.actions_attempted.is_empty());
        assert!(!t.observations.is_empty());
    }

    #[test]
    fn mfa_bypass_raw_data_keys() {
        let srv = mock_server(200, r#"{"status":"MFA_REQUIRED"}"#);
        let ev = &MfaBypassTester.test(&base_config(&srv)).unwrap()[0];
        assert!(ev.raw_data.get("test_scenario").is_some());
        assert!(ev.raw_data.get("bypass_blocked").is_some());
        assert!(ev.raw_data.get("authn_status").is_some());
        assert_eq!(ev.raw_data["bypass_blocked"].as_bool(), Some(true));
    }

    #[test]
    fn mfa_bypass_success_raw_data_bypassed() {
        let srv = mock_server(200, r#"{"status":"SUCCESS","sessionToken":"tok"}"#);
        let ev = &MfaBypassTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.raw_data["bypass_blocked"].as_bool(), Some(false));
        assert_eq!(ev.raw_data["test_result"].as_str(), Some("bypassed"));
    }

    #[test]
    fn mfa_bypass_has_two_observables() {
        let srv = mock_server(200, r#"{"status":"MFA_REQUIRED"}"#);
        let ev = &MfaBypassTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.observables.len(), 2);
        assert!(ev.observables.iter().any(|o| o.obs_type == "resource"));
        assert!(ev.observables.iter().any(|o| o.obs_type == "user"));
    }

    #[test]
    fn mfa_bypass_safety_classification_in_metadata() {
        let srv = mock_server(200, r#"{"status":"MFA_REQUIRED"}"#);
        let ev = &MfaBypassTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.metadata.safety_classification.as_deref(), Some("safe"));
    }

    #[test]
    fn mfa_bypass_unique_ids() {
        let srv1 = mock_server(200, r#"{"status":"MFA_REQUIRED"}"#);
        let srv2 = mock_server(200, r#"{"status":"MFA_REQUIRED"}"#);
        let id1 = MfaBypassTester.test(&base_config(&srv1)).unwrap()[0].id;
        let id2 = MfaBypassTester.test(&base_config(&srv2)).unwrap()[0].id;
        assert_ne!(id1, id2);
    }
}
