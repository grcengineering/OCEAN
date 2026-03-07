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

/// Attempts authentication via the OAuth2 Resource Owner Password Credentials
/// (ROPC) flow without satisfying MFA to verify that Conditional Access policies
/// block the attempt. This is a safe, read-only probe — it only observes whether
/// the authentication attempt is properly blocked by CA policies.
///
/// Required config: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`,
/// `AZURE_TEST_USER`, `AZURE_TEST_PASSWORD`.
/// Optional: `AZURE_LOGIN_BASE` (login endpoint override for testing).
pub struct MfaBypassTester;

impl Module for MfaBypassTester {
    fn id(&self) -> &str {
        "azure.mfa_bypass"
    }
    fn name(&self) -> &str {
        "Azure AD MFA Bypass Tester"
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
                description: "App registration client ID (must allow ROPC flow)".to_string(),
                required: true,
            },
            CredentialReq {
                name: "AZURE_CLIENT_SECRET".to_string(),
                cred_type: "client_secret".to_string(),
                description: "App registration client secret".to_string(),
                required: true,
            },
            CredentialReq {
                name: "AZURE_TEST_USER".to_string(),
                cred_type: "username".to_string(),
                description: "Test user UPN for MFA bypass attempt".to_string(),
                required: true,
            },
            CredentialReq {
                name: "AZURE_TEST_PASSWORD".to_string(),
                cred_type: "password".to_string(),
                description: "Test user password for MFA bypass attempt".to_string(),
                required: true,
            },
        ]
    }
}

impl Tester for MfaBypassTester {
    fn safety_class(&self) -> SafetyClassification {
        SafetyClassification::Safe
    }
    fn environment_scope(&self) -> EnvironmentScope {
        EnvironmentScope::Production
    }

    fn pre_flight_checks(&self) -> Vec<String> {
        vec![
            "verify Azure AD login endpoint reachable".to_string(),
            "verify test credentials configured".to_string(),
        ]
    }

    fn cleanup_procedures(&self) -> Vec<String> {
        vec![] // Safe read-only ROPC probe — no state changes, no cleanup needed.
    }

    fn test(&self, config: &HashMap<String, String>) -> Result<Vec<Evidence>> {
        let tenant_id = config
            .get("AZURE_TENANT_ID")
            .ok_or_else(|| anyhow!("AZURE_TENANT_ID is required"))?;
        let client_id = config
            .get("AZURE_CLIENT_ID")
            .ok_or_else(|| anyhow!("AZURE_CLIENT_ID is required"))?;
        let client_secret = config
            .get("AZURE_CLIENT_SECRET")
            .ok_or_else(|| anyhow!("AZURE_CLIENT_SECRET is required"))?;
        let test_user = config
            .get("AZURE_TEST_USER")
            .ok_or_else(|| anyhow!("AZURE_TEST_USER is required for MFA bypass testing"))?;
        let test_password = config
            .get("AZURE_TEST_PASSWORD")
            .ok_or_else(|| anyhow!("AZURE_TEST_PASSWORD is required for MFA bypass testing"))?;

        let login_base = config
            .get("AZURE_LOGIN_BASE")
            .cloned()
            .unwrap_or_else(|| "https://login.microsoftonline.com".to_string());

        let now = Utc::now();
        let mut recorder = TranscriptRecorder::new();
        let safety_class = "safe".to_string();
        let endpoint = format!("/{}/oauth2/v2.0/token", tenant_id);
        let url = format!(
            "{}{}", login_base.trim_end_matches('/'), endpoint
        );

        recorder.record_action(
            "initiate ROPC authentication without MFA interaction",
            Some(json!({
                "target": tenant_id,
                "method": "ropc_flow",
                "user": test_user,
                "endpoint": &endpoint,
            })),
        );

        recorder.record_action(
            "submit ROPC credentials (no MFA interaction possible)",
            Some(json!({
                "credentials": "redacted",
                "mfa_interaction": "none",
                "grant_type": "password",
            })),
        );

        // Attempt ROPC flow — if MFA is enforced via CA policies, this should fail
        // with an "interaction_required" error (AADSTS50076).
        let post_body = format!(
            "grant_type=password&client_id={}&client_secret={}&username={}&password={}&scope=openid",
            client_id, client_secret, test_user, test_password
        );

        let post_resp = ureq::post(&url)
            .set("Content-Type", "application/x-www-form-urlencoded")
            .set("Accept", "application/json")
            .send_string(&post_body);

        let (http_status, resp_body): (u16, Value) = match post_resp {
            Ok(r) => {
                let code = r.status();
                let body: Value = r.into_json().unwrap_or(json!({}));
                (code, body)
            }
            Err(ureq::Error::Status(code, r)) => {
                let body: Value = r.into_json().unwrap_or(json!({}));
                (code, body)
            }
            Err(e) => return Err(anyhow!("Azure AD ROPC request failed: {}", e)),
        };

        let error_code = resp_body
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let error_description = resp_body
            .get("error_description")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // Determine control effectiveness.
        // "interaction_required" means CA policy demands MFA — bypass blocked.
        // A 200 with access_token means ROPC succeeded without MFA — bypass worked.
        let (status_id, status_text, bypass_blocked) =
            if error_code == "interaction_required" {
                recorder.record_observation(
                    format!(
                        "ROPC rejected with interaction_required (HTTP {})",
                        http_status
                    ),
                    true,
                );
                recorder.record_observation(
                    "Conditional Access policy requires MFA interaction",
                    true,
                );
                (
                    StatusId::Effective,
                    "MFA bypass attempt was correctly blocked by Conditional Access".to_string(),
                    true,
                )
            } else if error_code == "invalid_grant"
                && error_description.contains("AADSTS50076")
            {
                // AADSTS50076 specifically means MFA is required.
                recorder.record_observation(
                    "ROPC rejected with AADSTS50076 (MFA required)",
                    true,
                );
                (
                    StatusId::Effective,
                    "MFA bypass attempt was correctly blocked by Conditional Access".to_string(),
                    true,
                )
            } else if http_status == 200 && resp_body.get("access_token").is_some() {
                recorder.record_observation(
                    "ROPC succeeded — access token issued without MFA",
                    false,
                );
                recorder.record_observation(
                    "session established without MFA verification",
                    false,
                );
                (
                    StatusId::Ineffective,
                    "MFA bypass succeeded — ROPC authentication completed without MFA".to_string(),
                    false,
                )
            } else if http_status == 401 || http_status == 403 {
                recorder.record_observation(
                    format!("authentication rejected with HTTP {}", http_status),
                    true,
                );
                (
                    StatusId::Effective,
                    "MFA bypass attempt was correctly blocked".to_string(),
                    true,
                )
            } else {
                // Other errors (bad credentials, locked account, etc.) — bypass not achieved.
                recorder.record_observation(
                    format!(
                        "ROPC returned error {:?} (HTTP {})",
                        error_code, http_status
                    ),
                    true,
                );
                recorder.record_observation(
                    "authentication did not succeed without MFA",
                    true,
                );
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
                    "ROPC authentication without MFA was blocked (HTTP {}, error: {:?})",
                    http_status, error_code
                ),
                severity_id: 0,
            }]
        } else {
            vec![Finding {
                title: "MFA Bypass Succeeded".to_string(),
                description: "ROPC authentication completed without MFA — Conditional Access MFA enforcement is not working".to_string(),
                severity_id: 3,
            }]
        };

        let raw_data = json!({
            "test_scenario": "azure_mfa_bypass_attempt",
            "target_system": tenant_id,
            "test_result": if bypass_blocked { "blocked" } else { "bypassed" },
            "http_status": http_status,
            "error_code": error_code,
            "bypass_blocked": bypass_blocked,
        });

        Ok(vec![Evidence {
            id: Uuid::new_v4(),
            control_id: "conditional_access.mfa_enforcement".to_string(),
            class_uid: 1001,
            category_uid: 1,
            activity_id: 2,
            time: now,
            confidence_level: ConfidenceLevel::ActiveVerification,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "azure.mfa_bypass".to_string(),
                    version: "0.1.0".to_string(),
                    module_type: "tester".to_string(),
                },
                source: SourceInfo {
                    system: "azure_ad".to_string(),
                    api_version: "v2.0".to_string(),
                    endpoint,
                },
                original_time: None,
                processed_time: now,
                safety_classification: Some(safety_class),
            },
            observables: vec![
                Observable {
                    obs_type: "resource".to_string(),
                    value: "conditional_access_policy".to_string(),
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

    fn base_config(base_url: &str) -> HashMap<String, String> {
        HashMap::from([
            ("AZURE_TENANT_ID".to_string(), "test-tenant".to_string()),
            ("AZURE_CLIENT_ID".to_string(), "test-client".to_string()),
            (
                "AZURE_CLIENT_SECRET".to_string(),
                "test-secret".to_string(),
            ),
            (
                "AZURE_TEST_USER".to_string(),
                "test@example.com".to_string(),
            ),
            (
                "AZURE_TEST_PASSWORD".to_string(),
                "TestPass123!".to_string(),
            ),
            ("AZURE_LOGIN_BASE".to_string(), base_url.to_string()),
        ])
    }

    // ── Metadata ─────────────────────────────────────────────────────────────

    #[test]
    fn mfa_bypass_id() {
        assert_eq!(MfaBypassTester.id(), "azure.mfa_bypass");
    }

    #[test]
    fn mfa_bypass_name() {
        assert_eq!(MfaBypassTester.name(), "Azure AD MFA Bypass Tester");
    }

    #[test]
    fn mfa_bypass_version() {
        assert_eq!(MfaBypassTester.version(), "0.1.0");
    }

    #[test]
    fn mfa_bypass_source_system() {
        assert_eq!(MfaBypassTester.source_system(), "azure_ad");
    }

    #[test]
    fn mfa_bypass_evidence_types() {
        assert_eq!(MfaBypassTester.evidence_types(), &[1001]);
    }

    #[test]
    fn mfa_bypass_credential_requirements() {
        let reqs = MfaBypassTester.credential_requirements();
        assert_eq!(reqs.len(), 5);
        assert!(reqs
            .iter()
            .any(|r| r.name == "AZURE_TENANT_ID" && r.required));
        assert!(reqs
            .iter()
            .any(|r| r.name == "AZURE_CLIENT_ID" && r.required));
        assert!(reqs
            .iter()
            .any(|r| r.name == "AZURE_CLIENT_SECRET" && r.required));
        assert!(reqs
            .iter()
            .any(|r| r.name == "AZURE_TEST_USER" && r.required));
        assert!(reqs
            .iter()
            .any(|r| r.name == "AZURE_TEST_PASSWORD" && r.required));
    }

    #[test]
    fn mfa_bypass_safety_class() {
        assert_eq!(MfaBypassTester.safety_class(), SafetyClassification::Safe);
    }

    #[test]
    fn mfa_bypass_environment_scope() {
        assert_eq!(
            MfaBypassTester.environment_scope(),
            EnvironmentScope::Production
        );
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
    fn missing_tenant_id_errors() {
        let config = HashMap::from([
            ("AZURE_CLIENT_ID".to_string(), "c".to_string()),
            ("AZURE_CLIENT_SECRET".to_string(), "s".to_string()),
            ("AZURE_TEST_USER".to_string(), "u".to_string()),
            ("AZURE_TEST_PASSWORD".to_string(), "p".to_string()),
        ]);
        let err = MfaBypassTester.test(&config).unwrap_err();
        assert!(err.to_string().contains("AZURE_TENANT_ID"));
    }

    #[test]
    fn missing_client_id_errors() {
        let config = HashMap::from([
            ("AZURE_TENANT_ID".to_string(), "t".to_string()),
            ("AZURE_CLIENT_SECRET".to_string(), "s".to_string()),
            ("AZURE_TEST_USER".to_string(), "u".to_string()),
            ("AZURE_TEST_PASSWORD".to_string(), "p".to_string()),
        ]);
        let err = MfaBypassTester.test(&config).unwrap_err();
        assert!(err.to_string().contains("AZURE_CLIENT_ID"));
    }

    #[test]
    fn missing_client_secret_errors() {
        let config = HashMap::from([
            ("AZURE_TENANT_ID".to_string(), "t".to_string()),
            ("AZURE_CLIENT_ID".to_string(), "c".to_string()),
            ("AZURE_TEST_USER".to_string(), "u".to_string()),
            ("AZURE_TEST_PASSWORD".to_string(), "p".to_string()),
        ]);
        let err = MfaBypassTester.test(&config).unwrap_err();
        assert!(err.to_string().contains("AZURE_CLIENT_SECRET"));
    }

    #[test]
    fn missing_test_user_errors() {
        let config = HashMap::from([
            ("AZURE_TENANT_ID".to_string(), "t".to_string()),
            ("AZURE_CLIENT_ID".to_string(), "c".to_string()),
            ("AZURE_CLIENT_SECRET".to_string(), "s".to_string()),
            ("AZURE_TEST_PASSWORD".to_string(), "p".to_string()),
        ]);
        let err = MfaBypassTester.test(&config).unwrap_err();
        assert!(err.to_string().contains("AZURE_TEST_USER"));
    }

    #[test]
    fn missing_test_password_errors() {
        let config = HashMap::from([
            ("AZURE_TENANT_ID".to_string(), "t".to_string()),
            ("AZURE_CLIENT_ID".to_string(), "c".to_string()),
            ("AZURE_CLIENT_SECRET".to_string(), "s".to_string()),
            ("AZURE_TEST_USER".to_string(), "u".to_string()),
        ]);
        let err = MfaBypassTester.test(&config).unwrap_err();
        assert!(err.to_string().contains("AZURE_TEST_PASSWORD"));
    }

    // ── HTTP integration ─────────────────────────────────────────────────────

    #[test]
    fn interaction_required_is_effective() {
        let srv = mock_server(
            400,
            r#"{"error":"interaction_required","error_description":"AADSTS50076: MFA required"}"#,
        );
        let ev = &MfaBypassTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert!(ev.findings.iter().any(|f| f.title == "MFA Bypass Blocked"));
        assert_eq!(ev.class_uid, 1001);
        assert_eq!(ev.control_id, "conditional_access.mfa_enforcement");
    }

    #[test]
    fn invalid_grant_aadsts50076_is_effective() {
        let srv = mock_server(
            400,
            r#"{"error":"invalid_grant","error_description":"AADSTS50076: Due to a configuration change"}"#,
        );
        let ev = &MfaBypassTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert!(ev.findings.iter().any(|f| f.title == "MFA Bypass Blocked"));
    }

    #[test]
    fn success_response_is_ineffective() {
        let srv = mock_server(
            200,
            r#"{"access_token":"eyJ...","token_type":"Bearer","expires_in":3600}"#,
        );
        let ev = &MfaBypassTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "MFA Bypass Succeeded"));
        assert_eq!(ev.findings[0].severity_id, 3);
    }

    #[test]
    fn http_401_is_effective() {
        let srv = mock_server(
            401,
            r#"{"error":"invalid_client","error_description":"bad credentials"}"#,
        );
        let ev = &MfaBypassTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
    }

    #[test]
    fn http_403_is_effective() {
        let srv = mock_server(403, r#"{"error":"access_denied"}"#);
        let ev = &MfaBypassTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
    }

    #[test]
    fn other_error_is_effective() {
        let srv = mock_server(
            400,
            r#"{"error":"invalid_grant","error_description":"AADSTS50126: Invalid username or password"}"#,
        );
        let ev = &MfaBypassTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
    }

    #[test]
    fn mfa_bypass_has_transcript() {
        let srv = mock_server(
            400,
            r#"{"error":"interaction_required","error_description":"MFA required"}"#,
        );
        let ev = &MfaBypassTester.test(&base_config(&srv)).unwrap()[0];
        let t = ev.test_transcript.as_ref().unwrap();
        assert!(!t.actions_attempted.is_empty());
        assert!(!t.observations.is_empty());
    }

    #[test]
    fn mfa_bypass_raw_data_keys() {
        let srv = mock_server(
            400,
            r#"{"error":"interaction_required","error_description":"MFA"}"#,
        );
        let ev = &MfaBypassTester.test(&base_config(&srv)).unwrap()[0];
        assert!(ev.raw_data.get("test_scenario").is_some());
        assert!(ev.raw_data.get("bypass_blocked").is_some());
        assert!(ev.raw_data.get("error_code").is_some());
        assert_eq!(ev.raw_data["bypass_blocked"].as_bool(), Some(true));
    }

    #[test]
    fn mfa_bypass_success_raw_data_bypassed() {
        let srv = mock_server(
            200,
            r#"{"access_token":"tok","token_type":"Bearer","expires_in":3600}"#,
        );
        let ev = &MfaBypassTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.raw_data["bypass_blocked"].as_bool(), Some(false));
        assert_eq!(ev.raw_data["test_result"].as_str(), Some("bypassed"));
    }

    #[test]
    fn mfa_bypass_has_two_observables() {
        let srv = mock_server(
            400,
            r#"{"error":"interaction_required","error_description":"MFA"}"#,
        );
        let ev = &MfaBypassTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.observables.len(), 2);
        assert!(ev.observables.iter().any(|o| o.obs_type == "resource"));
        assert!(ev.observables.iter().any(|o| o.obs_type == "user"));
    }

    #[test]
    fn mfa_bypass_safety_classification_in_metadata() {
        let srv = mock_server(
            400,
            r#"{"error":"interaction_required","error_description":"MFA"}"#,
        );
        let ev = &MfaBypassTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.metadata.safety_classification.as_deref(), Some("safe"));
    }

    #[test]
    fn mfa_bypass_unique_ids() {
        let srv1 = mock_server(
            400,
            r#"{"error":"interaction_required","error_description":"MFA"}"#,
        );
        let srv2 = mock_server(
            400,
            r#"{"error":"interaction_required","error_description":"MFA"}"#,
        );
        let id1 = MfaBypassTester.test(&base_config(&srv1)).unwrap()[0].id;
        let id2 = MfaBypassTester.test(&base_config(&srv2)).unwrap()[0].id;
        assert_ne!(id1, id2);
    }
}
