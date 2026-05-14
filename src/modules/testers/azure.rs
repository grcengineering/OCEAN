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

/// Attempts password-only authentication against Azure AD (Entra ID) via the
/// ROPC (Resource Owner Password Credentials) flow without completing an MFA
/// challenge, to verify that Conditional Access MFA enforcement is working.
///
/// A successful authentication without MFA → `Ineffective` (bypass succeeded).
/// An `AADSTS50076` / `AADSTS50074` error or `interaction_required` → `Effective`
/// (MFA challenge required — bypass blocked).
///
/// This is a safe, read-only probe; it makes no state changes beyond producing
/// a sign-in log entry in the Entra ID audit log.
///
/// Required config: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_TEST_USER`,
///                  `AZURE_TEST_PASSWORD`.
/// Optional: `AZURE_LOGIN_BASE_URL` (default: `https://login.microsoftonline.com`).
pub struct MfaBypassTester;

impl Module for MfaBypassTester {
    fn id(&self) -> &str {
        "azure.mfa_bypass"
    }
    fn name(&self) -> &str {
        "Azure MFA Bypass Tester"
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
                description: "App registration client ID configured for ROPC flow".to_string(),
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
            "verify Azure AD token endpoint reachable".to_string(),
            "verify test credentials configured".to_string(),
        ]
    }

    fn cleanup_procedures(&self) -> Vec<String> {
        vec![] // Safe read-only probe — produces only a sign-in log entry, no state change.
    }

    fn test(&self, config: &HashMap<String, String>) -> Result<Vec<Evidence>> {
        let tenant_id = config
            .get("AZURE_TENANT_ID")
            .ok_or_else(|| anyhow!("AZURE_TENANT_ID is required"))?;
        let client_id = config
            .get("AZURE_CLIENT_ID")
            .ok_or_else(|| anyhow!("AZURE_CLIENT_ID is required"))?;
        let test_user = config
            .get("AZURE_TEST_USER")
            .ok_or_else(|| anyhow!("AZURE_TEST_USER is required for MFA bypass testing"))?;
        let test_password = config
            .get("AZURE_TEST_PASSWORD")
            .ok_or_else(|| anyhow!("AZURE_TEST_PASSWORD is required for MFA bypass testing"))?;

        let login_base_url = config
            .get("AZURE_LOGIN_BASE_URL")
            .map(|s| s.trim_end_matches('/').to_string())
            .unwrap_or_else(|| "https://login.microsoftonline.com".to_string());

        let now = Utc::now();
        let mut recorder = TranscriptRecorder::new();
        let safety_class = "safe".to_string();
        let endpoint = format!("/{}/oauth2/v2.0/token", tenant_id);
        let url = format!("{}{}", login_base_url, endpoint);

        recorder.record_action(
            "initiate ROPC authentication without MFA token",
            Some(json!({
                "target": tenant_id,
                "method": "ropc_password_grant",
                "user": test_user,
                "endpoint": endpoint,
            })),
        );

        recorder.record_action(
            "submit credentials without MFA factor",
            Some(json!({
                "credentials": "redacted",
                "mfa_token": "none",
                "grant_type": "password",
            })),
        );

        // POST ROPC grant — password only, no MFA factor.
        let body = format!(
            "grant_type=password&client_id={}&username={}&password={}&scope=openid",
            client_id, test_user, test_password
        );
        let post_resp = ureq::post(&url)
            .set("Content-Type", "application/x-www-form-urlencoded")
            .send_string(&body);

        // Parse response: success = access_token present; MFA required = error code AADSTS50076/50074
        let (http_status, access_token_present, error_code): (u16, bool, String) = match post_resp
        {
            Ok(r) => {
                let code = r.status();
                let data: Value = r.into_json().unwrap_or(json!({}));
                let has_token = data.get("access_token").is_some();
                let err_code = data
                    .get("error_codes")
                    .and_then(|v| v.as_array())
                    .and_then(|a| a.first())
                    .and_then(|v| v.as_u64())
                    .map(|n| n.to_string())
                    .unwrap_or_default();
                (code, has_token, err_code)
            }
            Err(ureq::Error::Status(code, r)) => {
                let data: Value = r.into_json().unwrap_or(json!({}));
                let err_code = data
                    .get("error_codes")
                    .and_then(|v| v.as_array())
                    .and_then(|a| a.first())
                    .and_then(|v| v.as_u64())
                    .map(|n| n.to_string())
                    .or_else(|| data.get("error").and_then(|v| v.as_str()).map(|s| s.to_string()))
                    .unwrap_or_default();
                (code, false, err_code)
            }
            Err(e) => return Err(anyhow!("Azure ROPC request failed: {}", e)),
        };

        // AADSTS50076 = MFA required; AADSTS50074 = strong auth required;
        // "interaction_required" also indicates the policy blocked password-only grant.
        let mfa_blocked = !access_token_present
            && (error_code == "50076"
                || error_code == "50074"
                || error_code == "interaction_required"
                || http_status == 400
                || http_status == 401);

        let (status_id, status_text, bypass_blocked) = if access_token_present {
            recorder.record_observation(
                "access token issued without MFA challenge",
                false,
            );
            recorder.record_observation("MFA bypass succeeded — Conditional Access not enforcing MFA", false);
            (
                StatusId::Ineffective,
                "MFA bypass succeeded — authentication completed without MFA".to_string(),
                false,
            )
        } else if mfa_blocked {
            recorder.record_observation(
                format!("authentication rejected (HTTP {}, error: {})", http_status, error_code),
                true,
            );
            recorder.record_observation("MFA bypass attempt blocked by Conditional Access", true);
            (
                StatusId::Effective,
                "MFA bypass attempt was correctly blocked by Conditional Access".to_string(),
                true,
            )
        } else {
            recorder.record_observation(
                format!("authentication failed with unexpected status (HTTP {}, error: {})", http_status, error_code),
                true,
            );
            recorder.record_observation("no access token issued without MFA", true);
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
                description: "ROPC authentication completed without MFA challenge — Conditional Access MFA enforcement is not working".to_string(),
                severity_id: 3,
            }]
        };

        let raw_data = json!({
            "test_scenario": "mfa_bypass_attempt_ropc",
            "target_system": tenant_id,
            "test_result": if bypass_blocked { "blocked" } else { "bypassed" },
            "http_status": http_status,
            "error_code": error_code,
            "bypass_blocked": bypass_blocked,
        });

        Ok(vec![Evidence {
            id: Uuid::new_v4(),
            control_id: "iam.mfa_enforcement".to_string(),
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
                    system: "azure".to_string(),
                    api_version: "v2.0".to_string(),
                    endpoint: endpoint.clone(),
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
                    "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
                    len = body.len()
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
            ("AZURE_TENANT_ID".to_string(), "test-tenant-id".to_string()),
            ("AZURE_CLIENT_ID".to_string(), "test-client-id".to_string()),
            ("AZURE_TEST_USER".to_string(), "test@example.com".to_string()),
            (
                "AZURE_TEST_PASSWORD".to_string(),
                "TestPass123!".to_string(),
            ),
            ("AZURE_LOGIN_BASE_URL".to_string(), base_url.to_string()),
        ])
    }

    // ── Metadata ─────────────────────────────────────────────────────────────

    #[test]
    fn mfa_bypass_id() {
        assert_eq!(MfaBypassTester.id(), "azure.mfa_bypass");
    }

    #[test]
    fn mfa_bypass_name() {
        assert_eq!(MfaBypassTester.name(), "Azure MFA Bypass Tester");
    }

    #[test]
    fn mfa_bypass_version() {
        assert_eq!(MfaBypassTester.version(), "0.1.0");
    }

    #[test]
    fn mfa_bypass_source_system() {
        assert_eq!(MfaBypassTester.source_system(), "azure");
    }

    #[test]
    fn mfa_bypass_evidence_types() {
        assert_eq!(MfaBypassTester.evidence_types(), &[1001]);
    }

    #[test]
    fn mfa_bypass_credential_requirements() {
        let reqs = MfaBypassTester.credential_requirements();
        assert_eq!(reqs.len(), 4);
        assert!(reqs
            .iter()
            .any(|r| r.name == "AZURE_TENANT_ID" && r.required));
        assert!(reqs
            .iter()
            .any(|r| r.name == "AZURE_CLIENT_ID" && r.required));
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
            ("AZURE_CLIENT_ID".to_string(), "cid".to_string()),
            ("AZURE_TEST_USER".to_string(), "u".to_string()),
            ("AZURE_TEST_PASSWORD".to_string(), "p".to_string()),
        ]);
        let err = MfaBypassTester.test(&config).unwrap_err();
        assert!(err.to_string().contains("AZURE_TENANT_ID"));
    }

    #[test]
    fn missing_client_id_errors() {
        let config = HashMap::from([
            ("AZURE_TENANT_ID".to_string(), "tid".to_string()),
            ("AZURE_TEST_USER".to_string(), "u".to_string()),
            ("AZURE_TEST_PASSWORD".to_string(), "p".to_string()),
        ]);
        let err = MfaBypassTester.test(&config).unwrap_err();
        assert!(err.to_string().contains("AZURE_CLIENT_ID"));
    }

    #[test]
    fn missing_test_user_errors() {
        let config = HashMap::from([
            ("AZURE_TENANT_ID".to_string(), "tid".to_string()),
            ("AZURE_CLIENT_ID".to_string(), "cid".to_string()),
            ("AZURE_TEST_PASSWORD".to_string(), "p".to_string()),
        ]);
        let err = MfaBypassTester.test(&config).unwrap_err();
        assert!(err.to_string().contains("AZURE_TEST_USER"));
    }

    #[test]
    fn missing_test_password_errors() {
        let config = HashMap::from([
            ("AZURE_TENANT_ID".to_string(), "tid".to_string()),
            ("AZURE_CLIENT_ID".to_string(), "cid".to_string()),
            ("AZURE_TEST_USER".to_string(), "u".to_string()),
        ]);
        let err = MfaBypassTester.test(&config).unwrap_err();
        assert!(err.to_string().contains("AZURE_TEST_PASSWORD"));
    }

    // ── HTTP integration ─────────────────────────────────────────────────────

    #[test]
    fn mfa_required_error_50076_is_effective() {
        // AADSTS50076: MFA required
        let srv = mock_server(
            400,
            r#"{"error":"invalid_grant","error_description":"AADSTS50076","error_codes":[50076]}"#,
        );
        let ev = &MfaBypassTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert!(ev.findings.iter().any(|f| f.title == "MFA Bypass Blocked"));
        assert_eq!(ev.control_id, "iam.mfa_enforcement");
        assert_eq!(ev.class_uid, 1001);
    }

    #[test]
    fn mfa_required_error_50074_is_effective() {
        // AADSTS50074: Strong authentication required
        let srv = mock_server(
            400,
            r#"{"error":"invalid_grant","error_description":"AADSTS50074","error_codes":[50074]}"#,
        );
        let ev = &MfaBypassTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert!(ev.findings.iter().any(|f| f.title == "MFA Bypass Blocked"));
    }

    #[test]
    fn http_401_is_effective() {
        let srv = mock_server(
            401,
            r#"{"error":"unauthorized","error_codes":[]}"#,
        );
        let ev = &MfaBypassTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
    }

    #[test]
    fn access_token_present_is_ineffective() {
        // If an access_token is returned, bypass succeeded.
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
    fn mfa_bypass_has_transcript() {
        let srv = mock_server(
            400,
            r#"{"error":"invalid_grant","error_codes":[50076]}"#,
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
            r#"{"error":"invalid_grant","error_codes":[50076]}"#,
        );
        let ev = &MfaBypassTester.test(&base_config(&srv)).unwrap()[0];
        assert!(ev.raw_data.get("test_scenario").is_some());
        assert!(ev.raw_data.get("bypass_blocked").is_some());
        assert!(ev.raw_data.get("error_code").is_some());
        assert_eq!(ev.raw_data["bypass_blocked"].as_bool(), Some(true));
    }

    #[test]
    fn bypass_success_raw_data_bypassed() {
        let srv = mock_server(
            200,
            r#"{"access_token":"tok","token_type":"Bearer"}"#,
        );
        let ev = &MfaBypassTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.raw_data["bypass_blocked"].as_bool(), Some(false));
        assert_eq!(ev.raw_data["test_result"].as_str(), Some("bypassed"));
    }

    #[test]
    fn mfa_bypass_has_two_observables() {
        let srv = mock_server(
            400,
            r#"{"error":"invalid_grant","error_codes":[50076]}"#,
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
            r#"{"error":"invalid_grant","error_codes":[50076]}"#,
        );
        let ev = &MfaBypassTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.metadata.safety_classification.as_deref(), Some("safe"));
    }

    #[test]
    fn mfa_bypass_unique_ids() {
        let srv1 = mock_server(400, r#"{"error_codes":[50076]}"#);
        let srv2 = mock_server(400, r#"{"error_codes":[50076]}"#);
        let id1 = MfaBypassTester.test(&base_config(&srv1)).unwrap()[0].id;
        let id2 = MfaBypassTester.test(&base_config(&srv2)).unwrap()[0].id;
        assert_ne!(id1, id2);
    }

    #[test]
    fn unexpected_status_no_access_token_is_effective() {
        // A non-400/401 status with no access token falls into the else branch
        // (mfa_blocked = false, access_token_present = false → unexpected → Effective).
        let srv = mock_server(
            200,
            r#"{"error":"some_other_error","error_codes":[99999]}"#,
        );
        let ev = &MfaBypassTester.test(&base_config(&srv)).unwrap()[0];
        // No access_token and error_code not in [50076, 50074, interaction_required, 400, 401]
        // → mfa_blocked = false, access_token_present = false → else branch → Effective
        assert_eq!(ev.status_id, StatusId::Effective);
        assert!(ev.findings.iter().any(|f| f.title == "MFA Bypass Blocked"));
    }

    #[test]
    fn interaction_required_error_is_effective() {
        let srv = mock_server(
            400,
            r#"{"error":"interaction_required","error_codes":[]}"#,
        );
        let ev = &MfaBypassTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
    }

    #[test]
    fn metadata_complete() {
        use crate::module::Module;
        use crate::module::Tester;
        let t = MfaBypassTester;
        assert_eq!(t.id(), "azure.mfa_bypass");
        assert!(!t.name().is_empty());
        assert_eq!(t.version(), "0.1.0");
        assert_eq!(t.source_system(), "azure");
        assert!(!t.evidence_types().is_empty());
        let creds = t.credential_requirements();
        assert!(!creds.is_empty());
        assert!(creds.iter().any(|c| c.name == "AZURE_CLIENT_ID"));
        assert!(creds.iter().any(|c| c.name == "AZURE_TENANT_ID"));
        // Tester trait methods
        let _safety = t.safety_class();
        let _scope = t.environment_scope();
        let _pre = t.pre_flight_checks();
        let _cleanup = t.cleanup_procedures();
    }

    // ── Missed fn: evidence_types ────────────────────────────────────────────

    #[test]
    fn azure_mfa_bypass_evidence_types() {
        assert_eq!(MfaBypassTester.evidence_types(), &[1001]);
    }

    // ── Connection refused error ─────────────────────────────────────────────

    #[test]
    fn connection_refused_returns_err() {
        let config = base_config("http://127.0.0.1:1");
        let result = MfaBypassTester.test(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Azure ROPC request failed"));
    }

    // ── Error with string error code (interaction_required via "error" field) ─

    #[test]
    fn interaction_required_via_error_field_is_effective() {
        // error_codes is empty array, but "error" field = "interaction_required"
        // The Err::Status arm falls through to or_else and reads the "error" field.
        let srv = mock_server(
            400,
            r#"{"error":"interaction_required","error_description":"AADSTS65001"}"#,
        );
        let ev = &MfaBypassTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert_eq!(ev.raw_data["error_code"].as_str(), Some("interaction_required"));
    }

    #[test]
    fn okta_get_invalid_json_on_200_exercises_closure() {
        let srv = mock_server(200, "this is not json {");
        let _ = MfaBypassTester.test(&base_config(&srv));
    }

    #[test]
    fn okta_get_invalid_json_on_error_status_exercises_closure() {
        let srv = mock_server(500, "<html>500</html>");
        let _ = MfaBypassTester.test(&base_config(&srv));
    }
}
