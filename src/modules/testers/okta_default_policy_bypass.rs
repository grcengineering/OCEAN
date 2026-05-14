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

// ─── HTTP helper ─────────────────────────────────────────────────────────────

/// Performs an authenticated GET to the Okta API.
/// Returns `(body, http_status)`.
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

// ─── DefaultPolicyBypassTester ───────────────────────────────────────────────

/// Verifies that the Okta default MFA enrollment policy cannot be bypassed.
///
/// Fetches all MFA_ENROLL policies and locates the default (system) policy,
/// then reads its rules to check whether any rule permits enrollment to be
/// skipped (`actions.enroll.self == "NOT_ALLOWED"`). A bypass exists if any
/// rule allows skipping MFA enrollment for a group of users.
///
/// This is a safe, read-only probe — no state is modified.
///
/// Required config: `OKTA_API_TOKEN`, `OKTA_DOMAIN`.
/// Optional: `OKTA_BASE_URL` (test override — defaults to `https://{OKTA_DOMAIN}`).
pub struct DefaultPolicyBypassTester;

impl Module for DefaultPolicyBypassTester {
    fn id(&self) -> &str {
        "okta.default_policy_bypass"
    }
    fn name(&self) -> &str {
        "Okta Default Policy Bypass Tester"
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

impl Tester for DefaultPolicyBypassTester {
    fn safety_class(&self) -> SafetyClassification {
        SafetyClassification::Safe
    }
    fn environment_scope(&self) -> EnvironmentScope {
        EnvironmentScope::Production
    }

    fn pre_flight_checks(&self) -> Vec<String> {
        vec![
            "Verify OKTA_API_TOKEN has read access to policies".to_string(),
            "Verify OKTA_DOMAIN is set".to_string(),
        ]
    }

    fn cleanup_procedures(&self) -> Vec<String> {
        vec![] // Safe read-only probe — no state changes, no cleanup needed.
    }

    fn test(&self, config: &HashMap<String, String>) -> Result<Vec<Evidence>> {
        let token = config
            .get("OKTA_API_TOKEN")
            .ok_or_else(|| anyhow!("OKTA_API_TOKEN is required"))?;
        let domain = config
            .get("OKTA_DOMAIN")
            .ok_or_else(|| anyhow!("OKTA_DOMAIN is required"))?;

        // OKTA_BASE_URL overrides the default https://{domain} (used in tests).
        let base_url = config
            .get("OKTA_BASE_URL")
            .map(|s| s.trim_end_matches('/').to_string())
            .unwrap_or_else(|| format!("https://{}", domain));

        let now = Utc::now();
        let mut recorder = TranscriptRecorder::new();
        let policies_endpoint = "/api/v1/policies?type=MFA_ENROLL";

        recorder.record_action(
            "fetch MFA enrollment policies",
            Some(json!({
                "target": domain,
                "endpoint": policies_endpoint,
            })),
        );

        // ── Step 1: Fetch MFA enrollment policies ─────────────────────────
        let (policies_body, policies_status) = okta_get(token, &base_url, policies_endpoint)?;

        if policies_status == 403 || policies_status == 401 {
            return Err(anyhow!(
                "Okta API returned HTTP {} fetching policies — check OKTA_API_TOKEN permissions",
                policies_status
            ));
        }

        let policies = policies_body.as_array().cloned().unwrap_or_default();

        recorder.record_observation(
            format!("found {} MFA_ENROLL policies", policies.len()),
            true,
        );

        // ── Step 2: Find the default (system) policy ──────────────────────
        let default_policy = policies.iter().find(|p| {
            p.get("system")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        });

        let policy_id = match default_policy {
            Some(p) => p
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            None => {
                // Fall back to first policy if no system policy found.
                policies
                    .first()
                    .and_then(|p| p.get("id"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string()
            }
        };

        recorder.record_action(
            "fetch rules for default MFA enrollment policy",
            Some(json!({
                "policy_id": policy_id,
            })),
        );

        if policy_id.is_empty() {
            // No policies at all — cannot assess; treat as inconclusive effective.
            let transcript = recorder.finalize();
            return Ok(vec![Evidence {
                id: Uuid::new_v4(),
                control_id: "OKTA-1.9".to_string(),
                class_uid: 1001,
                category_uid: 1,
                activity_id: 4,
                time: now,
                confidence_level: ConfidenceLevel::ActiveVerification,
                metadata: Metadata {
                    module: ModuleInfo {
                        name: "okta.default_policy_bypass".to_string(),
                        version: "0.1.0".to_string(),
                        module_type: "tester".to_string(),
                    },
                    source: SourceInfo {
                        system: "okta".to_string(),
                        api_version: "v1".to_string(),
                        endpoint: policies_endpoint.to_string(),
                    },
                    original_time: None,
                    processed_time: now,
                    safety_classification: Some("safe".to_string()),
                },
                observables: vec![Observable {
                    obs_type: "policy".to_string(),
                    value: "none".to_string(),
                    name: "mfa_enroll_default_policy".to_string(),
                }],
                status_id: StatusId::Effective,
                status: "No MFA enrollment policies found — cannot assess bypass risk".to_string(),
                raw_data: json!({
                    "test_scenario": "default_policy_bypass_check",
                    "target_system": domain,
                    "policies_found": 0,
                    "bypass_detected": false,
                }),
                findings: vec![],
                test_transcript: Some(transcript),
                enrichments: vec![],
            }]);
        }

        // ── Step 3: Fetch rules for the default policy ────────────────────
        let rules_endpoint = format!("/api/v1/policies/{}/rules", policy_id);
        let (rules_body, rules_status) = okta_get(token, &base_url, &rules_endpoint)?;

        if rules_status == 403 || rules_status == 401 {
            return Err(anyhow!(
                "Okta API returned HTTP {} fetching policy rules — check OKTA_API_TOKEN permissions",
                rules_status
            ));
        }

        let rules = rules_body.as_array().cloned().unwrap_or_default();

        recorder.record_observation(
            format!("found {} rules for default policy {}", rules.len(), policy_id),
            true,
        );

        // ── Step 4: Inspect rules for bypass conditions ───────────────────
        //
        // A bypass exists if any rule has `actions.enroll.self == "NOT_ALLOWED"`,
        // meaning that matched users are explicitly blocked from enrolling (i.e.,
        // they can skip MFA enrollment entirely).
        let mut bypass_detected = false;
        let mut bypass_rule_name = String::new();

        for rule in &rules {
            let enroll_self = rule
                .pointer("/actions/enroll/self")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            if enroll_self == "NOT_ALLOWED" {
                bypass_detected = true;
                bypass_rule_name = rule
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown rule")
                    .to_string();
                recorder.record_observation(
                    format!(
                        "rule '{}' has enroll.self=NOT_ALLOWED — MFA enrollment bypass path exists",
                        bypass_rule_name
                    ),
                    false,
                );
                break;
            }
        }

        if !bypass_detected {
            recorder.record_observation(
                "all default policy rules require MFA enrollment — no bypass found",
                true,
            );
        }

        let transcript = recorder.finalize();

        let (status_id, status_text, findings) = if bypass_detected {
            (
                StatusId::Ineffective,
                format!(
                    "Default MFA enrollment policy bypass detected via rule '{}'",
                    bypass_rule_name
                ),
                vec![Finding {
                    title: "Default MFA Policy Bypass Detected".to_string(),
                    description: format!(
                        "Rule '{}' in the default MFA enrollment policy has enroll.self=NOT_ALLOWED, \
                         allowing users matched by this rule to bypass MFA enrollment.",
                        bypass_rule_name
                    ),
                    severity_id: 3,
                }],
            )
        } else {
            (
                StatusId::Effective,
                "Default MFA enrollment policy enforces enrollment for all users — no bypass found"
                    .to_string(),
                vec![Finding {
                    title: "Default MFA Policy Bypass Not Detected".to_string(),
                    description:
                        "All rules in the default MFA enrollment policy require enrollment — \
                         no bypass path detected."
                            .to_string(),
                    severity_id: 0,
                }],
            )
        };

        let raw_data = json!({
            "test_scenario": "default_policy_bypass_check",
            "target_system": domain,
            "default_policy_id": policy_id,
            "rules_inspected": rules.len(),
            "bypass_detected": bypass_detected,
            "bypass_rule": if bypass_detected { bypass_rule_name.as_str() } else { "" },
        });

        Ok(vec![Evidence {
            id: Uuid::new_v4(),
            control_id: "OKTA-1.9".to_string(),
            class_uid: 1001,
            category_uid: 1,
            activity_id: 4,
            time: now,
            confidence_level: ConfidenceLevel::ActiveVerification,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "okta.default_policy_bypass".to_string(),
                    version: "0.1.0".to_string(),
                    module_type: "tester".to_string(),
                },
                source: SourceInfo {
                    system: "okta".to_string(),
                    api_version: "v1".to_string(),
                    endpoint: policies_endpoint.to_string(),
                },
                original_time: None,
                processed_time: now,
                safety_classification: Some("safe".to_string()),
            },
            observables: vec![Observable {
                obs_type: "policy".to_string(),
                value: policy_id,
                name: "mfa_enroll_default_policy".to_string(),
            }],
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

    /// Spin up a mock HTTP server that serves `responses` in order — one
    /// response per accepted connection. Each entry is `(status, body)`.
    fn mock_server(responses: Vec<(u16, &'static str)>) -> String {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        thread::spawn(move || {
            for (status, body) in responses {
                if let Ok((mut stream, _)) = listener.accept() {
                    let mut buf = [0u8; 8192];
                    let _ = stream.read(&mut buf);
                    let resp = format!(
                        "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n\
                         Content-Length: {len}\r\nConnection: close\r\n\r\n{body}",
                        len = body.len()
                    );
                    let _ = stream.write_all(resp.as_bytes());
                    let _ = stream.shutdown(std::net::Shutdown::Write);
                    let mut drain = [0u8; 256];
                    while matches!(stream.read(&mut drain), Ok(n) if n > 0) {}
                }
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
    fn default_policy_bypass_id() {
        assert_eq!(DefaultPolicyBypassTester.id(), "okta.default_policy_bypass");
    }

    #[test]
    fn default_policy_bypass_name() {
        assert_eq!(
            DefaultPolicyBypassTester.name(),
            "Okta Default Policy Bypass Tester"
        );
    }

    #[test]
    fn default_policy_bypass_safety_class() {
        assert_eq!(
            DefaultPolicyBypassTester.safety_class(),
            SafetyClassification::Safe
        );
    }

    #[test]
    fn default_policy_bypass_environment_scope() {
        assert_eq!(
            DefaultPolicyBypassTester.environment_scope(),
            EnvironmentScope::Production
        );
    }

    #[test]
    fn default_policy_bypass_preflight_nonempty() {
        assert!(!DefaultPolicyBypassTester.pre_flight_checks().is_empty());
    }

    #[test]
    fn default_policy_bypass_cleanup_empty() {
        assert!(DefaultPolicyBypassTester.cleanup_procedures().is_empty());
    }

    // ── Config validation ────────────────────────────────────────────────────

    #[test]
    fn missing_api_token_errors() {
        let config = HashMap::from([(
            "OKTA_DOMAIN".to_string(),
            "example.okta.com".to_string(),
        )]);
        let err = DefaultPolicyBypassTester.test(&config).unwrap_err();
        assert!(err.to_string().contains("OKTA_API_TOKEN"));
    }

    #[test]
    fn missing_domain_errors() {
        let config = HashMap::from([("OKTA_API_TOKEN".to_string(), "tok".to_string())]);
        let err = DefaultPolicyBypassTester.test(&config).unwrap_err();
        assert!(err.to_string().contains("OKTA_DOMAIN"));
    }

    // ── HTTP integration ─────────────────────────────────────────────────────

    /// Test 1: Default policy with all rules requiring MFA enrollment → Effective (no bypass).
    #[test]
    fn mfa_required_rules_is_effective() {
        let policies_body = r#"[{"id":"pol1","name":"Default Policy","system":true,"type":"MFA_ENROLL"}]"#;
        let rules_body = r#"[{"id":"rul1","name":"Default Rule","actions":{"enroll":{"self":"CHALLENGE"}}},{"id":"rul2","name":"Catch-All","actions":{"enroll":{"self":"LOGIN"}}}]"#;

        let srv = mock_server(vec![(200, policies_body), (200, rules_body)]);
        let ev = &DefaultPolicyBypassTester.test(&base_config(&srv)).unwrap()[0];

        assert_eq!(ev.status_id, StatusId::Effective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "Default MFA Policy Bypass Not Detected"));
        assert_eq!(ev.raw_data["bypass_detected"].as_bool(), Some(false));
        assert_eq!(ev.control_id, "OKTA-1.9");
        assert!(ev.test_transcript.is_some());
    }

    /// Test 2: Default policy has a NOT_ALLOWED rule → Ineffective (bypass detected), finding present.
    #[test]
    fn not_allowed_rule_is_ineffective() {
        let policies_body = r#"[{"id":"pol1","name":"Default Policy","system":true,"type":"MFA_ENROLL"}]"#;
        let rules_body = r#"[{"id":"rul1","name":"Skip Enrollment","actions":{"enroll":{"self":"NOT_ALLOWED"}}},{"id":"rul2","name":"Default Rule","actions":{"enroll":{"self":"CHALLENGE"}}}]"#;

        let srv = mock_server(vec![(200, policies_body), (200, rules_body)]);
        let ev = &DefaultPolicyBypassTester.test(&base_config(&srv)).unwrap()[0];

        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "Default MFA Policy Bypass Detected"));
        assert_eq!(ev.raw_data["bypass_detected"].as_bool(), Some(true));
        assert_eq!(ev.findings[0].severity_id, 3);
    }

    /// Test 3: API 403 on policies fetch → test returns Err.
    #[test]
    fn api_403_returns_err() {
        let srv = mock_server(vec![(
            403,
            r#"{"errorCode":"E0000006","errorSummary":"Unauthorized"}"#,
        )]);
        let result = DefaultPolicyBypassTester.test(&base_config(&srv));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("403"));
    }

    /// Test: 401 on policies fetch → Err.
    #[test]
    fn api_401_returns_err() {
        let srv = mock_server(vec![(
            401,
            r#"{"errorCode":"E0000006","errorSummary":"Unauthorized"}"#,
        )]);
        let result = DefaultPolicyBypassTester.test(&base_config(&srv));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("401"));
    }

    /// Test: policies present but no system:true → first policy used as fallback.
    #[test]
    fn non_system_policy_used_as_fallback() {
        let policies_body =
            r#"[{"id":"pol-fallback","name":"Custom Policy","system":false,"type":"MFA_ENROLL"}]"#;
        let rules_body = r#"[{"id":"rul1","name":"Default Rule","actions":{"enroll":{"self":"CHALLENGE"}}}]"#;
        let srv = mock_server(vec![(200, policies_body), (200, rules_body)]);
        let ev = &DefaultPolicyBypassTester.test(&base_config(&srv)).unwrap()[0];
        // Falls back to first policy — rules have no bypass → Effective.
        assert_eq!(ev.status_id, StatusId::Effective);
        assert_eq!(ev.observables[0].value, "pol-fallback");
    }

    /// Test: policies array is empty (policy_id is empty) → Effective / no assessment.
    #[test]
    fn empty_policies_returns_effective_no_assessment() {
        let srv = mock_server(vec![(200, "[]")]);
        let ev = &DefaultPolicyBypassTester.test(&base_config(&srv)).unwrap()[0];
        // Empty array → policy_id empty → inconclusive effective.
        assert_eq!(ev.status_id, StatusId::Effective);
        assert_eq!(ev.raw_data["policies_found"].as_u64(), Some(0));
        assert_eq!(ev.raw_data["bypass_detected"].as_bool(), Some(false));
    }

    /// Test: rules endpoint returns 403 → Err.
    #[test]
    fn rules_403_returns_err() {
        let policies_body =
            r#"[{"id":"pol1","name":"Default Policy","system":true,"type":"MFA_ENROLL"}]"#;
        let srv = mock_server(vec![
            (200, policies_body),
            (403, r#"{"errorCode":"E0000006","errorSummary":"Forbidden"}"#),
        ]);
        let result = DefaultPolicyBypassTester.test(&base_config(&srv));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("403"));
    }

    /// Test: rules endpoint returns 401 → Err.
    #[test]
    fn rules_401_returns_err() {
        let policies_body =
            r#"[{"id":"pol1","name":"Default Policy","system":true,"type":"MFA_ENROLL"}]"#;
        let srv = mock_server(vec![
            (200, policies_body),
            (401, r#"{"errorCode":"E0000006","errorSummary":"Unauthorized"}"#),
        ]);
        let result = DefaultPolicyBypassTester.test(&base_config(&srv));
        assert!(result.is_err());
    }

    /// Test: raw_data has expected keys on success path.
    #[test]
    fn raw_data_has_expected_keys() {
        let policies_body =
            r#"[{"id":"pol1","name":"Default Policy","system":true,"type":"MFA_ENROLL"}]"#;
        let rules_body =
            r#"[{"id":"rul1","name":"Default Rule","actions":{"enroll":{"self":"CHALLENGE"}}}]"#;
        let srv = mock_server(vec![(200, policies_body), (200, rules_body)]);
        let ev = &DefaultPolicyBypassTester.test(&base_config(&srv)).unwrap()[0];
        assert!(ev.raw_data.get("test_scenario").is_some());
        assert!(ev.raw_data.get("default_policy_id").is_some());
        assert!(ev.raw_data.get("rules_inspected").is_some());
        assert!(ev.raw_data.get("bypass_detected").is_some());
    }

    #[test]
    fn metadata_complete() {
        use crate::module::Module;
        use crate::module::Tester;
        let t = DefaultPolicyBypassTester;
        assert_eq!(t.id(), "okta.default_policy_bypass");
        assert!(!t.name().is_empty());
        assert_eq!(t.version(), "0.1.0");
        assert_eq!(t.source_system(), "okta");
        assert!(!t.evidence_types().is_empty());
        let creds = t.credential_requirements();
        assert!(!creds.is_empty());
        assert!(creds.iter().any(|c| c.name == "OKTA_API_TOKEN"));
        assert!(creds.iter().any(|c| c.name == "OKTA_DOMAIN"));
        // Tester trait methods
        let _safety = t.safety_class();
        let _scope = t.environment_scope();
        let _pre = t.pre_flight_checks();
        let _cleanup = t.cleanup_procedures();
    }

    // ── Missed Module trait fns ──────────────────────────────────────────────

    #[test]
    fn default_policy_bypass_version() {
        assert_eq!(DefaultPolicyBypassTester.version(), "0.1.0");
    }

    #[test]
    fn default_policy_bypass_source_system() {
        assert_eq!(DefaultPolicyBypassTester.source_system(), "okta");
    }

    #[test]
    fn default_policy_bypass_evidence_types() {
        assert_eq!(DefaultPolicyBypassTester.evidence_types(), &[1001]);
    }

    #[test]
    fn default_policy_bypass_credential_requirements_count() {
        let reqs = DefaultPolicyBypassTester.credential_requirements();
        assert_eq!(reqs.len(), 2);
    }

    // ── Rule with no name defaults to "unknown rule" ─────────────────────────

    #[test]
    fn bypass_rule_with_no_name_shows_unknown() {
        let policies_body = r#"[{"id":"pol1","name":"Default Policy","system":true,"type":"MFA_ENROLL"}]"#;
        let rules_body = r#"[{"id":"rul1","actions":{"enroll":{"self":"NOT_ALLOWED"}}}]"#;
        let srv = mock_server(vec![(200, policies_body), (200, rules_body)]);
        let ev = &DefaultPolicyBypassTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev.raw_data["bypass_rule"].as_str().unwrap().contains("unknown"));
    }

    #[test]
    fn okta_get_invalid_json_on_200_exercises_closure() {
        let srv = mock_server(vec![(200, "this is not json {")]);
        let _ = DefaultPolicyBypassTester.test(&base_config(&srv));
    }

    #[test]
    fn okta_get_invalid_json_on_error_status_exercises_closure() {
        let srv = mock_server(vec![(500, "<html>500</html>")]);
        let _ = DefaultPolicyBypassTester.test(&base_config(&srv));
    }
}
