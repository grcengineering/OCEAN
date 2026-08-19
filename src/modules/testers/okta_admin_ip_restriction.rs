use std::collections::HashMap;

use anyhow::{anyhow, Result};
use chrono::Utc;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId,
    TranscriptRecorder, EVIDENCE_SCHEMA_VERSION,
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

// ─── AdminIpRestrictionTester ─────────────────────────────────────────────────

/// Verifies that the Okta admin console is restricted to specific IP zones.
///
/// Fetches OKTA_SIGN_ON policies and inspects their rules for network zone
/// conditions on rules that apply to admin users. If at least one rule
/// restricts admin access to named IP zones, the control is effective.
///
/// This is a safe, read-only probe — no state is modified.
///
/// Required config: `OKTA_API_TOKEN`, `OKTA_DOMAIN`.
/// Optional: `OKTA_BASE_URL` (test override — defaults to `https://{OKTA_DOMAIN}`).
pub struct AdminIpRestrictionTester;

impl Module for AdminIpRestrictionTester {
    fn id(&self) -> &str {
        "okta.admin_ip_restriction"
    }
    fn name(&self) -> &str {
        "Okta Admin IP Restriction Tester"
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
                description: "Okta API token with read access to sign-on policies".to_string(),
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

impl Tester for AdminIpRestrictionTester {
    fn safety_class(&self) -> SafetyClassification {
        SafetyClassification::Safe
    }
    fn environment_scope(&self) -> EnvironmentScope {
        EnvironmentScope::Production
    }

    fn pre_flight_checks(&self) -> Vec<String> {
        vec!["Verify OKTA_API_TOKEN has read access to sign-on policies".to_string()]
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
        let policies_endpoint = "/api/v1/policies?type=OKTA_SIGN_ON";

        recorder.record_action(
            "fetch OKTA_SIGN_ON policies",
            Some(json!({
                "target": domain,
                "endpoint": policies_endpoint,
            })),
        );

        // ── Step 1: Fetch OKTA_SIGN_ON policies ───────────────────────────
        let (policies_body, policies_status) = okta_get(token, &base_url, policies_endpoint)?;

        if policies_status == 403 || policies_status == 401 {
            return Err(anyhow!(
                "Okta API returned HTTP {} fetching sign-on policies — check OKTA_API_TOKEN permissions",
                policies_status
            ));
        }

        let policies = policies_body.as_array().cloned().unwrap_or_default();

        recorder.record_observation(
            format!("found {} OKTA_SIGN_ON policies", policies.len()),
            true,
        );

        if policies.is_empty() {
            recorder.record_observation(
                "no sign-on policies found — admin IP restriction cannot be verified",
                false,
            );
            let transcript = recorder.finalize();
            return Ok(vec![build_evidence(BuildEvidenceParams {
                now,
                domain,
                policies_endpoint,
                status_id: StatusId::Ineffective,
                status_text: "No OKTA_SIGN_ON policies found — admin IP restriction not verifiable".to_string(),
                findings: vec![Finding {
                    title: "No Sign-On Policies Found".to_string(),
                    description: "No OKTA_SIGN_ON policies were returned — admin console IP restriction cannot be confirmed.".to_string(),
                    severity_id: 2,
                }],
                raw_data: json!({
                    "test_scenario": "admin_ip_restriction_check",
                    "target_system": domain,
                    "policies_found": 0,
                    "restriction_found": false,
                    "obs_type": "policy",
                    "name": "admin_restriction_policy",
                    "value": "none",
                }),
                observable_value: "none".to_string(),
                transcript: Some(transcript),
            })]);
        }

        // ── Step 2: Inspect each policy's rules for network zone conditions ─
        //
        // A rule has an IP restriction if:
        //   conditions.network.connection == "ZONE" (or "ANYWHERE" negated)
        //   AND conditions.network.include is a non-empty array of zone IDs.
        //
        // We treat any rule with a non-empty `conditions.network.include` array
        // as an IP restriction rule for admin access.
        let mut restriction_found = false;
        let mut restricting_policy_id = String::new();
        let mut rules_inspected = 0usize;

        'outer: for policy in &policies {
            let policy_id = policy
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            if policy_id.is_empty() {
                continue;
            }

            let rules_endpoint = format!("/api/v1/policies/{}/rules", policy_id);

            recorder.record_action(
                "fetch rules for sign-on policy",
                Some(json!({ "policy_id": policy_id })),
            );

            let (rules_body, rules_status) = okta_get(token, &base_url, &rules_endpoint)?;

            if rules_status == 403 || rules_status == 401 {
                // Skip this policy — insufficient permissions to read its rules.
                recorder.record_observation(
                    format!(
                        "HTTP {} reading rules for policy {} — skipping",
                        rules_status, policy_id
                    ),
                    false,
                );
                continue;
            }

            let rules = rules_body.as_array().cloned().unwrap_or_default();
            rules_inspected += rules.len();

            for rule in &rules {
                // Check for network zone condition: non-empty include list signals IP restriction.
                let has_zone_include = rule
                    .pointer("/conditions/network/include")
                    .and_then(|v| v.as_array())
                    .map(|arr| !arr.is_empty())
                    .unwrap_or(false);

                // Also check connection type == "ZONE" as an alternative indicator.
                let connection_is_zone = rule
                    .pointer("/conditions/network/connection")
                    .and_then(|v| v.as_str())
                    .map(|c| c == "ZONE")
                    .unwrap_or(false);

                if has_zone_include || connection_is_zone {
                    restriction_found = true;
                    restricting_policy_id = policy_id.clone();
                    recorder.record_observation(
                        format!(
                            "rule '{}' in policy {} has network zone condition — admin IP restriction in place",
                            rule.get("name").and_then(|v| v.as_str()).unwrap_or("unknown"),
                            policy_id
                        ),
                        true,
                    );
                    break 'outer;
                }
            }
        }

        if !restriction_found {
            recorder.record_observation(
                "no sign-on policy rules with IP zone conditions found — admin access is not IP-restricted",
                false,
            );
        }

        let transcript = recorder.finalize();

        let observable_value = if restriction_found {
            restricting_policy_id.clone()
        } else {
            "none".to_string()
        };

        let raw_data = json!({
            "test_scenario": "admin_ip_restriction_check",
            "target_system": domain,
            "policies_found": policies.len(),
            "rules_inspected": rules_inspected,
            "restriction_found": restriction_found,
            "restricting_policy_id": observable_value,
            "obs_type": "policy",
            "name": "admin_restriction_policy",
            "value": observable_value,
        });

        let (status_id, status_text, findings) = if restriction_found {
            (
                StatusId::Effective,
                format!(
                    "Admin console IP restriction is in place (policy {})",
                    restricting_policy_id
                ),
                vec![Finding {
                    title: "Admin IP Restriction Enforced".to_string(),
                    description: format!(
                        "At least one sign-on policy rule (policy {}) restricts admin access \
                         to specific IP zones.",
                        restricting_policy_id
                    ),
                    severity_id: 0,
                }],
            )
        } else {
            (
                StatusId::Ineffective,
                "No sign-on policy rules found with IP zone restrictions for admin access"
                    .to_string(),
                vec![Finding {
                    title: "Admin IP Restriction Not Found".to_string(),
                    description:
                        "No OKTA_SIGN_ON policy rules with network zone conditions were found. \
                                  Admin console access may not be restricted by IP."
                            .to_string(),
                    severity_id: 3,
                }],
            )
        };

        Ok(vec![build_evidence(BuildEvidenceParams {
            now,
            domain,
            policies_endpoint,
            status_id,
            status_text,
            findings,
            raw_data,
            observable_value,
            transcript: Some(transcript),
        })])
    }
}

// ─── Evidence builder ─────────────────────────────────────────────────────────

/// Bundled parameters for [`build_evidence`] (keeps the function's argument
/// count within clippy's `too_many_arguments` threshold).
struct BuildEvidenceParams<'a> {
    now: chrono::DateTime<Utc>,
    domain: &'a str,
    policies_endpoint: &'a str,
    status_id: StatusId,
    status_text: String,
    findings: Vec<Finding>,
    raw_data: Value,
    observable_value: String,
    transcript: Option<crate::evidence::TestTranscript>,
}

fn build_evidence(params: BuildEvidenceParams) -> Evidence {
    let BuildEvidenceParams {
        now,
        domain: _domain,
        policies_endpoint,
        status_id,
        status_text,
        findings,
        raw_data,
        observable_value,
        transcript,
    } = params;

    Evidence {
        schema_version: EVIDENCE_SCHEMA_VERSION.to_string(),
        connected_account: None,
        population: None,
        evaluation: None,
        id: Uuid::new_v4(),
        control_id: "OKTA-2.2".to_string(),
        class_uid: 1001,
        category_uid: 1,
        activity_id: 4,
        time: now,
        confidence_level: ConfidenceLevel::ActiveVerification,
        metadata: Metadata {
            module: ModuleInfo {
                name: "okta.admin_ip_restriction".to_string(),
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
            value: observable_value,
            name: "admin_restriction_policy".to_string(),
        }],
        status_id,
        status: status_text,
        raw_data,
        findings,
        test_transcript: transcript,
        enrichments: vec![],
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Spin up a mock HTTP server that serves `responses` in order — one
    /// response per accepted connection.
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
    fn admin_ip_restriction_id() {
        assert_eq!(AdminIpRestrictionTester.id(), "okta.admin_ip_restriction");
    }

    #[test]
    fn admin_ip_restriction_name() {
        assert_eq!(
            AdminIpRestrictionTester.name(),
            "Okta Admin IP Restriction Tester"
        );
    }

    #[test]
    fn admin_ip_restriction_safety_class() {
        assert_eq!(
            AdminIpRestrictionTester.safety_class(),
            SafetyClassification::Safe
        );
    }

    #[test]
    fn admin_ip_restriction_environment_scope() {
        assert_eq!(
            AdminIpRestrictionTester.environment_scope(),
            EnvironmentScope::Production
        );
    }

    #[test]
    fn admin_ip_restriction_preflight_nonempty() {
        assert!(!AdminIpRestrictionTester.pre_flight_checks().is_empty());
    }

    #[test]
    fn admin_ip_restriction_cleanup_empty() {
        assert!(AdminIpRestrictionTester.cleanup_procedures().is_empty());
    }

    // ── Config validation ────────────────────────────────────────────────────

    #[test]
    fn missing_api_token_errors() {
        let config = HashMap::from([("OKTA_DOMAIN".to_string(), "example.okta.com".to_string())]);
        let err = AdminIpRestrictionTester.test(&config).unwrap_err();
        assert!(err.to_string().contains("OKTA_API_TOKEN"));
    }

    #[test]
    fn missing_domain_errors() {
        let config = HashMap::from([("OKTA_API_TOKEN".to_string(), "tok".to_string())]);
        let err = AdminIpRestrictionTester.test(&config).unwrap_err();
        assert!(err.to_string().contains("OKTA_DOMAIN"));
    }

    // ── HTTP integration ─────────────────────────────────────────────────────

    /// Test 1: Sign-on policy with a zone condition on a rule → Effective.
    #[test]
    fn zone_condition_is_effective() {
        let policies_body = r#"[{"id":"pol1","name":"Admin Policy","type":"OKTA_SIGN_ON"}]"#;
        let rules_body = r#"[{"id":"rul1","name":"Admin Zone Rule","conditions":{"network":{"connection":"ZONE","include":["nzn1a8baqhYbhqABc0g3"]}}}]"#;

        let srv = mock_server(vec![(200, policies_body), (200, rules_body)]);
        let ev = &AdminIpRestrictionTester.test(&base_config(&srv)).unwrap()[0];

        assert_eq!(ev.status_id, StatusId::Effective);
        assert_eq!(ev.control_id, "OKTA-2.2");
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "Admin IP Restriction Enforced"));
        assert_eq!(ev.findings[0].severity_id, 0);
        assert_ne!(
            ev.observables[0].value, "none",
            "observable value should be the policy ID"
        );
        assert!(ev.test_transcript.is_some());
    }

    /// Test 2: Policies present but no zone conditions on any rule → Ineffective, finding present.
    #[test]
    fn no_zone_conditions_is_ineffective() {
        let policies_body = r#"[{"id":"pol1","name":"Default Policy","type":"OKTA_SIGN_ON"}]"#;
        let rules_body = r#"[{"id":"rul1","name":"Allow All","conditions":{"network":{"connection":"ANYWHERE"}}}]"#;

        let srv = mock_server(vec![(200, policies_body), (200, rules_body)]);
        let ev = &AdminIpRestrictionTester.test(&base_config(&srv)).unwrap()[0];

        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "Admin IP Restriction Not Found"));
        assert_eq!(ev.findings[0].severity_id, 3);
        assert_eq!(ev.observables[0].value, "none");
    }

    /// Test 3: Empty policy list → Ineffective, finding present.
    #[test]
    fn empty_policy_list_is_ineffective() {
        let srv = mock_server(vec![(200, "[]")]);
        let ev = &AdminIpRestrictionTester.test(&base_config(&srv)).unwrap()[0];

        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "No Sign-On Policies Found"));
        assert_eq!(ev.raw_data["policies_found"].as_u64(), Some(0));
    }
}
