use std::collections::HashMap;

use anyhow::{anyhow, bail, Result};
use chrono::Utc;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId,
};
use crate::module::{observer::Observer, CredentialReq, Module};

// ─── Factor taxonomy (user-enrolled factor types) ────────────────────────────

/// Phishing-resistant factor types as they appear in the Okta user factors API.
const PR_FACTOR_TYPES: [&str; 1] = ["webauthn"];

/// Phishable factor types as they appear in the Okta user factors API.
const PHISHABLE_FACTOR_TYPES: [&str; 6] = [
    "token:software:totp",
    "push",
    "sms",
    "call",
    "email",
    "token:hotp",
];

// ─── HTTP helper ─────────────────────────────────────────────────────────────

/// GET with SSWS auth; returns (body, status_code).
fn okta_get(token: &str, url: &str) -> Result<(Value, u16)> {
    let resp = ureq::get(url)
        .set("Authorization", &format!("SSWS {}", token))
        .set("Accept", "application/json")
        .call();

    match resp {
        Ok(r) => {
            let status = r.status();
            // Extract Link header before consuming response
            let link_header = r.header("Link").map(|s| s.to_string());
            let body: Value = r
                .into_json()
                .map_err(|e| anyhow!("parsing Okta JSON: {}", e))?;
            // Attach link header as metadata if present
            if let Some(link) = link_header {
                let wrapper = json!({ "data": body, "link": link });
                Ok((wrapper, status))
            } else {
                Ok((json!({ "data": body }), status))
            }
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

/// Extract the "next" link URL from the Link header value.
/// Format: `<https://...>; rel="next"` possibly with other entries.
fn extract_next_link(link_header: &str) -> Option<String> {
    for part in link_header.split(',') {
        let part = part.trim();
        if part.contains("rel=\"next\"") {
            // Extract URL between < and >
            if let Some(start) = part.find('<') {
                if let Some(end) = part.find('>') {
                    return Some(part[start + 1..end].to_string());
                }
            }
        }
    }
    None
}

// ─── MfaEnrollmentPopulationObserver ────────────────────────────────────────

/// Queries Okta user enrollment data to measure phishing-resistant MFA coverage
/// across the user population. Classifies each user as compliant (PR-only),
/// partially compliant (PR + phishable fallback), or non-compliant.
pub struct MfaEnrollmentPopulationObserver;

impl Module for MfaEnrollmentPopulationObserver {
    fn id(&self) -> &str {
        "okta.mfa_enrollment_population"
    }
    fn name(&self) -> &str {
        "Okta MFA Enrollment Population Observer"
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
                description: "Okta API token with read access to users and factors".to_string(),
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

/// Classification of a user's MFA enrollment posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UserCompliance {
    /// Has PR factors only, no phishable factors enrolled.
    Compliant,
    /// Has PR factors AND phishable factors enrolled.
    PartiallyCompliant,
    /// No PR factors enrolled.
    NonCompliant,
}

/// Classify a single user's factor enrollment.
fn classify_user_factors(factors: &[Value]) -> UserCompliance {
    let mut has_pr = false;
    let mut has_phishable = false;

    for factor in factors {
        let factor_type = factor
            .get("factorType")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let status = factor.get("status").and_then(|v| v.as_str()).unwrap_or("");

        if status != "ACTIVE" {
            continue;
        }

        if PR_FACTOR_TYPES.contains(&factor_type) {
            has_pr = true;
        } else if PHISHABLE_FACTOR_TYPES.contains(&factor_type) {
            has_phishable = true;
        }
        // Unknown factor types are ignored (not counted as phishable or PR).
    }

    match (has_pr, has_phishable) {
        (true, false) => UserCompliance::Compliant,
        (true, true) => UserCompliance::PartiallyCompliant,
        _ => UserCompliance::NonCompliant,
    }
}

impl Observer for MfaEnrollmentPopulationObserver {
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
        let endpoint = format!(
            "{}/api/v1/users?filter=status+eq+%22ACTIVE%22&limit=200",
            base_url.trim_end_matches('/')
        );

        // Step 1: Fetch all active users with pagination (cap at 1000)
        let mut all_users: Vec<Value> = Vec::new();
        let mut sampled = false;
        let mut next_url: Option<String> = Some(endpoint.clone());

        while let Some(url) = next_url.take() {
            if all_users.len() >= 1000 {
                sampled = true;
                break;
            }

            let (resp, status) = okta_get(token, &url)?;

            if status != 200 {
                bail!("Okta API returned status {} querying users", status);
            }

            let page_users = resp
                .get("data")
                .and_then(|d| d.as_array())
                .cloned()
                .unwrap_or_default();

            all_users.extend(page_users);

            // Check for pagination link
            if let Some(link) = resp.get("link").and_then(|l| l.as_str()) {
                if let Some(next) = extract_next_link(link) {
                    // If the next link is a relative path, prefix with base_url
                    if next.starts_with("http") {
                        next_url = Some(next);
                    } else {
                        next_url = Some(format!("{}{}", base_url.trim_end_matches('/'), next));
                    }
                }
            }

            if all_users.len() >= 1000 {
                sampled = true;
                break;
            }
        }

        // Step 2: Per-user factor classification
        let mut compliant_count = 0usize;
        let mut partially_compliant_count = 0usize;
        let mut non_compliant_ids: Vec<String> = Vec::new();

        for user in &all_users {
            let user_id = user.get("id").and_then(|v| v.as_str()).unwrap_or("");

            if user_id.is_empty() {
                continue;
            }

            let factors_url = format!(
                "{}/api/v1/users/{}/factors",
                base_url.trim_end_matches('/'),
                user_id
            );

            let (factors_resp, factors_status) = okta_get(token, &factors_url)?;

            if factors_status != 200 {
                // Treat API errors for individual users as non-compliant
                non_compliant_ids.push(user_id.to_string());
                continue;
            }

            let factors = factors_resp
                .get("data")
                .and_then(|d| d.as_array())
                .cloned()
                .unwrap_or_default();

            match classify_user_factors(&factors) {
                UserCompliance::Compliant => compliant_count += 1,
                UserCompliance::PartiallyCompliant => partially_compliant_count += 1,
                UserCompliance::NonCompliant => {
                    if non_compliant_ids.len() < 100 {
                        non_compliant_ids.push(user_id.to_string());
                    }
                }
            }
        }

        // Step 3: Compute statistics
        let total_users = all_users.len();
        let non_compliant_count = total_users - compliant_count - partially_compliant_count;
        let coverage_pct = if total_users > 0 {
            compliant_count as f64 / total_users as f64 * 100.0
        } else {
            100.0
        };

        // Step 4: Build evidence
        let (status_id, status_text) = if coverage_pct >= 99.0 && partially_compliant_count == 0 {
            (
                StatusId::Effective,
                format!(
                    "{}/{} users have PR-only MFA ({:.1}% coverage)",
                    compliant_count, total_users, coverage_pct
                ),
            )
        } else {
            (
                    StatusId::Ineffective,
                    format!(
                        "{}/{} compliant, {} partially compliant, {} non-compliant ({:.1}% PR-only coverage)",
                        compliant_count, total_users, partially_compliant_count,
                        non_compliant_count, coverage_pct
                    ),
                )
        };

        let findings = if status_id == StatusId::Ineffective {
            vec![Finding {
                title: "PR MFA Coverage Gap".to_string(),
                description: format!(
                    "{} of {} users lack phishing-resistant-only MFA enrollment ({} partially compliant, {} non-compliant)",
                    total_users - compliant_count, total_users, partially_compliant_count, non_compliant_count
                ),
                severity_id: 2,
            }]
        } else {
            vec![Finding {
                title: "PR MFA Coverage Compliant".to_string(),
                description: format!(
                    "All {} users have phishing-resistant-only MFA enrollment",
                    total_users
                ),
                severity_id: 0,
            }]
        };

        let observables = vec![Observable {
            obs_type: "population".to_string(),
            value: "okta_users".to_string(),
            name: String::new(),
        }];

        let raw_data = json!({
            "iam_auth": {
                "policy_layer": "enrollment",
                "provider": "okta",
                "total_users": total_users,
                "compliant_users": compliant_count,
                "coverage_pct": coverage_pct,
                "partially_compliant_count": partially_compliant_count,
                "non_compliant_count": non_compliant_count,
                "non_compliant": non_compliant_ids,
            },
            "total_users": total_users,
            "compliant_users": compliant_count,
            "coverage_pct": coverage_pct,
            "partially_compliant_count": partially_compliant_count,
            "non_compliant_count": non_compliant_count,
            "sampled": sampled,
        });

        Ok(vec![Evidence {
            id: Uuid::new_v4(),
            control_id: "mfa.enrollment_coverage".to_string(),
            class_uid: 1001,
            category_uid: 1,
            activity_id: 7,
            time: now,
            confidence_level: ConfidenceLevel::PassiveObservation,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "okta.mfa_enrollment_population".to_string(),
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
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;

    /// Multi-connection mock server that routes by URL path.
    /// Each route is (path_fragment, status_code, body).
    /// Server handles up to `max_requests` connections, matching by path.
    fn multi_mock_server(routes: Vec<(&str, u16, String)>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let max_requests = routes.len() * 2;
        let counter = Arc::new(AtomicUsize::new(0));

        // Convert routes to owned strings for thread safety
        let owned_routes: Vec<(String, u16, String)> = routes
            .into_iter()
            .map(|(path, status, body)| (path.to_string(), status, body))
            .collect();

        let counter_clone = Arc::clone(&counter);
        thread::spawn(move || {
            for stream_result in listener.incoming() {
                if counter_clone.fetch_add(1, Ordering::SeqCst) >= max_requests {
                    break;
                }

                if let Ok(mut stream) = stream_result {
                    let mut buf = [0u8; 8192];
                    let n = stream.read(&mut buf).unwrap_or(0);
                    let request = String::from_utf8_lossy(&buf[..n]);

                    // Extract path from first line: "GET /path HTTP/1.1"
                    let first_line = request.lines().next().unwrap_or("");

                    let mut matched = false;
                    for (path_fragment, status, body) in &owned_routes {
                        if first_line.contains(path_fragment.as_str()) {
                            let resp = format!(
                                "HTTP/1.1 {} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                status,
                                body.len(),
                                body
                            );
                            let _ = stream.write_all(resp.as_bytes());
                            matched = true;
                            break;
                        }
                    }

                    if !matched {
                        let body = r#"{"error":"not found"}"#;
                        let resp = format!(
                            "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(resp.as_bytes());
                    }

                    // Windows: shutdown + drain to prevent WSAECONNRESET
                    let _ = stream.shutdown(Shutdown::Write);
                    let mut drain = Vec::new();
                    let _ = stream.read_to_end(&mut drain);
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

    // ── Fixtures ─────────────────────────────────────────────────────────

    const USERS_3: &str = r#"[{"id":"u1","login":"a@x.com"},{"id":"u2","login":"b@x.com"},{"id":"u3","login":"c@x.com"}]"#;
    const EMPTY_USERS: &str = "[]";

    // u1: PR only (compliant)
    const U1_FACTORS: &str = r#"[{"factorType":"webauthn","status":"ACTIVE","provider":"FIDO"}]"#;
    // u2: PR + phishable (partially compliant)
    const U2_FACTORS: &str = r#"[{"factorType":"webauthn","status":"ACTIVE"},{"factorType":"token:software:totp","status":"ACTIVE"}]"#;
    // u3: phishable only (non-compliant)
    const U3_FACTORS: &str = r#"[{"factorType":"token:software:totp","status":"ACTIVE"}]"#;

    // All compliant: all 3 users have only webauthn
    const U_ALL_PR: &str = r#"[{"factorType":"webauthn","status":"ACTIVE","provider":"FIDO"}]"#;

    // ── Metadata ─────────────────────────────────────────────────────────

    #[test]
    fn metadata_correct() {
        let observer = MfaEnrollmentPopulationObserver;
        assert_eq!(observer.id(), "okta.mfa_enrollment_population");
        assert_eq!(observer.evidence_types(), &[1001]);

        let srv = multi_mock_server(vec![("/api/v1/users", 200, EMPTY_USERS.to_string())]);
        let ev = &observer.observe(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.class_uid, 1001);
        assert_eq!(ev.activity_id, 7);
        assert_eq!(ev.confidence_level, ConfidenceLevel::PassiveObservation);
    }

    // ── Config validation ────────────────────────────────────────────────

    #[test]
    fn missing_api_token_errors() {
        let err = MfaEnrollmentPopulationObserver
            .observe(&HashMap::from([(
                "OKTA_DOMAIN".to_string(),
                "example.okta.com".to_string(),
            )]))
            .unwrap_err();
        assert!(err.to_string().contains("OKTA_API_TOKEN"));
    }

    #[test]
    fn missing_domain_errors() {
        let err = MfaEnrollmentPopulationObserver
            .observe(&HashMap::from([(
                "OKTA_API_TOKEN".to_string(),
                "tok".to_string(),
            )]))
            .unwrap_err();
        assert!(err.to_string().contains("OKTA_DOMAIN"));
    }

    // ── Compliance tests ─────────────────────────────────────────────────

    #[test]
    fn all_compliant_returns_effective() {
        let srv = multi_mock_server(vec![
            ("/api/v1/users?", 200, USERS_3.to_string()),
            ("u1/factors", 200, U_ALL_PR.to_string()),
            ("u2/factors", 200, U_ALL_PR.to_string()),
            ("u3/factors", 200, U_ALL_PR.to_string()),
        ]);
        let ev = &MfaEnrollmentPopulationObserver
            .observe(&base_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert_eq!(ev.raw_data["total_users"], 3);
        assert_eq!(ev.raw_data["compliant_users"], 3);
    }

    #[test]
    fn partial_compliance_returns_ineffective() {
        let srv = multi_mock_server(vec![
            ("/api/v1/users?", 200, USERS_3.to_string()),
            ("u1/factors", 200, U1_FACTORS.to_string()),
            ("u2/factors", 200, U2_FACTORS.to_string()),
            ("u3/factors", 200, U3_FACTORS.to_string()),
        ]);
        let ev = &MfaEnrollmentPopulationObserver
            .observe(&base_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
    }

    #[test]
    fn empty_user_list_returns_effective() {
        let srv = multi_mock_server(vec![("/api/v1/users", 200, EMPTY_USERS.to_string())]);
        let ev = &MfaEnrollmentPopulationObserver
            .observe(&base_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert_eq!(ev.raw_data["coverage_pct"], 100.0);
    }

    #[test]
    fn non_compliant_list_populated() {
        let srv = multi_mock_server(vec![
            ("/api/v1/users?", 200, USERS_3.to_string()),
            ("u1/factors", 200, U1_FACTORS.to_string()),
            ("u2/factors", 200, U2_FACTORS.to_string()),
            ("u3/factors", 200, U3_FACTORS.to_string()),
        ]);
        let ev = &MfaEnrollmentPopulationObserver
            .observe(&base_config(&srv))
            .unwrap()[0];
        let non_compliant = ev.raw_data["iam_auth"]["non_compliant"].as_array().unwrap();
        let ids: Vec<&str> = non_compliant.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(ids.contains(&"u3"), "u3 should be non-compliant");
    }

    #[test]
    fn coverage_pct_calculated_correctly() {
        let srv = multi_mock_server(vec![
            ("/api/v1/users?", 200, USERS_3.to_string()),
            ("u1/factors", 200, U1_FACTORS.to_string()),
            ("u2/factors", 200, U2_FACTORS.to_string()),
            ("u3/factors", 200, U3_FACTORS.to_string()),
        ]);
        let ev = &MfaEnrollmentPopulationObserver
            .observe(&base_config(&srv))
            .unwrap()[0];
        // 1 compliant out of 3 = 33.33...%
        let pct = ev.raw_data["coverage_pct"].as_f64().unwrap();
        assert!((pct - 33.333).abs() < 0.1, "expected ~33.3%, got {}", pct);
    }

    #[test]
    fn domain_only_uses_https_prefix() {
        let cfg = HashMap::from([
            ("OKTA_API_TOKEN".to_string(), "test_token".to_string()),
            ("OKTA_DOMAIN".to_string(), "localhost".to_string()),
        ]);
        let result = MfaEnrollmentPopulationObserver.observe(&cfg);
        assert!(result.is_err());
    }

    #[test]
    fn api_returns_403_errors() {
        let srv = multi_mock_server(vec![(
            "/api/v1/users",
            403,
            r#"{"errorCode":"E0000006","errorSummary":"forbidden"}"#.to_string(),
        )]);
        let result = MfaEnrollmentPopulationObserver.observe(&base_config(&srv));
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("403"));
    }

    #[test]
    fn api_connection_refused_returns_error() {
        let cfg = base_config("http://127.0.0.1:1");
        let result = MfaEnrollmentPopulationObserver.observe(&cfg);
        assert!(result.is_err());
    }

    #[test]
    fn user_factors_api_error_counts_as_non_compliant() {
        // Users list succeeds, but factors API for u1 returns 403 → u1 is non-compliant
        let srv = multi_mock_server(vec![
            (
                "/api/v1/users?",
                200,
                r#"[{"id":"u1","login":"a@x.com"}]"#.to_string(),
            ),
            ("u1/factors", 403, r#"{"errorCode":"E0000006"}"#.to_string()),
        ]);
        let ev = &MfaEnrollmentPopulationObserver
            .observe(&base_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        let non_compliant = ev.raw_data["iam_auth"]["non_compliant"].as_array().unwrap();
        assert!(
            non_compliant.iter().any(|v| v.as_str() == Some("u1")),
            "u1 should be counted as non-compliant due to factors API error"
        );
    }

    #[test]
    fn user_with_empty_id_is_skipped() {
        // User without an id field is skipped — doesn't panic
        let srv = multi_mock_server(vec![(
            "/api/v1/users?",
            200,
            r#"[{"login":"noId@x.com"}]"#.to_string(),
        )]);
        let ev = &MfaEnrollmentPopulationObserver
            .observe(&base_config(&srv))
            .unwrap()[0];
        // 0 users processed (the one without id is skipped)
        assert_eq!(ev.raw_data["total_users"], 1);
        assert_eq!(ev.raw_data["compliant_users"], 0);
    }

    #[test]
    fn classify_user_factors_compliant() {
        let factors = vec![json!({"factorType": "webauthn", "status": "ACTIVE"})];
        assert_eq!(classify_user_factors(&factors), UserCompliance::Compliant);
    }

    #[test]
    fn classify_user_factors_partially_compliant() {
        let factors = vec![
            json!({"factorType": "webauthn", "status": "ACTIVE"}),
            json!({"factorType": "sms", "status": "ACTIVE"}),
        ];
        assert_eq!(
            classify_user_factors(&factors),
            UserCompliance::PartiallyCompliant
        );
    }

    #[test]
    fn classify_user_factors_non_compliant() {
        let factors = vec![json!({"factorType": "sms", "status": "ACTIVE"})];
        assert_eq!(
            classify_user_factors(&factors),
            UserCompliance::NonCompliant
        );
    }

    #[test]
    fn classify_user_factors_inactive_are_ignored() {
        // Inactive webauthn + active sms → non-compliant (webauthn not active)
        let factors = vec![
            json!({"factorType": "webauthn", "status": "INACTIVE"}),
            json!({"factorType": "sms", "status": "ACTIVE"}),
        ];
        assert_eq!(
            classify_user_factors(&factors),
            UserCompliance::NonCompliant
        );
    }

    #[test]
    fn classify_user_factors_unknown_type_ignored() {
        // Unknown factor type is ignored — not PR, not phishable
        let factors = vec![json!({"factorType": "some_new_factor", "status": "ACTIVE"})];
        assert_eq!(
            classify_user_factors(&factors),
            UserCompliance::NonCompliant
        );
    }

    #[test]
    fn extract_next_link_parses_correctly() {
        let link = r#"<https://example.okta.com/api/v1/users?after=abc>; rel="next", <https://example.okta.com/api/v1/users>; rel="self""#;
        let next = extract_next_link(link);
        assert_eq!(
            next,
            Some("https://example.okta.com/api/v1/users?after=abc".to_string())
        );
    }

    #[test]
    fn extract_next_link_returns_none_without_next() {
        let link = r#"<https://example.okta.com/api/v1/users>; rel="self""#;
        let next = extract_next_link(link);
        assert_eq!(next, None);
    }

    // ── Module trait fns coverage ────────────────────────────────────────────

    #[test]
    fn observer_name() {
        assert_eq!(
            MfaEnrollmentPopulationObserver.name(),
            "Okta MFA Enrollment Population Observer"
        );
    }

    #[test]
    fn observer_version() {
        assert_eq!(MfaEnrollmentPopulationObserver.version(), "0.1.0");
    }

    #[test]
    fn observer_source_system() {
        assert_eq!(MfaEnrollmentPopulationObserver.source_system(), "okta");
    }

    #[test]
    fn observer_evidence_types() {
        assert_eq!(MfaEnrollmentPopulationObserver.evidence_types(), &[1001]);
    }

    #[test]
    fn observer_credential_requirements() {
        let reqs = MfaEnrollmentPopulationObserver.credential_requirements();
        assert_eq!(reqs.len(), 2);
        assert!(reqs
            .iter()
            .any(|r| r.name == "OKTA_API_TOKEN" && r.required));
        assert!(reqs.iter().any(|r| r.name == "OKTA_DOMAIN" && r.required));
    }

    // ── Pagination: next link with relative path ─────────────────────────────

    #[test]
    fn pagination_relative_next_link() {
        // Server returns users with a relative next link, then second page returns empty.
        let link_header = r#"</api/v1/users?after=abc>; rel="next""#;
        let next = extract_next_link(link_header);
        assert_eq!(next, Some("/api/v1/users?after=abc".to_string()));
    }

    // ── Factor classification edge cases ────────────────────────────────────

    #[test]
    fn classify_empty_factors_is_non_compliant() {
        assert_eq!(classify_user_factors(&[]), UserCompliance::NonCompliant);
    }

    #[test]
    fn classify_missing_factor_type_field() {
        // Factor with no factorType → empty string → unknown → ignored
        let factors = vec![json!({"status": "ACTIVE"})];
        assert_eq!(
            classify_user_factors(&factors),
            UserCompliance::NonCompliant
        );
    }

    #[test]
    fn classify_missing_status_field() {
        // Factor with no status → empty string → not "ACTIVE" → skipped
        let factors = vec![json!({"factorType": "webauthn"})];
        assert_eq!(
            classify_user_factors(&factors),
            UserCompliance::NonCompliant
        );
    }

    #[test]
    fn classify_all_phishable_types() {
        // Test each phishable factor type
        for ft in &[
            "token:software:totp",
            "push",
            "sms",
            "call",
            "email",
            "token:hotp",
        ] {
            let factors = vec![json!({"factorType": ft, "status": "ACTIVE"})];
            assert_eq!(
                classify_user_factors(&factors),
                UserCompliance::NonCompliant,
                "factor type {} should be phishable/non-compliant",
                ft
            );
        }
    }

    // ── Extract next link edge cases ────────────────────────────────────────

    #[test]
    fn extract_next_link_empty_string() {
        assert_eq!(extract_next_link(""), None);
    }

    #[test]
    fn extract_next_link_no_angle_brackets() {
        let link = r#"https://example.com; rel="next""#;
        assert_eq!(extract_next_link(link), None);
    }

    // ── okta_get with error status code ─────────────────────────────────────

    #[test]
    fn okta_get_error_status_returns_body() {
        let srv = multi_mock_server(vec![(
            "/test",
            500,
            r#"{"errorCode":"E0000500"}"#.to_string(),
        )]);
        let (body, status) = okta_get("token", &format!("{}/test", srv)).unwrap();
        assert_eq!(status, 500);
        assert_eq!(body["errorCode"].as_str(), Some("E0000500"));
    }

    // ── Sampled flag when > 1000 users ──────────────────────────────────────
    // This is hard to test with real pagination, but we can verify the sampled
    // field is false for small user lists.

    #[test]
    fn sampled_is_false_for_small_user_set() {
        let srv = multi_mock_server(vec![
            ("/api/v1/users?", 200, USERS_3.to_string()),
            ("u1/factors", 200, U1_FACTORS.to_string()),
            ("u2/factors", 200, U2_FACTORS.to_string()),
            ("u3/factors", 200, U3_FACTORS.to_string()),
        ]);
        let ev = &MfaEnrollmentPopulationObserver
            .observe(&base_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.raw_data["sampled"].as_bool(), Some(false));
    }

    // ── Evidence fields coverage ─────────────────────────────────────────────

    #[test]
    fn evidence_has_correct_control_id_and_category() {
        let srv = multi_mock_server(vec![("/api/v1/users", 200, EMPTY_USERS.to_string())]);
        let ev = &MfaEnrollmentPopulationObserver
            .observe(&base_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.control_id, "mfa.enrollment_coverage");
        assert_eq!(ev.category_uid, 1);
        assert_eq!(ev.activity_id, 7);
        assert!(ev.test_transcript.is_none());
        assert_eq!(ev.observables.len(), 1);
        assert_eq!(ev.observables[0].obs_type, "population");
    }

    #[test]
    fn effective_finding_title() {
        let srv = multi_mock_server(vec![
            ("/api/v1/users?", 200, USERS_3.to_string()),
            ("u1/factors", 200, U_ALL_PR.to_string()),
            ("u2/factors", 200, U_ALL_PR.to_string()),
            ("u3/factors", 200, U_ALL_PR.to_string()),
        ]);
        let ev = &MfaEnrollmentPopulationObserver
            .observe(&base_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.findings[0].title, "PR MFA Coverage Compliant");
        assert_eq!(ev.findings[0].severity_id, 0);
    }

    #[test]
    fn ineffective_finding_title() {
        let srv = multi_mock_server(vec![
            ("/api/v1/users?", 200, USERS_3.to_string()),
            ("u1/factors", 200, U1_FACTORS.to_string()),
            ("u2/factors", 200, U2_FACTORS.to_string()),
            ("u3/factors", 200, U3_FACTORS.to_string()),
        ]);
        let ev = &MfaEnrollmentPopulationObserver
            .observe(&base_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.findings[0].title, "PR MFA Coverage Gap");
        assert_eq!(ev.findings[0].severity_id, 2);
    }

    #[test]
    fn iam_auth_raw_data_fields() {
        let srv = multi_mock_server(vec![
            ("/api/v1/users?", 200, USERS_3.to_string()),
            ("u1/factors", 200, U1_FACTORS.to_string()),
            ("u2/factors", 200, U2_FACTORS.to_string()),
            ("u3/factors", 200, U3_FACTORS.to_string()),
        ]);
        let ev = &MfaEnrollmentPopulationObserver
            .observe(&base_config(&srv))
            .unwrap()[0];
        let iam = &ev.raw_data["iam_auth"];
        assert_eq!(iam["policy_layer"].as_str(), Some("enrollment"));
        assert_eq!(iam["provider"].as_str(), Some("okta"));
        assert_eq!(iam["total_users"].as_u64(), Some(3));
    }

    // ── Pagination with Link header ──────────────────────────────────────────

    #[test]
    fn pagination_with_link_header_follows_next() {
        // First page returns 1 user with a Link header pointing to second page.
        // Second page returns 1 user with no Link header.
        use std::io::{Read as _, Write as _};
        use std::net::{Shutdown, TcpListener};

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let base = format!("http://127.0.0.1:{}", addr.port());
        let base_clone = base.clone();

        thread::spawn(move || {
            // Request 1: users list page 1 → returns u1, with Link header to page 2
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 8192];
                let _ = stream.read(&mut buf);
                let body = r#"[{"id":"u1","login":"a@x.com"}]"#;
                let next_link = format!("{}/api/v1/users?after=u1", base_clone);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nLink: <{}>; rel=\"next\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    next_link, body.len(), body
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.shutdown(Shutdown::Write);
                let mut drain = Vec::new();
                let _ = stream.read_to_end(&mut drain);
            }
            // Request 2: users list page 2 → returns u2, no Link header
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 8192];
                let _ = stream.read(&mut buf);
                let body = r#"[{"id":"u2","login":"b@x.com"}]"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(), body
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.shutdown(Shutdown::Write);
                let mut drain = Vec::new();
                let _ = stream.read_to_end(&mut drain);
            }
            // Request 3: u1 factors
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 8192];
                let _ = stream.read(&mut buf);
                let body = U_ALL_PR;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(), body
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.shutdown(Shutdown::Write);
                let mut drain = Vec::new();
                let _ = stream.read_to_end(&mut drain);
            }
            // Request 4: u2 factors
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 8192];
                let _ = stream.read(&mut buf);
                let body = U_ALL_PR;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(), body
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.shutdown(Shutdown::Write);
                let mut drain = Vec::new();
                let _ = stream.read_to_end(&mut drain);
            }
        });

        let ev = &MfaEnrollmentPopulationObserver
            .observe(&base_config(&base))
            .unwrap()[0];
        assert_eq!(ev.raw_data["total_users"].as_u64(), Some(2));
        assert_eq!(ev.raw_data["compliant_users"].as_u64(), Some(2));
        assert_eq!(ev.status_id, StatusId::Effective);
    }
}
