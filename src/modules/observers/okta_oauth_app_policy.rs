use std::collections::HashMap;

use anyhow::{anyhow, Result};
use chrono::Utc;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId,
};
use crate::module::{observer::Observer, CredentialReq, Module};

// ─── Okta HTTP client ─────────────────────────────────────────────────────────

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

// ─── OAuthAppPolicyObserver ───────────────────────────────────────────────────

/// Queries active Okta apps, filters for OIDC apps, and checks OAuth consent
/// and refresh token expiry policies.
///
/// Controls:
///   - OKTA-3.1: All OIDC apps must have `consent_method == "REQUIRED"`.
///   - OKTA-3.3: OIDC apps should configure refresh token rotation/leeway.
///
/// Required config: `OKTA_API_TOKEN`, `OKTA_DOMAIN`.
/// Optional: `OKTA_BASE_URL` (test override — defaults to `https://{OKTA_DOMAIN}`).
pub struct OAuthAppPolicyObserver;

impl Module for OAuthAppPolicyObserver {
    fn id(&self) -> &str {
        "okta.oauth_app_policy"
    }
    fn name(&self) -> &str {
        "Okta OAuth App Policy Observer"
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
                description: "Okta API token with read access to applications".to_string(),
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

impl Observer for OAuthAppPolicyObserver {
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
        let path = r#"/api/v1/apps?filter=status+eq+"ACTIVE"&limit=50"#;
        let endpoint = format!("{}{}", base_url.trim_end_matches('/'), path);

        let (body, status) = okta_get(token, &base_url, path)?;

        if status != 200 {
            return Err(anyhow!(
                "Okta API returned status {} querying apps",
                status
            ));
        }

        let apps = body
            .as_array()
            .ok_or_else(|| anyhow!("expected JSON array from Okta apps endpoint"))?;

        // Filter for OIDC apps
        let oidc_apps: Vec<&Value> = apps
            .iter()
            .filter(|app| {
                let sign_on_mode = app
                    .get("signOnMode")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let name = app
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                sign_on_mode == "OPENID_CONNECT" || name.to_lowercase().contains("oidc")
            })
            .collect();

        // If no OIDC apps exist, return unknown/informational evidence
        if oidc_apps.is_empty() {
            return Ok(vec![Evidence {
                id: Uuid::new_v4(),
                control_id: "OKTA-3.1".to_string(),
                class_uid: 1001,
                category_uid: 1,
                activity_id: 1,
                time: now,
                confidence_level: ConfidenceLevel::PassiveObservation,
                metadata: Metadata {
                    module: ModuleInfo {
                        name: "okta.oauth_app_policy".to_string(),
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
                observables: vec![],
                status_id: StatusId::Unknown,
                status: "No active OIDC apps found; OKTA-3.1 and OKTA-3.3 are not applicable"
                    .to_string(),
                raw_data: json!({
                    "oidc_app_count": 0,
                    "consent_required_count": 0,
                    "apps_missing_consent": [],
                    "note": "No active OIDC apps found"
                }),
                findings: vec![Finding {
                    title: "No OIDC Apps Found".to_string(),
                    description: "No active OIDC apps were found; OAuth consent controls are not applicable.".to_string(),
                    severity_id: 0,
                }],
                test_transcript: None,
                enrichments: vec![],
            }]);
        }

        let mut consent_required_count = 0usize;
        let mut apps_missing_consent: Vec<String> = Vec::new();
        let mut observables: Vec<Observable> = Vec::new();
        let mut findings: Vec<Finding> = Vec::new();

        for app in &oidc_apps {
            let app_id = app
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let app_label = app
                .get("label")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");

            observables.push(Observable {
                obs_type: "resource".to_string(),
                value: format!("app:{}", app_id),
                name: String::new(),
            });

            let consent_method = app
                .get("settings")
                .and_then(|s| s.get("oauthClient"))
                .and_then(|o| o.get("consent_method"))
                .and_then(|v| v.as_str())
                .unwrap_or("TRUSTED");

            if consent_method == "REQUIRED" {
                consent_required_count += 1;
            } else {
                apps_missing_consent.push(app_label.to_string());
                findings.push(Finding {
                    title: "OAuth App Missing Required Consent".to_string(),
                    description: format!(
                        "App {:?} has consent_method={:?}; OKTA-3.1 requires \
                         consent_method=REQUIRED to ensure users explicitly approve OAuth scopes.",
                        app_label, consent_method
                    ),
                    severity_id: 3,
                });
            }

            // OKTA-3.3: Check refresh token configuration
            let refresh_token = app
                .get("settings")
                .and_then(|s| s.get("oauthClient"))
                .and_then(|o| o.get("refresh_token"));

            let has_refresh_token_config = refresh_token
                .map(|rt| {
                    rt.get("leeway").is_some() || rt.get("rotation_type").is_some()
                })
                .unwrap_or(false);

            if !has_refresh_token_config {
                findings.push(Finding {
                    title: "OAuth App Missing Refresh Token Expiry Config".to_string(),
                    description: format!(
                        "App {:?} does not configure refresh token rotation_type or leeway; \
                         OKTA-3.3 requires refresh tokens to have an expiry policy.",
                        app_label
                    ),
                    severity_id: 2,
                });
            }
        }

        let oidc_app_count = oidc_apps.len();
        let all_consent_required = apps_missing_consent.is_empty();

        if findings.is_empty() {
            findings.push(Finding {
                title: "OAuth App Consent Policies Compliant".to_string(),
                description: format!(
                    "All {} OIDC app(s) require consent and have refresh token expiry configured",
                    oidc_app_count
                ),
                severity_id: 0,
            });
        }

        let (status_id, status_text) = if all_consent_required {
            (
                StatusId::Effective,
                format!(
                    "All {} OIDC app(s) require OAuth consent (OKTA-3.1 satisfied)",
                    oidc_app_count
                ),
            )
        } else {
            (
                StatusId::Ineffective,
                format!(
                    "{} of {} OIDC app(s) are missing required consent; \
                     apps without consent: {:?}",
                    apps_missing_consent.len(),
                    oidc_app_count,
                    apps_missing_consent
                ),
            )
        };

        let raw_data = json!({
            "oidc_app_count": oidc_app_count,
            "consent_required_count": consent_required_count,
            "apps_missing_consent": apps_missing_consent,
        });

        Ok(vec![Evidence {
            id: Uuid::new_v4(),
            control_id: "OKTA-3.1".to_string(),
            class_uid: 1001,
            category_uid: 1,
            activity_id: 1,
            time: now,
            confidence_level: ConfidenceLevel::PassiveObservation,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "okta.oauth_app_policy".to_string(),
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

    const OIDC_APP_CONSENT_REQUIRED: &str = r#"[
        {
            "id": "app_oidc_1",
            "label": "My OIDC App",
            "name": "oidc_client",
            "status": "ACTIVE",
            "signOnMode": "OPENID_CONNECT",
            "settings": {
                "oauthClient": {
                    "consent_method": "REQUIRED",
                    "refresh_token": {
                        "rotation_type": "ROTATE",
                        "leeway": 30
                    }
                }
            }
        }
    ]"#;

    const OIDC_APP_CONSENT_TRUSTED: &str = r#"[
        {
            "id": "app_oidc_2",
            "label": "Unconsented OIDC App",
            "name": "oidc_client",
            "status": "ACTIVE",
            "signOnMode": "OPENID_CONNECT",
            "settings": {
                "oauthClient": {
                    "consent_method": "TRUSTED",
                    "refresh_token": {
                        "rotation_type": "ROTATE",
                        "leeway": 30
                    }
                }
            }
        }
    ]"#;

    const NO_OIDC_APPS: &str = r#"[
        {
            "id": "app_saml_1",
            "label": "SAML App",
            "name": "saml_app",
            "status": "ACTIVE",
            "signOnMode": "SAML_2_0",
            "settings": {}
        }
    ]"#;

    #[test]
    fn oidc_app_with_consent_required_is_effective() {
        let srv = mock_server(200, OIDC_APP_CONSENT_REQUIRED);
        let ev = &OAuthAppPolicyObserver
            .observe(&base_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert_eq!(ev.control_id, "OKTA-3.1");
        let raw = &ev.raw_data;
        assert_eq!(raw["oidc_app_count"], 1);
        assert_eq!(raw["consent_required_count"], 1);
        let missing: &Vec<Value> = raw["apps_missing_consent"].as_array().unwrap();
        assert!(missing.is_empty());
    }

    #[test]
    fn oidc_app_with_consent_trusted_is_ineffective_with_finding() {
        let srv = mock_server(200, OIDC_APP_CONSENT_TRUSTED);
        let ev = &OAuthAppPolicyObserver
            .observe(&base_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "OAuth App Missing Required Consent"));
        let raw = &ev.raw_data;
        assert_eq!(raw["consent_required_count"], 0);
        let missing = raw["apps_missing_consent"].as_array().unwrap();
        assert_eq!(missing.len(), 1);
    }

    #[test]
    fn no_oidc_apps_returns_unknown_evidence() {
        let srv = mock_server(200, NO_OIDC_APPS);
        let ev = &OAuthAppPolicyObserver
            .observe(&base_config(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Unknown);
        assert_eq!(ev.raw_data["oidc_app_count"], 0);
        assert!(ev.findings.iter().any(|f| f.title == "No OIDC Apps Found"));
    }

    #[test]
    fn metadata_complete() {
        use crate::module::Module;
        let obs = OAuthAppPolicyObserver;
        assert_eq!(obs.id(), "okta.oauth_app_policy");
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
        let result = OAuthAppPolicyObserver.observe(&cfg);
        assert!(result.is_err());
    }

    #[test]
    fn missing_token_errors() {
        let cfg = HashMap::from([
            ("OKTA_DOMAIN".to_string(), "example.okta.com".to_string()),
        ]);
        let result = OAuthAppPolicyObserver.observe(&cfg);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("OKTA_API_TOKEN"));
    }

    #[test]
    fn missing_domain_errors() {
        let cfg = HashMap::from([
            ("OKTA_API_TOKEN".to_string(), "test".to_string()),
        ]);
        let result = OAuthAppPolicyObserver.observe(&cfg);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("OKTA_DOMAIN"));
    }

    #[test]
    fn api_returns_403_errors() {
        let srv = mock_server(403, r#"{"errorCode":"E0000006","errorSummary":"forbidden"}"#);
        let result = OAuthAppPolicyObserver.observe(&base_config(&srv));
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("403"));
    }

    #[test]
    fn api_connection_refused_returns_error() {
        let cfg = base_config("http://127.0.0.1:1");
        let result = OAuthAppPolicyObserver.observe(&cfg);
        assert!(result.is_err());
    }

    #[test]
    fn non_json_array_body_errors() {
        let srv = mock_server(200, r#""not an array""#);
        let result = OAuthAppPolicyObserver.observe(&base_config(&srv));
        assert!(result.is_err());
    }

    #[test]
    fn oidc_app_missing_refresh_token_config_has_finding() {
        // App has REQUIRED consent but no refresh_token block → triggers OKTA-3.3 finding
        let body = r#"[{
            "id": "app_oidc_3",
            "label": "No Refresh Config App",
            "name": "oidc_client",
            "status": "ACTIVE",
            "signOnMode": "OPENID_CONNECT",
            "settings": {
                "oauthClient": {
                    "consent_method": "REQUIRED"
                }
            }
        }]"#;
        let srv = mock_server(200, body);
        let ev = &OAuthAppPolicyObserver.observe(&base_config(&srv)).unwrap()[0];
        // consent is REQUIRED so overall status is Effective, but there should be a refresh token finding
        assert_eq!(ev.status_id, StatusId::Effective);
        assert!(
            ev.findings
                .iter()
                .any(|f| f.title == "OAuth App Missing Refresh Token Expiry Config"),
            "expected a refresh token finding"
        );
    }

    #[test]
    fn oidc_app_consent_trusted_and_no_refresh_has_both_findings() {
        // App has TRUSTED consent AND no refresh_token → two findings
        let body = r#"[{
            "id": "app_oidc_4",
            "label": "Bad App",
            "name": "oidc_client",
            "status": "ACTIVE",
            "signOnMode": "OPENID_CONNECT",
            "settings": {
                "oauthClient": {
                    "consent_method": "TRUSTED"
                }
            }
        }]"#;
        let srv = mock_server(200, body);
        let ev = &OAuthAppPolicyObserver.observe(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev.findings.iter().any(|f| f.title == "OAuth App Missing Required Consent"));
        assert!(ev.findings.iter().any(|f| f.title == "OAuth App Missing Refresh Token Expiry Config"));
    }

    #[test]
    fn empty_app_list_returns_unknown() {
        let srv = mock_server(200, "[]");
        let ev = &OAuthAppPolicyObserver.observe(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Unknown);
    }
}
