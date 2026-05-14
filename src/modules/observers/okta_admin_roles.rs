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

// ─── AdminRolesObserver ───────────────────────────────────────────────────────

/// Queries Okta IAM roles and checks for excessive super admin role assignments.
///
/// Required config: `OKTA_API_TOKEN`, `OKTA_DOMAIN`.
/// Optional: `OKTA_BASE_URL` (test override — defaults to `https://{OKTA_DOMAIN}`).
pub struct AdminRolesObserver;

impl Module for AdminRolesObserver {
    fn id(&self) -> &str {
        "okta.admin_roles"
    }
    fn name(&self) -> &str {
        "Okta Admin Roles Observer"
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
                description: "Okta API token with read access to IAM roles".to_string(),
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

impl Observer for AdminRolesObserver {
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
        let path = "/api/v1/iam/roles";
        let endpoint = format!("{}{}", base_url.trim_end_matches('/'), path);

        let (body, status) = okta_get(token, &base_url, path)?;

        if status != 200 {
            return Err(anyhow!(
                "Okta API returned status {} querying IAM roles",
                status
            ));
        }

        // Okta's /api/v1/iam/roles returns {"roles": [...], "_links": {...}}.
        // Fall back to bare array for mock/test servers.
        let roles_value = body.get("roles").cloned().unwrap_or_else(|| body.clone());
        let roles = roles_value
            .as_array()
            .ok_or_else(|| anyhow!("expected JSON array or {{\"roles\":[...]}} from Okta IAM roles endpoint"))?;

        let mut super_admin_roles: Vec<Value> = Vec::new();
        let mut observables: Vec<Observable> = Vec::new();

        for role in roles {
            let role_type = role
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let label = role
                .get("label")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let role_id = role
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");

            observables.push(Observable {
                obs_type: "resource".to_string(),
                value: format!("role:{}", role_id),
                name: String::new(),
            });

            if role_type == "SUPER_ADMIN" || label.to_lowercase().contains("super administrator") {
                super_admin_roles.push(role.clone());
            }
        }

        let super_admin_count = super_admin_roles.len();

        let mut findings: Vec<Finding> = Vec::new();

        // The built-in Okta super admin role always exists (count == 1 is normal).
        // More than 1 indicates custom super admin roles were created — flag that.
        let (status_id, status_text) = if super_admin_count <= 1 {
            findings.push(Finding {
                title: "Super Admin Roles Within Threshold".to_string(),
                description: format!(
                    "Found {} SUPER_ADMIN role(s); only the built-in role is present",
                    super_admin_count
                ),
                severity_id: 0,
            });
            (
                StatusId::Effective,
                format!(
                    "Super admin role count ({}) is within the expected threshold of 1",
                    super_admin_count
                ),
            )
        } else {
            findings.push(Finding {
                title: "Excessive Super Admin Roles".to_string(),
                description: format!(
                    "Found {} SUPER_ADMIN roles; expected at most 1 (the built-in role). \
                     Additional custom super admin roles increase the blast radius of credential compromise.",
                    super_admin_count
                ),
                severity_id: 3,
            });
            (
                StatusId::Ineffective,
                format!(
                    "Super admin role count ({}) exceeds the threshold of 1",
                    super_admin_count
                ),
            )
        };

        let raw_data = json!({
            "super_admin_role_count": super_admin_count,
            "roles": body,
        });

        Ok(vec![Evidence {
            id: Uuid::new_v4(),
            control_id: "OKTA-1.2".to_string(),
            class_uid: 1001,
            category_uid: 1,
            activity_id: 1,
            time: now,
            confidence_level: ConfidenceLevel::PassiveObservation,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "okta.admin_roles".to_string(),
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

    const SINGLE_SUPER_ADMIN_ROLE: &str = r#"[
        {
            "id": "IFIFAX2BIRGUSTXAN2SS",
            "label": "Super Administrator",
            "type": "SUPER_ADMIN",
            "status": "ACTIVE"
        }
    ]"#;

    const MULTIPLE_SUPER_ADMIN_ROLES: &str = r#"[
        {
            "id": "IFIFAX2BIRGUSTXAN2SS",
            "label": "Super Administrator",
            "type": "SUPER_ADMIN",
            "status": "ACTIVE"
        },
        {
            "id": "CUSTOM_SUPER_ADMIN_1",
            "label": "Custom Super Administrator",
            "type": "SUPER_ADMIN",
            "status": "ACTIVE"
        }
    ]"#;

    #[test]
    fn single_builtin_super_admin_role_is_effective() {
        let srv = mock_server(200, SINGLE_SUPER_ADMIN_ROLE);
        let ev = &AdminRolesObserver.observe(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert_eq!(ev.control_id, "OKTA-1.2");
        let raw = &ev.raw_data;
        assert_eq!(raw["super_admin_role_count"], 1);
    }

    #[test]
    fn multiple_super_admin_roles_is_ineffective() {
        let srv = mock_server(200, MULTIPLE_SUPER_ADMIN_ROLES);
        let ev = &AdminRolesObserver.observe(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "Excessive Super Admin Roles"));
        let raw = &ev.raw_data;
        assert_eq!(raw["super_admin_role_count"], 2);
    }

    #[test]
    fn wrapped_roles_response_is_parsed_correctly() {
        // Real Okta API wraps the array: {"roles": [...], "_links": {...}}
        let body = r#"{"roles":[{"id":"IFIFAX2BIRGUSTXAN2SS","label":"Super Administrator","type":"SUPER_ADMIN","status":"ACTIVE"}],"_links":{"self":{"href":"https://example.okta.com/api/v1/iam/roles"}}}"#;
        let srv = mock_server(200, body);
        let ev = &AdminRolesObserver.observe(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert_eq!(ev.raw_data["super_admin_role_count"], 1);
    }

    #[test]
    fn api_returns_403_errors() {
        let srv = mock_server(403, r#"{"errorCode":"E0000006","errorSummary":"You do not have permission to perform the requested action"}"#);
        let result = AdminRolesObserver.observe(&base_config(&srv));
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("403"));
    }

    #[test]
    fn metadata_complete() {
        use crate::module::Module;
        let obs = AdminRolesObserver;
        assert_eq!(obs.id(), "okta.admin_roles");
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
        let result = AdminRolesObserver.observe(&cfg);
        assert!(result.is_err());
    }

    #[test]
    fn missing_token_errors() {
        let cfg = HashMap::from([
            ("OKTA_DOMAIN".to_string(), "example.okta.com".to_string()),
        ]);
        let result = AdminRolesObserver.observe(&cfg);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("OKTA_API_TOKEN"));
    }

    #[test]
    fn missing_domain_errors() {
        let cfg = HashMap::from([
            ("OKTA_API_TOKEN".to_string(), "test".to_string()),
        ]);
        let result = AdminRolesObserver.observe(&cfg);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("OKTA_DOMAIN"));
    }

    #[test]
    fn api_connection_refused_returns_error() {
        // Port 1 is privileged and always refused on localhost
        let cfg = base_config("http://127.0.0.1:1");
        let result = AdminRolesObserver.observe(&cfg);
        assert!(result.is_err());
    }

    #[test]
    fn non_json_array_body_errors() {
        // A JSON string (not an array) triggers the ok_or_else error path
        let srv = mock_server(200, r#""not an array""#);
        let result = AdminRolesObserver.observe(&base_config(&srv));
        assert!(result.is_err());
    }

    #[test]
    fn okta_get_invalid_json_on_200_returns_error() {
        // 200 with non-JSON body → into_json().map_err(...) closure fires
        let srv = mock_server(200, "this is not json {");
        let result = AdminRolesObserver.observe(&base_config(&srv));
        assert!(result.is_err());
    }

    #[test]
    fn okta_get_invalid_json_on_error_status_uses_fallback() {
        // 500 with non-JSON body → unwrap_or_else fallback fires, then
        // status-based branch handles the result. observe() should still
        // surface a structured error (not panic).
        let srv = mock_server(500, "<html>500</html>");
        let result = AdminRolesObserver.observe(&base_config(&srv));
        assert!(result.is_err());
    }
}
