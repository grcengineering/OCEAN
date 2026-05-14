use std::collections::HashMap;

use anyhow::{anyhow, Result};
use chrono::Utc;
use uuid::Uuid;

use crate::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId,
};
use crate::module::{observer::Observer, CredentialReq, Module};
use crate::modules::github_common::{github_get, DEFAULT_GITHUB_API};

// ─── OrgBasePermissionsObserver ──────────────────────────────────────────────

/// Checks the default repository permission for the GitHub organization.
///
/// Control: GH-1.2 — base permission should be "none" or "read", not "write"
/// or "admin".
/// Required config: `GITHUB_TOKEN`, `GITHUB_ORG`.
/// Optional: `GITHUB_API_URL` (test override).
pub struct OrgBasePermissionsObserver;

impl Module for OrgBasePermissionsObserver {
    fn id(&self) -> &str {
        "github.org_base_permissions"
    }
    fn name(&self) -> &str {
        "GitHub Org Base Permissions Observer"
    }
    fn version(&self) -> &str {
        "0.1.0"
    }
    fn source_system(&self) -> &str {
        "github"
    }
    fn evidence_types(&self) -> &[i32] {
        &[1003]
    }

    fn credential_requirements(&self) -> Vec<CredentialReq> {
        vec![
            CredentialReq {
                name: "GITHUB_TOKEN".to_string(),
                cred_type: "api_token".to_string(),
                description: "GitHub PAT with admin:org scope for reading org settings".to_string(),
                required: true,
            },
            CredentialReq {
                name: "GITHUB_ORG".to_string(),
                cred_type: "config".to_string(),
                description: "GitHub organization name".to_string(),
                required: true,
            },
        ]
    }
}

impl Observer for OrgBasePermissionsObserver {
    fn observe(&self, config: &HashMap<String, String>) -> Result<Vec<Evidence>> {
        let token = config
            .get("GITHUB_TOKEN")
            .ok_or_else(|| anyhow!("GITHUB_TOKEN required"))?;
        let org = config
            .get("GITHUB_ORG")
            .ok_or_else(|| anyhow!("GITHUB_ORG required"))?;
        let base_url = config
            .get("GITHUB_API_URL")
            .map(|s| s.as_str())
            .unwrap_or(DEFAULT_GITHUB_API);

        let now = Utc::now();
        let path = format!("/orgs/{}", org);
        let endpoint = format!("{}{}", base_url.trim_end_matches('/'), &path);

        let (body, status) = github_get(token, base_url, &path)?;

        if status != 200 {
            return Err(anyhow!(
                "GitHub API returned status {} for {}",
                status,
                path
            ));
        }

        let permission = body
            .get("default_repository_permission")
            .and_then(|v| v.as_str())
            .unwrap_or("none")
            .to_string();

        let is_effective = matches!(permission.as_str(), "none" | "read");

        let status_id = if is_effective {
            StatusId::Effective
        } else {
            StatusId::Ineffective
        };

        let mut findings: Vec<Finding> = Vec::new();
        if !is_effective {
            findings.push(Finding {
                title: "Overly Permissive Base Permission".to_string(),
                description: format!(
                    "Default repository permission is '{}'; should be 'none' or 'read'",
                    permission
                ),
                severity_id: 3,
            });
        }

        let status_msg = if is_effective {
            format!(
                "Base permission '{}' is acceptable for organization {}",
                permission, org
            )
        } else {
            format!(
                "Base permission '{}' is too permissive for organization {}",
                permission, org
            )
        };

        let raw_data = serde_json::json!({
            "default_repository_permission": permission
        });

        Ok(vec![Evidence {
            id: Uuid::new_v4(),
            control_id: "GH-1.2".to_string(),
            class_uid: 1003,
            category_uid: 2,
            activity_id: 1,
            time: now,
            confidence_level: ConfidenceLevel::PassiveObservation,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "github.org_base_permissions".to_string(),
                    version: "0.1.0".to_string(),
                    module_type: "observer".to_string(),
                },
                source: SourceInfo {
                    system: "github".to_string(),
                    api_version: "v3".to_string(),
                    endpoint,
                },
                original_time: None,
                processed_time: now,
                safety_classification: None,
            },
            observables: vec![Observable {
                obs_type: "policy".to_string(),
                name: "default_repository_permission".to_string(),
                value: permission,
            }],
            status_id,
            status: status_msg,
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
    use crate::modules::github_common::{mock_server, test_config_with_org};

    #[test]
    fn base_permission_none_is_effective() {
        let srv = mock_server(200, r#"{"default_repository_permission":"none"}"#);
        let ev = &OrgBasePermissionsObserver
            .observe(&test_config_with_org(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert!(ev.findings.is_empty());
        assert_eq!(ev.control_id, "GH-1.2");
    }

    #[test]
    fn base_permission_write_is_ineffective_with_finding() {
        let srv = mock_server(200, r#"{"default_repository_permission":"write"}"#);
        let ev = &OrgBasePermissionsObserver
            .observe(&test_config_with_org(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(!ev.findings.is_empty());
        assert!(ev.findings[0].description.contains("write"));
    }

    #[test]
    fn base_permission_admin_is_ineffective_with_finding() {
        let srv = mock_server(200, r#"{"default_repository_permission":"admin"}"#);
        let ev = &OrgBasePermissionsObserver
            .observe(&test_config_with_org(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(!ev.findings.is_empty());
        assert!(ev.findings[0].description.contains("admin"));
    }

    #[test]
    fn base_permission_api_error_returns_err() {
        let srv = mock_server(404, r#"{"message":"Not Found"}"#);
        let result = OrgBasePermissionsObserver.observe(&test_config_with_org(&srv));
        assert!(result.is_err());
    }

    #[test]
    fn base_permission_evidence_types() {
        assert_eq!(OrgBasePermissionsObserver.evidence_types(), &[1003]);
    }

    #[test]
    fn base_permission_credential_requirements() {
        let reqs = OrgBasePermissionsObserver.credential_requirements();
        assert_eq!(reqs.len(), 2);
        assert!(reqs.iter().any(|r| r.name == "GITHUB_TOKEN" && r.required));
        assert!(reqs.iter().any(|r| r.name == "GITHUB_ORG" && r.required));
    }

    #[test]
    fn base_permission_missing_token_errors() {
        let err = OrgBasePermissionsObserver
            .observe(&HashMap::from([(
                "GITHUB_ORG".to_string(),
                "org".to_string(),
            )]))
            .unwrap_err();
        assert!(err.to_string().contains("GITHUB_TOKEN"));
    }

    #[test]
    fn base_permission_missing_org_errors() {
        let err = OrgBasePermissionsObserver
            .observe(&HashMap::from([(
                "GITHUB_TOKEN".to_string(),
                "tok".to_string(),
            )]))
            .unwrap_err();
        assert!(err.to_string().contains("GITHUB_ORG"));
    }
}
