use std::collections::HashMap;

use anyhow::{anyhow, Result};
use chrono::Utc;
use uuid::Uuid;

use crate::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId,
    EVIDENCE_SCHEMA_VERSION,
};
use crate::module::{observer::Observer, CredentialReq, Module};
use crate::modules::github_common::{github_get, DEFAULT_GITHUB_API};

// ─── OrgAdminAuditObserver ───────────────────────────────────────────────────

/// Counts organization admins and flags if the count exceeds 5.
///
/// Control: GH-1.4 — admin count should be minimal (≤ 5).
/// Required config: `GITHUB_TOKEN`, `GITHUB_ORG`.
/// Optional: `GITHUB_API_URL` (test override).
pub struct OrgAdminAuditObserver;

impl Module for OrgAdminAuditObserver {
    fn id(&self) -> &str {
        "github.org_admin_audit"
    }
    fn name(&self) -> &str {
        "GitHub Org Admin Audit Observer"
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
                description: "GitHub PAT with admin:org scope for listing org members".to_string(),
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

impl Observer for OrgAdminAuditObserver {
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
        let path = format!("/orgs/{}/members?role=admin", org);
        let endpoint = format!("{}{}", base_url.trim_end_matches('/'), path);

        let (body, status) = github_get(token, base_url, &path)?;

        if status != 200 {
            return Err(anyhow!(
                "GitHub API returned status {} for {}",
                status,
                path
            ));
        }

        let empty_vec = vec![];
        let members = body.as_array().unwrap_or(&empty_vec);
        let admin_count = members.len();

        let logins: Vec<String> = members
            .iter()
            .filter_map(|m| m.get("login").and_then(|v| v.as_str()).map(String::from))
            .collect();

        let is_effective = admin_count <= 5;

        let status_id = if is_effective {
            StatusId::Effective
        } else {
            StatusId::Ineffective
        };

        let mut findings: Vec<Finding> = Vec::new();
        if !is_effective {
            findings.push(Finding {
                title: "Excessive Admin Count".to_string(),
                description: format!("Excessive admin count: {} admins", admin_count),
                severity_id: 3,
            });
        }

        let status_msg = if is_effective {
            format!(
                "Admin count {} is within acceptable limit for organization {}",
                admin_count, org
            )
        } else {
            format!(
                "Admin count {} exceeds limit of 5 for organization {}",
                admin_count, org
            )
        };

        let raw_data = serde_json::json!({
            "admin_count": admin_count,
            "admins": logins
        });

        Ok(vec![Evidence {
            schema_version: EVIDENCE_SCHEMA_VERSION.to_string(),
            connected_account: None,
            population: None,
            evaluation: None,
            id: Uuid::new_v4(),
            control_id: "GH-1.4".to_string(),
            class_uid: 1003,
            category_uid: 2,
            activity_id: 1,
            time: now,
            confidence_level: ConfidenceLevel::PassiveObservation,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "github.org_admin_audit".to_string(),
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
                obs_type: "count".to_string(),
                name: "admin_count".to_string(),
                value: admin_count.to_string(),
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
    fn two_admins_is_effective() {
        let srv = mock_server(200, r#"[{"login":"alice"},{"login":"bob"}]"#);
        let ev = &OrgAdminAuditObserver
            .observe(&test_config_with_org(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert!(ev.findings.is_empty());
        assert_eq!(ev.raw_data["admin_count"], 2);
    }

    #[test]
    fn six_admins_is_ineffective_with_finding() {
        let srv = mock_server(
            200,
            r#"[{"login":"a"},{"login":"b"},{"login":"c"},{"login":"d"},{"login":"e"},{"login":"f"}]"#,
        );
        let ev = &OrgAdminAuditObserver
            .observe(&test_config_with_org(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.description.contains("6 admins")));
    }

    #[test]
    fn admin_audit_403_returns_err() {
        let srv = mock_server(403, r#"{"message":"Forbidden"}"#);
        let result = OrgAdminAuditObserver.observe(&test_config_with_org(&srv));
        assert!(result.is_err());
    }
}
