use std::collections::HashMap;

use anyhow::{anyhow, Result};
use chrono::Utc;
use uuid::Uuid;

use crate::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId,
};
use crate::module::{observer::Observer, CredentialReq, Module};
use crate::modules::github_common::{github_get, DEFAULT_GITHUB_API};

// ─── OrgMfaEnforcementObserver ───────────────────────────────────────────────

/// Checks whether the GitHub organization enforces two-factor authentication
/// (2FA / MFA) for all members.
///
/// Control: GH-1.1 — 2FA required for all members.
/// Required config: `GITHUB_TOKEN`, `GITHUB_ORG`.
/// Optional: `GITHUB_API_URL` (test override).
pub struct OrgMfaEnforcementObserver;

impl Module for OrgMfaEnforcementObserver {
    fn id(&self) -> &str {
        "github.org_mfa_enforcement"
    }
    fn name(&self) -> &str {
        "GitHub Org MFA Enforcement Observer"
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

impl Observer for OrgMfaEnforcementObserver {
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
        let endpoint = format!("{}{}", base_url.trim_end_matches('/'), path);

        let (body, status) = github_get(token, base_url, &path)?;

        if status != 200 {
            return Err(anyhow!(
                "GitHub API returned status {} for {}",
                status,
                path
            ));
        }

        let mfa_enabled = body
            .get("two_factor_requirement_enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let status_id = if mfa_enabled {
            StatusId::Effective
        } else {
            StatusId::Ineffective
        };

        let mut findings: Vec<Finding> = Vec::new();
        if !mfa_enabled {
            findings.push(Finding {
                title: "MFA Not Enforced".to_string(),
                description: "MFA not enforced for all org members".to_string(),
                severity_id: 3,
            });
        }

        let status_msg = if mfa_enabled {
            format!("MFA enforced for organization {}", org)
        } else {
            format!("MFA not enforced for organization {}", org)
        };

        let raw_data = serde_json::json!({
            "two_factor_requirement_enabled": mfa_enabled
        });

        Ok(vec![Evidence {
            id: Uuid::new_v4(),
            control_id: "GH-1.1".to_string(),
            class_uid: 1003,
            category_uid: 2,
            activity_id: 1,
            time: now,
            confidence_level: ConfidenceLevel::PassiveObservation,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "github.org_mfa_enforcement".to_string(),
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
                name: "mfa_enabled".to_string(),
                value: mfa_enabled.to_string(),
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
    fn mfa_enabled_is_effective() {
        let srv = mock_server(200, r#"{"two_factor_requirement_enabled":true}"#);
        let ev = &OrgMfaEnforcementObserver
            .observe(&test_config_with_org(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert!(ev.findings.is_empty());
        assert_eq!(ev.control_id, "GH-1.1");
    }

    #[test]
    fn mfa_disabled_is_ineffective_with_finding() {
        let srv = mock_server(200, r#"{"two_factor_requirement_enabled":false}"#);
        let ev = &OrgMfaEnforcementObserver
            .observe(&test_config_with_org(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.description.contains("MFA not enforced")));
    }

    #[test]
    fn mfa_api_error_returns_err() {
        let srv = mock_server(404, r#"{"message":"Not Found"}"#);
        let result = OrgMfaEnforcementObserver.observe(&test_config_with_org(&srv));
        assert!(result.is_err());
    }

    #[test]
    fn mfa_evidence_types() {
        assert_eq!(OrgMfaEnforcementObserver.evidence_types(), &[1003]);
    }

    #[test]
    fn mfa_credential_requirements() {
        let reqs = OrgMfaEnforcementObserver.credential_requirements();
        assert_eq!(reqs.len(), 2);
        assert!(reqs.iter().any(|r| r.name == "GITHUB_TOKEN" && r.required));
        assert!(reqs.iter().any(|r| r.name == "GITHUB_ORG" && r.required));
    }

    #[test]
    fn mfa_missing_token_errors() {
        let err = OrgMfaEnforcementObserver
            .observe(&HashMap::from([(
                "GITHUB_ORG".to_string(),
                "org".to_string(),
            )]))
            .unwrap_err();
        assert!(err.to_string().contains("GITHUB_TOKEN"));
    }

    #[test]
    fn mfa_missing_org_errors() {
        let err = OrgMfaEnforcementObserver
            .observe(&HashMap::from([(
                "GITHUB_TOKEN".to_string(),
                "tok".to_string(),
            )]))
            .unwrap_err();
        assert!(err.to_string().contains("GITHUB_ORG"));
    }
}
