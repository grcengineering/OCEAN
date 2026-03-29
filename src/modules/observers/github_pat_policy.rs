use std::collections::HashMap;

use anyhow::{anyhow, Result};
use chrono::Utc;
use uuid::Uuid;

use crate::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId,
};
use crate::module::{observer::Observer, CredentialReq, Module};
use crate::modules::github_common::{github_get, DEFAULT_GITHUB_API};

// ─── PatPolicyObserver ───────────────────────────────────────────────────────

/// Checks whether the GitHub organization requires admin approval for
/// fine-grained personal access tokens (PATs).
///
/// The `/orgs/{org}/personal-access-token-requests` endpoint only exists when
/// the PAT approval policy is enabled (GHEC feature). A 200 response means
/// the policy is enforced; 404 or 403 means it is not enforced or not
/// available.
///
/// Control: GH-1.7 — PATs require admin approval / fine-grained PATs enforced.
/// Required config: `GITHUB_TOKEN`, `GITHUB_ORG`.
/// Optional: `GITHUB_API_URL` (test override).
pub struct PatPolicyObserver;

impl Module for PatPolicyObserver {
    fn id(&self) -> &str {
        "github.pat_policy"
    }
    fn name(&self) -> &str {
        "GitHub PAT Policy Observer"
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
                description: "GitHub PAT with admin:org scope for reading PAT policy".to_string(),
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

impl Observer for PatPolicyObserver {
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
        let path = format!("/orgs/{}/personal-access-token-requests?per_page=1", org);
        let endpoint = format!("{}{}", base_url.trim_end_matches('/'), &path);

        let (body, status) = github_get(token, base_url, &path)?;

        let (pat_approval_required, status_id, findings) = match status {
            200 => {
                // Endpoint exists — policy is enforced.
                let pending = body.as_array().map(|a| a.len()).unwrap_or(0);
                let _ = pending; // used in raw_data below
                (true, StatusId::Effective, vec![])
            }
            403 | 404 => {
                // Endpoint unavailable — policy not enforced or not GHEC.
                let finding = Finding {
                    title: "PAT Approval Policy Not Enforced".to_string(),
                    description: format!(
                        "Fine-grained PAT approval policy is not enforced for organization {} \
                         (API returned {}). This feature requires GitHub Enterprise Cloud.",
                        org, status
                    ),
                    severity_id: 3,
                };
                (false, StatusId::Ineffective, vec![finding])
            }
            other => {
                return Err(anyhow!(
                    "GitHub API returned unexpected status {} for {}",
                    other,
                    path
                ));
            }
        };

        let pending_requests = if pat_approval_required {
            body.as_array().map(|a| a.len()).unwrap_or(0)
        } else {
            0
        };

        let status_msg = if pat_approval_required {
            format!(
                "Fine-grained PAT approval policy is enforced for organization {}",
                org
            )
        } else {
            format!(
                "Fine-grained PAT approval policy is not enforced for organization {}",
                org
            )
        };

        let raw_data = serde_json::json!({
            "pat_approval_required": pat_approval_required,
            "pending_requests": pending_requests
        });

        Ok(vec![Evidence {
            id: Uuid::new_v4(),
            control_id: "GH-1.7".to_string(),
            class_uid: 1003,
            category_uid: 2,
            activity_id: 1,
            time: now,
            confidence_level: ConfidenceLevel::PassiveObservation,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "github.pat_policy".to_string(),
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
                name: "pat_approval_required".to_string(),
                value: pat_approval_required.to_string(),
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
    fn pat_200_empty_array_is_effective() {
        let srv = mock_server(200, r#"[]"#);
        let ev = &PatPolicyObserver
            .observe(&test_config_with_org(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert!(ev.findings.is_empty());
        assert_eq!(ev.raw_data["pat_approval_required"], true);
        assert_eq!(ev.control_id, "GH-1.7");
    }

    #[test]
    fn pat_404_is_ineffective_with_finding() {
        let srv = mock_server(404, r#"{"message":"Not Found"}"#);
        let ev = &PatPolicyObserver
            .observe(&test_config_with_org(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(!ev.findings.is_empty());
        assert_eq!(ev.raw_data["pat_approval_required"], false);
    }

    #[test]
    fn pat_403_is_ineffective_with_finding() {
        let srv = mock_server(403, r#"{"message":"Forbidden"}"#);
        let ev = &PatPolicyObserver
            .observe(&test_config_with_org(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(!ev.findings.is_empty());
        assert!(ev.findings[0].description.contains("403"));
    }
}
