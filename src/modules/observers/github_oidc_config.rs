use std::collections::HashMap;

use anyhow::{anyhow, Result};
use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

use crate::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId,
};
use crate::module::{observer::Observer, CredentialReq, Module};
use crate::modules::github_common::{github_get, DEFAULT_GITHUB_API};

// ─── OidcConfigObserver ──────────────────────────────────────────────────────

/// Checks whether the GitHub Actions OIDC customization sub-claim is configured
/// for the organization. OIDC sub-claim customization enables cloud workload
/// identity federation without hardcoded secrets.
///
/// Required config: `GITHUB_TOKEN`, `GITHUB_ORG`.
/// Optional: `GITHUB_API_URL` (test override).
pub struct OidcConfigObserver;

impl Module for OidcConfigObserver {
    fn id(&self) -> &str {
        "github.oidc_config"
    }
    fn name(&self) -> &str {
        "GitHub Actions OIDC Config Observer"
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
                description: "GitHub PAT with admin:org scope for reading OIDC configuration"
                    .to_string(),
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

impl Observer for OidcConfigObserver {
    fn observe(&self, config: &HashMap<String, String>) -> Result<Vec<Evidence>> {
        let token = config
            .get("GITHUB_TOKEN")
            .ok_or_else(|| anyhow!("GITHUB_TOKEN is required"))?;
        let org = config
            .get("GITHUB_ORG")
            .ok_or_else(|| anyhow!("GITHUB_ORG is required"))?;
        let base_url = config
            .get("GITHUB_API_URL")
            .map(|s| s.as_str())
            .unwrap_or(DEFAULT_GITHUB_API);

        let now = Utc::now();
        let path = format!("/orgs/{}/actions/oidc/customization/sub", org);
        let endpoint = format!("{}{}", base_url.trim_end_matches('/'), path);

        let (body, status) = github_get(token, base_url, &path)?;

        if status == 403 {
            return Err(anyhow!(
                "GitHub API returned status 403 for {} — insufficient permissions",
                path
            ));
        }

        let (status_id, raw_data, findings) = if status == 200 {
            let claim_keys = body
                .get("include_claim_keys")
                .and_then(|v| v.as_array())
                .map(|a| !a.is_empty())
                .unwrap_or(false);

            if claim_keys {
                (
                    StatusId::Effective,
                    body.clone(),
                    vec![Finding {
                        title: "OIDC Sub-Claim Configured".to_string(),
                        description: format!(
                            "Organization {} has customized OIDC sub-claim keys configured, \
                             enabling secure cloud workload identity federation.",
                            org
                        ),
                        severity_id: 0,
                    }],
                )
            } else {
                (
                    StatusId::Ineffective,
                    json!({ "oidc_configured": false }),
                    vec![Finding {
                        title: "OIDC Sub-Claim Not Configured".to_string(),
                        description: format!(
                            "Organization {} has no customized OIDC sub-claim keys. \
                             Configure OIDC sub-claim customization to enable secure \
                             cloud workload identity without hardcoded secrets (GH-5.2, GH-3.6).",
                            org
                        ),
                        severity_id: 2,
                    }],
                )
            }
        } else {
            // 404 — OIDC customization not configured
            (
                StatusId::Ineffective,
                json!({ "oidc_configured": false }),
                vec![Finding {
                    title: "OIDC Sub-Claim Not Configured".to_string(),
                    description: format!(
                        "Organization {} has not configured OIDC sub-claim customization \
                         (endpoint returned {}). Configure OIDC to avoid hardcoded secrets \
                         (GH-5.2, GH-3.6).",
                        org, status
                    ),
                    severity_id: 2,
                }],
            )
        };

        let status_msg = if status_id == StatusId::Effective {
            format!(
                "OIDC sub-claim customization is configured for organization {}",
                org
            )
        } else {
            format!(
                "OIDC sub-claim customization is not configured for organization {}",
                org
            )
        };

        Ok(vec![Evidence {
            id: Uuid::new_v4(),
            control_id: "GH-5.2".to_string(),
            class_uid: 1003,
            category_uid: 2,
            activity_id: 1,
            time: now,
            confidence_level: ConfidenceLevel::PassiveObservation,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "github.oidc_config".to_string(),
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
            observables: vec![
                Observable {
                    obs_type: "resource".to_string(),
                    value: format!("{}:oidc_config", org),
                    name: String::new(),
                },
                Observable {
                    obs_type: "domain".to_string(),
                    value: "github.com".to_string(),
                    name: String::new(),
                },
            ],
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
    fn oidc_configured_is_effective() {
        let srv = mock_server(200, r#"{"include_claim_keys":["repo","context","ref"]}"#);
        let ev = &OidcConfigObserver
            .observe(&test_config_with_org(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "OIDC Sub-Claim Configured"));
    }

    #[test]
    fn oidc_not_configured_404_is_ineffective_with_finding() {
        let srv = mock_server(404, r#"{"message":"Not Found"}"#);
        let ev = &OidcConfigObserver
            .observe(&test_config_with_org(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "OIDC Sub-Claim Not Configured"));
    }

    #[test]
    fn oidc_403_returns_err() {
        let srv = mock_server(403, r#"{"message":"Forbidden"}"#);
        let result = OidcConfigObserver.observe(&test_config_with_org(&srv));
        assert!(result.is_err());
    }

    #[test]
    fn oidc_empty_claim_keys_is_ineffective() {
        let srv = mock_server(200, r#"{"include_claim_keys":[]}"#);
        let ev = &OidcConfigObserver
            .observe(&test_config_with_org(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "OIDC Sub-Claim Not Configured"));
    }

    #[test]
    fn oidc_evidence_types() {
        assert_eq!(OidcConfigObserver.evidence_types(), &[1003]);
    }

    #[test]
    fn oidc_credential_requirements() {
        let reqs = OidcConfigObserver.credential_requirements();
        assert_eq!(reqs.len(), 2);
        assert!(reqs.iter().any(|r| r.name == "GITHUB_TOKEN" && r.required));
        assert!(reqs.iter().any(|r| r.name == "GITHUB_ORG" && r.required));
    }

    #[test]
    fn oidc_missing_token_errors() {
        let err = OidcConfigObserver
            .observe(&HashMap::from([(
                "GITHUB_ORG".to_string(),
                "org".to_string(),
            )]))
            .unwrap_err();
        assert!(err.to_string().contains("GITHUB_TOKEN"));
    }

    #[test]
    fn oidc_missing_org_errors() {
        let err = OidcConfigObserver
            .observe(&HashMap::from([(
                "GITHUB_TOKEN".to_string(),
                "tok".to_string(),
            )]))
            .unwrap_err();
        assert!(err.to_string().contains("GITHUB_ORG"));
    }
}
