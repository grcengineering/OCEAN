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

// ─── OAuthAppsObserver ───────────────────────────────────────────────────────

/// Checks whether any third-party OAuth app tokens have been authorized for the
/// organization. An empty credential-authorization list indicates that OAuth app
/// access is effectively restricted (GH-4.1). GHEC-only endpoint.
///
/// Required config: `GITHUB_TOKEN`, `GITHUB_ORG`.
/// Optional: `GITHUB_API_URL` (test override).
pub struct OAuthAppsObserver;

impl Module for OAuthAppsObserver {
    fn id(&self) -> &str {
        "github.oauth_apps"
    }
    fn name(&self) -> &str {
        "GitHub OAuth Apps Observer"
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
                description: "GitHub PAT with admin:org scope for reading credential authorizations"
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

impl Observer for OAuthAppsObserver {
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
        let path = format!("/orgs/{}/credential-authorizations?per_page=1", org);
        let endpoint = format!("{}{}", base_url.trim_end_matches('/'), &path);

        let (body, status) = github_get(token, base_url, &path)?;

        let (status_id, raw_data, findings) = match status {
            200 => {
                let count = body.as_array().map(|a| a.len()).unwrap_or(0);
                let raw = json!({ "oauth_token_count": count, "ghec_available": true });

                if count == 0 {
                    (
                        StatusId::Effective,
                        raw,
                        vec![Finding {
                            title: "No Third-Party OAuth Tokens".to_string(),
                            description: format!(
                                "Organization {} has no third-party OAuth app tokens authorized. \
                                 OAuth app access is effectively restricted (GH-4.1).",
                                org
                            ),
                            severity_id: 0,
                        }],
                    )
                } else {
                    (
                        StatusId::Ineffective,
                        raw,
                        vec![Finding {
                            title: "Third-Party OAuth Tokens Present".to_string(),
                            description: format!(
                                "Organization {} has {} third-party OAuth app token(s) authorized. \
                                 Review and revoke unnecessary OAuth app access to satisfy GH-4.1.",
                                org, count
                            ),
                            severity_id: 2,
                        }],
                    )
                }
            }
            404 | 403 => {
                let raw = json!({ "oauth_token_count": 0, "ghec_available": false });
                (
                    StatusId::Unknown,
                    raw,
                    vec![Finding {
                        title: "OAuth App Check Unavailable".to_string(),
                        description: format!(
                            "Organization {} returned HTTP {} for credential-authorizations. \
                             This endpoint requires GitHub Enterprise Cloud (GHEC). \
                             Upgrade to GHEC to enforce GH-4.1.",
                            org, status
                        ),
                        severity_id: 1,
                    }],
                )
            }
            _ => {
                return Err(anyhow!(
                    "GitHub API returned unexpected status {} for {}",
                    status,
                    path
                ));
            }
        };

        let status_msg = match status_id {
            StatusId::Effective => {
                format!("No third-party OAuth tokens found for organization {}", org)
            }
            StatusId::Ineffective => {
                format!("Third-party OAuth tokens are present for organization {}", org)
            }
            _ => format!(
                "OAuth app check unavailable for organization {} (GHEC required)",
                org
            ),
        };

        Ok(vec![Evidence {
            id: Uuid::new_v4(),
            control_id: "GH-4.1".to_string(),
            class_uid: 1003,
            category_uid: 2,
            activity_id: 1,
            time: now,
            confidence_level: ConfidenceLevel::PassiveObservation,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "github.oauth_apps".to_string(),
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
                    value: format!("{}:oauth_apps", org),
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
    fn oauth_no_tokens_is_effective() {
        let srv = mock_server(200, r#"[]"#);
        let ev = &OAuthAppsObserver
            .observe(&test_config_with_org(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "No Third-Party OAuth Tokens"));
        assert_eq!(ev.raw_data["oauth_token_count"], 0);
        assert_eq!(ev.raw_data["ghec_available"], true);
    }

    #[test]
    fn oauth_tokens_present_is_ineffective_with_finding() {
        let srv = mock_server(
            200,
            r#"[{"login":"some-app","credential_type":"oauth_token"}]"#,
        );
        let ev = &OAuthAppsObserver
            .observe(&test_config_with_org(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "Third-Party OAuth Tokens Present"));
        assert_eq!(ev.raw_data["oauth_token_count"], 1);
    }

    #[test]
    fn oauth_404_is_unknown_with_ghec_note() {
        let srv = mock_server(404, r#"{"message":"Not Found"}"#);
        let ev = &OAuthAppsObserver
            .observe(&test_config_with_org(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Unknown);
        assert_eq!(ev.raw_data["ghec_available"], false);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "OAuth App Check Unavailable"));
    }

    #[test]
    fn oauth_unexpected_status_returns_err() {
        let srv = mock_server(500, r#"{"message":"Internal Server Error"}"#);
        let result = OAuthAppsObserver.observe(&test_config_with_org(&srv));
        assert!(result.is_err());
    }

    #[test]
    fn oauth_evidence_types() {
        assert_eq!(OAuthAppsObserver.evidence_types(), &[1003]);
    }

    #[test]
    fn oauth_credential_requirements() {
        let reqs = OAuthAppsObserver.credential_requirements();
        assert_eq!(reqs.len(), 2);
        assert!(reqs.iter().any(|r| r.name == "GITHUB_TOKEN" && r.required));
        assert!(reqs.iter().any(|r| r.name == "GITHUB_ORG" && r.required));
    }

    #[test]
    fn oauth_missing_token_errors() {
        let err = OAuthAppsObserver
            .observe(&HashMap::from([(
                "GITHUB_ORG".to_string(),
                "org".to_string(),
            )]))
            .unwrap_err();
        assert!(err.to_string().contains("GITHUB_TOKEN"));
    }

    #[test]
    fn oauth_missing_org_errors() {
        let err = OAuthAppsObserver
            .observe(&HashMap::from([(
                "GITHUB_TOKEN".to_string(),
                "tok".to_string(),
            )]))
            .unwrap_err();
        assert!(err.to_string().contains("GITHUB_ORG"));
    }
}
