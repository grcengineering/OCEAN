use std::collections::HashMap;

use anyhow::{anyhow, Result};
use chrono::Utc;
use uuid::Uuid;

use crate::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId,
};
use crate::module::{observer::Observer, CredentialReq, Module};
use crate::modules::github_common::{github_get, DEFAULT_GITHUB_API};

// ─── SamlSsoObserver ─────────────────────────────────────────────────────────

/// Attempts to determine SAML SSO status for the GitHub organization.
///
/// The GitHub REST API does not expose SAML SSO configuration directly outside
/// of GitHub Enterprise Cloud (GHEC) or GraphQL. This observer always returns
/// status "unknown" with an informational finding noting the GHEC requirement.
///
/// Control: GH-1.3 — SAML SSO must be enabled for the org.
/// Required config: `GITHUB_TOKEN`, `GITHUB_ORG`.
/// Optional: `GITHUB_API_URL` (test override).
pub struct SamlSsoObserver;

impl Module for SamlSsoObserver {
    fn id(&self) -> &str {
        "github.saml_sso"
    }
    fn name(&self) -> &str {
        "GitHub SAML SSO Observer"
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
                description: "GitHub PAT with admin:org scope".to_string(),
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

impl Observer for SamlSsoObserver {
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

        let (_body, status) = github_get(token, base_url, &path)?;

        if status != 200 {
            return Err(anyhow!(
                "GitHub API returned status {} for {}",
                status,
                path
            ));
        }

        // SAML SSO status is not exposed via the public REST API without GHEC.
        // We emit an informational "unknown" evidence record to flag this gap.
        let raw_data = serde_json::json!({
            "saml_check": "requires_ghec",
            "note": "SAML SSO status requires GitHub Enterprise Cloud API"
        });

        let findings = vec![Finding {
            title: "SAML SSO Verification Requires GHEC".to_string(),
            description: "SAML SSO status cannot be determined via the standard REST API. \
                          Use the GitHub Enterprise Cloud API or GraphQL to verify."
                .to_string(),
            severity_id: 1,
        }];

        Ok(vec![Evidence {
            id: Uuid::new_v4(),
            control_id: "GH-1.3".to_string(),
            class_uid: 1003,
            category_uid: 2,
            activity_id: 1,
            time: now,
            confidence_level: ConfidenceLevel::PassiveObservation,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "github.saml_sso".to_string(),
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
                name: "saml_sso_status".to_string(),
                value: "unknown".to_string(),
            }],
            status_id: StatusId::Unknown,
            status: format!(
                "SAML SSO status unknown for organization {} — GHEC API required",
                org
            ),
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
    fn saml_200_response_returns_unknown_status() {
        let srv = mock_server(200, r#"{"login":"acme-org","plan":{"name":"enterprise"}}"#);
        let ev = &SamlSsoObserver
            .observe(&test_config_with_org(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Unknown);
        assert!(ev.raw_data["saml_check"] == "requires_ghec");
        assert!(!ev.findings.is_empty());
    }

    #[test]
    fn saml_404_returns_err() {
        let srv = mock_server(404, r#"{"message":"Not Found"}"#);
        let result = SamlSsoObserver.observe(&test_config_with_org(&srv));
        assert!(result.is_err());
    }

    #[test]
    fn saml_missing_org_returns_err() {
        use std::collections::HashMap;
        let err = SamlSsoObserver
            .observe(&HashMap::from([(
                "GITHUB_TOKEN".to_string(),
                "tok".to_string(),
            )]))
            .unwrap_err();
        assert!(err.to_string().contains("GITHUB_ORG"));
    }

    #[test]
    fn saml_missing_token_returns_err() {
        use std::collections::HashMap;
        let err = SamlSsoObserver
            .observe(&HashMap::from([(
                "GITHUB_ORG".to_string(),
                "acme-org".to_string(),
            )]))
            .unwrap_err();
        assert!(err.to_string().contains("GITHUB_TOKEN"));
    }

    #[test]
    fn saml_connection_refused_errors() {
        let mut cfg = test_config_with_org("placeholder");
        cfg.insert(
            "GITHUB_API_URL".to_string(),
            "http://127.0.0.1:1".to_string(),
        );
        let result = SamlSsoObserver.observe(&cfg);
        assert!(result.is_err());
    }

    #[test]
    fn saml_evidence_types() {
        assert_eq!(SamlSsoObserver.evidence_types(), &[1003]);
    }

    #[test]
    fn saml_credential_requirements() {
        let reqs = SamlSsoObserver.credential_requirements();
        assert_eq!(reqs.len(), 2);
        assert!(reqs.iter().any(|r| r.name == "GITHUB_TOKEN" && r.required));
        assert!(reqs.iter().any(|r| r.name == "GITHUB_ORG" && r.required));
    }

    #[test]
    fn metadata_complete() {
        use crate::module::Module;
        let obs = SamlSsoObserver;
        assert_eq!(obs.id(), "github.saml_sso");
        assert!(!obs.name().is_empty());
        assert_eq!(obs.version(), "0.1.0");
        assert_eq!(obs.source_system(), "github");
        assert!(!obs.evidence_types().is_empty());
        let creds = obs.credential_requirements();
        assert!(!creds.is_empty());
    }
}
