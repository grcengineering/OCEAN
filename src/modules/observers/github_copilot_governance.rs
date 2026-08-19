use std::collections::HashMap;

use anyhow::{anyhow, Result};
use chrono::Utc;
use uuid::Uuid;

use crate::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId,
};
use crate::module::{observer::Observer, CredentialReq, Module};
use crate::modules::github_common::{github_get, DEFAULT_GITHUB_API};

// ─── CopilotGovernanceObserver ────────────────────────────────────────────────

/// Checks whether GitHub Copilot access is governed via seat assignment rather
/// than granted to all organization members (GH-7.1). Reads
/// `seat_management_setting` from the Copilot billing endpoint. Returns unknown
/// if Copilot is not enabled for the organization.
///
/// Required config: `GITHUB_TOKEN`, `GITHUB_ORG`.
/// Optional: `GITHUB_API_URL` (test override).
pub struct CopilotGovernanceObserver;

impl Module for CopilotGovernanceObserver {
    fn id(&self) -> &str {
        "github.copilot_governance"
    }
    fn name(&self) -> &str {
        "GitHub Copilot Governance Observer"
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
                description: "GitHub PAT with manage_billing:copilot scope".to_string(),
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

impl Observer for CopilotGovernanceObserver {
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
        let path = format!("/orgs/{}/copilot/billing", org);
        let endpoint = format!("{}{}", base_url.trim_end_matches('/'), path);

        let (body, status) = github_get(token, base_url, &path)?;

        let (status_id, findings) = match status {
            200 => {
                let seat_setting = body
                    .get("seat_management_setting")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");

                if seat_setting == "assign_selected" {
                    (
                        StatusId::Effective,
                        vec![Finding {
                            title: "Copilot Access Governed".to_string(),
                            description: format!(
                                "Organization {} assigns Copilot seats to selected members only. \
                                 Access is governed and not granted org-wide (GH-7.1).",
                                org
                            ),
                            severity_id: 0,
                        }],
                    )
                } else if seat_setting == "assign_all" {
                    (
                        StatusId::Ineffective,
                        vec![Finding {
                            title: "Copilot Access Ungoverned".to_string(),
                            description: format!(
                                "Organization {} grants Copilot access to all members \
                                 (seat_management_setting=assign_all). Restrict Copilot access \
                                 to selected users to satisfy GH-7.1.",
                                org
                            ),
                            severity_id: 2,
                        }],
                    )
                } else {
                    (
                        StatusId::Unknown,
                        vec![Finding {
                            title: "Copilot Seat Setting Unrecognized".to_string(),
                            description: format!(
                                "Organization {} has an unrecognized Copilot seat management \
                                 setting: '{}'. Review Copilot billing configuration (GH-7.1).",
                                org, seat_setting
                            ),
                            severity_id: 1,
                        }],
                    )
                }
            }
            404 => (
                StatusId::Unknown,
                vec![Finding {
                    title: "Copilot Not Enabled".to_string(),
                    description: format!(
                        "Organization {} does not have GitHub Copilot enabled (HTTP 404). \
                         No Copilot governance action required at this time (GH-7.1).",
                        org
                    ),
                    severity_id: 0,
                }],
            ),
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
                format!(
                    "Copilot access is governed by seat selection for organization {}",
                    org
                )
            }
            StatusId::Ineffective => {
                format!(
                    "Copilot access is ungoverned (assign_all) for organization {}",
                    org
                )
            }
            _ => format!("Copilot governance status unknown for organization {}", org),
        };

        Ok(vec![Evidence {
            id: Uuid::new_v4(),
            control_id: "GH-7.1".to_string(),
            class_uid: 1003,
            category_uid: 2,
            activity_id: 1,
            time: now,
            confidence_level: ConfidenceLevel::PassiveObservation,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "github.copilot_governance".to_string(),
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
                    value: format!("{}:copilot_billing", org),
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
            raw_data: body,
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
    fn assign_selected_is_effective() {
        let srv = mock_server(
            200,
            r#"{"seat_breakdown":{"total":10},"seat_management_setting":"assign_selected"}"#,
        );
        let ev = &CopilotGovernanceObserver
            .observe(&test_config_with_org(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "Copilot Access Governed"));
    }

    #[test]
    fn assign_all_is_ineffective_with_finding() {
        let srv = mock_server(
            200,
            r#"{"seat_breakdown":{"total":50},"seat_management_setting":"assign_all"}"#,
        );
        let ev = &CopilotGovernanceObserver
            .observe(&test_config_with_org(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "Copilot Access Ungoverned"));
    }

    #[test]
    fn copilot_404_is_unknown() {
        let srv = mock_server(404, r#"{"message":"Not Found"}"#);
        let ev = &CopilotGovernanceObserver
            .observe(&test_config_with_org(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Unknown);
        assert!(ev.findings.iter().any(|f| f.title == "Copilot Not Enabled"));
    }

    #[test]
    fn copilot_unrecognized_setting_is_unknown() {
        let srv = mock_server(200, r#"{"seat_management_setting":"disabled"}"#);
        let ev = &CopilotGovernanceObserver
            .observe(&test_config_with_org(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Unknown);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "Copilot Seat Setting Unrecognized"));
    }

    #[test]
    fn copilot_unexpected_status_returns_err() {
        let srv = mock_server(500, r#"{"message":"Internal Server Error"}"#);
        let result = CopilotGovernanceObserver.observe(&test_config_with_org(&srv));
        assert!(result.is_err());
    }

    #[test]
    fn copilot_evidence_types() {
        assert_eq!(CopilotGovernanceObserver.evidence_types(), &[1003]);
    }

    #[test]
    fn copilot_credential_requirements() {
        let reqs = CopilotGovernanceObserver.credential_requirements();
        assert_eq!(reqs.len(), 2);
        assert!(reqs.iter().any(|r| r.name == "GITHUB_TOKEN" && r.required));
        assert!(reqs.iter().any(|r| r.name == "GITHUB_ORG" && r.required));
    }

    #[test]
    fn copilot_missing_token_errors() {
        let err = CopilotGovernanceObserver
            .observe(&HashMap::from([(
                "GITHUB_ORG".to_string(),
                "org".to_string(),
            )]))
            .unwrap_err();
        assert!(err.to_string().contains("GITHUB_TOKEN"));
    }

    #[test]
    fn copilot_missing_org_errors() {
        let err = CopilotGovernanceObserver
            .observe(&HashMap::from([(
                "GITHUB_TOKEN".to_string(),
                "tok".to_string(),
            )]))
            .unwrap_err();
        assert!(err.to_string().contains("GITHUB_ORG"));
    }
}
