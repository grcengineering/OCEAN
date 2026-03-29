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

// ─── AuditLogStreamingObserver ───────────────────────────────────────────────

/// Checks whether audit log streaming is configured for the organization
/// (GH-8.1). Requires GitHub Enterprise Cloud (GHEC). Returns unknown if the
/// endpoint is unavailable due to plan limitations.
///
/// Required config: `GITHUB_TOKEN`, `GITHUB_ORG`.
/// Optional: `GITHUB_API_URL` (test override).
pub struct AuditLogStreamingObserver;

impl Module for AuditLogStreamingObserver {
    fn id(&self) -> &str {
        "github.audit_log_streaming"
    }
    fn name(&self) -> &str {
        "GitHub Audit Log Streaming Observer"
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
                description: "GitHub PAT with admin:org scope for reading audit log streams"
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

impl Observer for AuditLogStreamingObserver {
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
        let path = format!("/orgs/{}/audit-log/streams", org);
        let endpoint = format!("{}{}", base_url.trim_end_matches('/'), &path);

        let (body, status) = github_get(token, base_url, &path)?;

        let (status_id, raw_data, findings) = match status {
            200 => {
                let stream_count = body.as_array().map(|a| a.len()).unwrap_or(0);
                let raw = json!({ "stream_count": stream_count, "ghec_available": true });

                if stream_count >= 1 {
                    (
                        StatusId::Effective,
                        raw,
                        vec![Finding {
                            title: "Audit Log Streaming Active".to_string(),
                            description: format!(
                                "Organization {} has {} active audit log stream(s) configured, \
                                 satisfying continuous audit log export requirements (GH-8.1).",
                                org, stream_count
                            ),
                            severity_id: 0,
                        }],
                    )
                } else {
                    (
                        StatusId::Ineffective,
                        raw,
                        vec![Finding {
                            title: "Audit Log Streaming Not Configured".to_string(),
                            description: format!(
                                "Organization {} has no audit log streams configured. \
                                 Configure audit log streaming to satisfy GH-8.1.",
                                org
                            ),
                            severity_id: 2,
                        }],
                    )
                }
            }
            404 | 403 => {
                let raw = json!({ "stream_count": 0, "ghec_available": false });
                (
                    StatusId::Unknown,
                    raw,
                    vec![Finding {
                        title: "Audit Log Streaming Unavailable".to_string(),
                        description: format!(
                            "Organization {} returned HTTP {} for audit log streams. \
                             This endpoint requires GitHub Enterprise Cloud (GHEC). \
                             Upgrade to GHEC to enable audit log streaming (GH-8.1).",
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
                format!("Audit log streaming is active for organization {}", org)
            }
            StatusId::Ineffective => {
                format!("Audit log streaming is not configured for organization {}", org)
            }
            _ => format!(
                "Audit log streaming check unavailable for organization {} (GHEC required)",
                org
            ),
        };

        Ok(vec![Evidence {
            id: Uuid::new_v4(),
            control_id: "GH-8.1".to_string(),
            class_uid: 1003,
            category_uid: 2,
            activity_id: 1,
            time: now,
            confidence_level: ConfidenceLevel::PassiveObservation,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "github.audit_log_streaming".to_string(),
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
                    value: format!("{}:audit_log_streaming", org),
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
    fn one_stream_is_effective() {
        let srv = mock_server(
            200,
            r#"[{"id":1,"stream_type":"S3","enabled":true}]"#,
        );
        let ev = &AuditLogStreamingObserver
            .observe(&test_config_with_org(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert_eq!(ev.raw_data["stream_count"], 1);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "Audit Log Streaming Active"));
    }

    #[test]
    fn empty_streams_is_ineffective_with_finding() {
        let srv = mock_server(200, r#"[]"#);
        let ev = &AuditLogStreamingObserver
            .observe(&test_config_with_org(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "Audit Log Streaming Not Configured"));
    }

    #[test]
    fn audit_log_404_is_unknown_with_note() {
        let srv = mock_server(404, r#"{"message":"Not Found"}"#);
        let ev = &AuditLogStreamingObserver
            .observe(&test_config_with_org(&srv))
            .unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Unknown);
        assert_eq!(ev.raw_data["ghec_available"], false);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "Audit Log Streaming Unavailable"));
    }
}
