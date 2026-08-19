use std::collections::HashMap;

use anyhow::{anyhow, Result};
use chrono::Utc;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId,
    EVIDENCE_SCHEMA_VERSION,
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

// ─── ThreatInsightObserver ────────────────────────────────────────────────────

/// Queries Okta ThreatInsight configuration and validates that blocking is enabled.
///
/// Controls: OKTA-5.2 (ThreatInsight must be enabled and blocking)
/// Required config: `OKTA_API_TOKEN`, `OKTA_DOMAIN`.
/// Optional: `OKTA_BASE_URL` (test override — defaults to `https://{OKTA_DOMAIN}`).
pub struct ThreatInsightObserver;

impl Module for ThreatInsightObserver {
    fn id(&self) -> &str {
        "okta.threat_insight"
    }
    fn name(&self) -> &str {
        "Okta ThreatInsight Configuration Observer"
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
                description: "Okta API token with read access to threat insight configuration"
                    .to_string(),
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

impl Observer for ThreatInsightObserver {
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
        let path = "/api/v1/threats/configuration";
        let endpoint = format!("{}{}", base_url.trim_end_matches('/'), path);

        let (body, status) = okta_get(token, &base_url, path)?;

        if status != 200 {
            return Err(anyhow!(
                "Okta API returned status {} querying ThreatInsight configuration",
                status
            ));
        }

        let action = body
            .get("action")
            .and_then(|v| v.as_str())
            .unwrap_or("none");

        let exclude_zones = body
            .get("excludeZones")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0);

        let mut findings: Vec<Finding> = Vec::new();

        let (status_id, status_text) = match action {
            "block" => (
                StatusId::Effective,
                "ThreatInsight is enabled and configured to block threats".to_string(),
            ),
            "audit" => {
                findings.push(Finding {
                    title: "ThreatInsight in Audit Mode Only".to_string(),
                    description:
                        "ThreatInsight action is 'audit' — threats are logged but not blocked. \
                         Set action to 'block' to satisfy OKTA-5.2."
                            .to_string(),
                    severity_id: 3,
                });
                (
                    StatusId::Ineffective,
                    "ThreatInsight is in audit-only mode; blocking is not active".to_string(),
                )
            }
            _ => {
                findings.push(Finding {
                    title: "ThreatInsight Disabled or Ineffective".to_string(),
                    description: format!(
                        "ThreatInsight action is {:?}. ThreatInsight must be set to 'block' \
                         to satisfy OKTA-5.2.",
                        action
                    ),
                    severity_id: 4,
                });
                (
                    StatusId::Ineffective,
                    format!(
                        "ThreatInsight action is {:?}; blocking is not active",
                        action
                    ),
                )
            }
        };

        if exclude_zones > 2 {
            findings.push(Finding {
                title: "Excessive ThreatInsight Zone Exclusions".to_string(),
                description: format!(
                    "{} zones are excluded from ThreatInsight. Large exclusion lists reduce \
                     the effectiveness of threat blocking.",
                    exclude_zones
                ),
                severity_id: 2,
            });
        }

        let observables: Vec<Observable> = vec![Observable {
            obs_type: "config".to_string(),
            value: action.to_string(),
            name: "threat_insight_action".to_string(),
        }];

        let raw_data = body.clone();

        Ok(vec![Evidence {
            schema_version: EVIDENCE_SCHEMA_VERSION.to_string(),
            connected_account: None,
            population: None,
            evaluation: None,
            id: Uuid::new_v4(),
            control_id: "OKTA-5.2".to_string(),
            class_uid: 1001,
            category_uid: 1,
            activity_id: 1,
            time: now,
            confidence_level: ConfidenceLevel::PassiveObservation,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "okta.threat_insight".to_string(),
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

    #[test]
    fn okta_threat_insight_block_is_effective() {
        let body = r#"{"action":"block","excludeZones":[]}"#;
        let url = mock_server(200, body);
        let cfg = base_config(&url);
        let ev = ThreatInsightObserver.observe(&cfg).unwrap();
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].status_id, StatusId::Effective);
        assert!(ev[0].findings.is_empty());
    }

    #[test]
    fn okta_threat_insight_none_is_ineffective_with_finding() {
        let body = r#"{"action":"none","excludeZones":[]}"#;
        let url = mock_server(200, body);
        let cfg = base_config(&url);
        let ev = ThreatInsightObserver.observe(&cfg).unwrap();
        assert_eq!(ev[0].status_id, StatusId::Ineffective);
        assert!(!ev[0].findings.is_empty());
        let titles: Vec<&str> = ev[0].findings.iter().map(|f| f.title.as_str()).collect();
        assert!(
            titles
                .iter()
                .any(|t| t.contains("Disabled") || t.contains("Ineffective")),
            "expected a ThreatInsight disabled finding, got: {:?}",
            titles
        );
    }

    #[test]
    fn okta_threat_insight_audit_is_ineffective_with_finding() {
        let body = r#"{"action":"audit","excludeZones":[]}"#;
        let url = mock_server(200, body);
        let cfg = base_config(&url);
        let ev = ThreatInsightObserver.observe(&cfg).unwrap();
        assert_eq!(ev[0].status_id, StatusId::Ineffective);
        assert!(
            ev[0]
                .findings
                .iter()
                .any(|f| f.title.contains("Audit Mode")),
            "expected audit-mode finding"
        );
    }
}
