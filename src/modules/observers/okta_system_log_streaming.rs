use std::collections::HashMap;

use anyhow::{anyhow, Result};
use chrono::Utc;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId,
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

// ─── SystemLogStreamingObserver ───────────────────────────────────────────────

/// Queries Okta log stream configurations and validates at least one is active.
///
/// Controls: OKTA-5.1 (log streaming must be configured)
/// Required config: `OKTA_API_TOKEN`, `OKTA_DOMAIN`.
/// Optional: `OKTA_BASE_URL` (test override — defaults to `https://{OKTA_DOMAIN}`).
pub struct SystemLogStreamingObserver;

impl Module for SystemLogStreamingObserver {
    fn id(&self) -> &str {
        "okta.system_log_streaming"
    }
    fn name(&self) -> &str {
        "Okta System Log Streaming Observer"
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
                description: "Okta API token with read access to log stream configurations"
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

impl Observer for SystemLogStreamingObserver {
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
        let path = "/api/v1/logStreams";
        let endpoint = format!("{}{}", base_url.trim_end_matches('/'), path);

        let (body, status) = okta_get(token, &base_url, path)?;

        if status != 200 {
            return Err(anyhow!(
                "Okta API returned status {} querying log streams",
                status
            ));
        }

        let streams = body
            .as_array()
            .ok_or_else(|| anyhow!("expected JSON array from Okta logStreams endpoint"))?;

        let stream_count = streams.len();
        let active_streams: Vec<&Value> = streams
            .iter()
            .filter(|s| {
                s.get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("INACTIVE")
                    == "ACTIVE"
            })
            .collect();
        let active_count = active_streams.len();

        let stream_types: Vec<String> = streams
            .iter()
            .filter_map(|s| {
                s.get("type")
                    .and_then(|v| v.as_str())
                    .map(|t| t.to_string())
            })
            .collect();

        let mut findings: Vec<Finding> = Vec::new();

        let (status_id, status_text) = if active_count > 0 {
            (
                StatusId::Effective,
                format!(
                    "{} active log stream(s) configured out of {} total",
                    active_count, stream_count
                ),
            )
        } else if stream_count == 0 {
            findings.push(Finding {
                title: "No Log Streams Configured".to_string(),
                description:
                    "No Okta log streams are configured. At least one active log stream is \
                     required to satisfy OKTA-5.1."
                        .to_string(),
                severity_id: 4,
            });
            (
                StatusId::Ineffective,
                "No log streams are configured".to_string(),
            )
        } else {
            findings.push(Finding {
                title: "All Log Streams Inactive".to_string(),
                description: format!(
                    "{} log stream(s) exist but none are ACTIVE. At least one active log \
                     stream is required to satisfy OKTA-5.1.",
                    stream_count
                ),
                severity_id: 3,
            });
            (
                StatusId::Ineffective,
                format!(
                    "{} log stream(s) configured but all are inactive",
                    stream_count
                ),
            )
        };

        let observables: Vec<Observable> = vec![Observable {
            obs_type: "count".to_string(),
            value: active_count.to_string(),
            name: "active_log_streams".to_string(),
        }];

        let raw_data = json!({
            "stream_count": stream_count,
            "active_streams": active_count,
            "stream_types": stream_types,
        });

        Ok(vec![Evidence {
            id: Uuid::new_v4(),
            control_id: "OKTA-5.1".to_string(),
            class_uid: 1001,
            category_uid: 1,
            activity_id: 1,
            time: now,
            confidence_level: ConfidenceLevel::PassiveObservation,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "okta.system_log_streaming".to_string(),
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
    fn okta_system_log_streaming_active_stream_is_effective() {
        let body = r#"[{"id":"ls1","type":"aws_eventbridge","status":"ACTIVE"}]"#;
        let url = mock_server(200, body);
        let cfg = base_config(&url);
        let ev = SystemLogStreamingObserver.observe(&cfg).unwrap();
        assert_eq!(ev[0].status_id, StatusId::Effective);
        assert!(ev[0].findings.is_empty());
        let obs_val = &ev[0].observables[0].value;
        assert_eq!(obs_val, "1");
    }

    #[test]
    fn okta_system_log_streaming_no_streams_is_ineffective_critical() {
        let body = r#"[]"#;
        let url = mock_server(200, body);
        let cfg = base_config(&url);
        let ev = SystemLogStreamingObserver.observe(&cfg).unwrap();
        assert_eq!(ev[0].status_id, StatusId::Ineffective);
        assert!(!ev[0].findings.is_empty());
        assert_eq!(ev[0].findings[0].severity_id, 4);
    }

    #[test]
    fn okta_system_log_streaming_all_inactive_is_ineffective() {
        let body =
            r#"[{"id":"ls1","type":"splunk_cloud_logstreaming","status":"INACTIVE"},{"id":"ls2","type":"aws_eventbridge","status":"INACTIVE"}]"#;
        let url = mock_server(200, body);
        let cfg = base_config(&url);
        let ev = SystemLogStreamingObserver.observe(&cfg).unwrap();
        assert_eq!(ev[0].status_id, StatusId::Ineffective);
        assert!(
            ev[0]
                .findings
                .iter()
                .any(|f| f.title.contains("All Log Streams Inactive"))
        );
    }
}
