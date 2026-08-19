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

// ─── NetworkZonesObserver ─────────────────────────────────────────────────────

/// Queries Okta network zones to verify IP allowlisting and blocklist configuration.
///
/// Controls:
///   - OKTA-2.1: At least one POLICY zone must exist (IP allowlisting configured).
///   - OKTA-2.3: At least one BLOCKLIST zone must exist (threat IP blocking configured).
///
/// Required config: `OKTA_API_TOKEN`, `OKTA_DOMAIN`.
/// Optional: `OKTA_BASE_URL` (test override — defaults to `https://{OKTA_DOMAIN}`).
pub struct NetworkZonesObserver;

impl Module for NetworkZonesObserver {
    fn id(&self) -> &str {
        "okta.network_zones"
    }
    fn name(&self) -> &str {
        "Okta Network Zones Observer"
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
                description: "Okta API token with read access to network zones".to_string(),
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

impl Observer for NetworkZonesObserver {
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
        let path = "/api/v1/zones";
        let endpoint = format!("{}{}", base_url.trim_end_matches('/'), path);

        let (body, status) = okta_get(token, &base_url, path)?;

        if status != 200 {
            return Err(anyhow!(
                "Okta API returned status {} querying network zones",
                status
            ));
        }

        let zones = body
            .as_array()
            .ok_or_else(|| anyhow!("expected JSON array from Okta network zones endpoint"))?;

        let mut policy_zone_count = 0usize;
        let mut blocklist_zone_count = 0usize;
        let mut observables: Vec<Observable> = Vec::new();

        for zone in zones {
            let zone_type = zone.get("type").and_then(|v| v.as_str()).unwrap_or("");
            let usage = zone.get("usage").and_then(|v| v.as_str()).unwrap_or("");
            let zone_id = zone.get("id").and_then(|v| v.as_str()).unwrap_or("unknown");

            observables.push(Observable {
                obs_type: "resource".to_string(),
                value: format!("zone:{}", zone_id),
                name: String::new(),
            });

            // OKTA-2.1: IP POLICY zones indicate allowlisting is configured
            if zone_type == "IP" && usage == "POLICY" {
                policy_zone_count += 1;
            }

            // OKTA-2.3: IP BLOCKLIST zones or DYNAMIC zones with threat intel
            if (zone_type == "IP" && usage == "BLOCKLIST") || zone_type == "DYNAMIC" {
                blocklist_zone_count += 1;
            }
        }

        // Count observable for total zones
        observables.push(Observable {
            obs_type: "count".to_string(),
            value: zones.len().to_string(),
            name: "network_zones".to_string(),
        });

        let has_policy_zone = policy_zone_count > 0;
        let has_blocklist_zone = blocklist_zone_count > 0;

        let mut findings: Vec<Finding> = Vec::new();

        if !has_policy_zone {
            findings.push(Finding {
                title: "No IP Allowlist Policy Zone Configured".to_string(),
                description: "OKTA-2.1 requires at least one POLICY-usage network zone to enforce \
                     IP allowlisting. No such zone was found."
                    .to_string(),
                severity_id: 3,
            });
        }

        if !has_blocklist_zone {
            findings.push(Finding {
                title: "No Blocklist or Threat Intelligence Zone Configured".to_string(),
                description:
                    "OKTA-2.3 requires at least one BLOCKLIST-usage or DYNAMIC (threat intel) \
                     network zone to block malicious IPs. No such zone was found."
                        .to_string(),
                severity_id: 3,
            });
        }

        let (status_id, status_text) = if has_policy_zone && has_blocklist_zone {
            if findings.is_empty() {
                findings.push(Finding {
                    title: "Network Zones Compliant".to_string(),
                    description: format!(
                        "Found {} POLICY zone(s) and {} BLOCKLIST/DYNAMIC zone(s); \
                         both OKTA-2.1 and OKTA-2.3 controls are satisfied.",
                        policy_zone_count, blocklist_zone_count
                    ),
                    severity_id: 0,
                });
            }
            (
                StatusId::Effective,
                format!(
                    "IP allowlisting ({} policy zones) and blocklisting ({} blocklist zones) \
                     are both configured",
                    policy_zone_count, blocklist_zone_count
                ),
            )
        } else {
            (
                StatusId::Ineffective,
                format!(
                    "Network zone controls incomplete: {} POLICY zone(s), {} BLOCKLIST zone(s)",
                    policy_zone_count, blocklist_zone_count
                ),
            )
        };

        let raw_data = json!({
            "total_zones": zones.len(),
            "policy_zones": policy_zone_count,
            "blocklist_zones": blocklist_zone_count,
        });

        Ok(vec![Evidence {
            schema_version: EVIDENCE_SCHEMA_VERSION.to_string(),
            connected_account: None,
            population: None,
            evaluation: None,
            id: Uuid::new_v4(),
            control_id: "OKTA-2.1".to_string(),
            class_uid: 1001,
            category_uid: 1,
            activity_id: 1,
            time: now,
            confidence_level: ConfidenceLevel::PassiveObservation,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "okta.network_zones".to_string(),
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

    const POLICY_AND_BLOCKLIST_ZONES: &str = r#"[
        {
            "id": "zone_policy_1",
            "name": "Corporate IP Allowlist",
            "type": "IP",
            "usage": "POLICY",
            "status": "ACTIVE"
        },
        {
            "id": "zone_block_1",
            "name": "Threat IP Blocklist",
            "type": "IP",
            "usage": "BLOCKLIST",
            "status": "ACTIVE"
        }
    ]"#;

    const NO_ZONES: &str = "[]";

    const ONLY_POLICY_ZONES: &str = r#"[
        {
            "id": "zone_policy_1",
            "name": "Corporate IP Allowlist",
            "type": "IP",
            "usage": "POLICY",
            "status": "ACTIVE"
        }
    ]"#;

    #[test]
    fn policy_and_blocklist_zones_is_effective() {
        let srv = mock_server(200, POLICY_AND_BLOCKLIST_ZONES);
        let ev = &NetworkZonesObserver.observe(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert_eq!(ev.control_id, "OKTA-2.1");
        let raw = &ev.raw_data;
        assert_eq!(raw["total_zones"], 2);
        assert_eq!(raw["policy_zones"], 1);
        assert_eq!(raw["blocklist_zones"], 1);
    }

    #[test]
    fn no_zones_is_ineffective_with_findings() {
        let srv = mock_server(200, NO_ZONES);
        let ev = &NetworkZonesObserver.observe(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        let raw = &ev.raw_data;
        assert_eq!(raw["total_zones"], 0);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "No IP Allowlist Policy Zone Configured"));
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "No Blocklist or Threat Intelligence Zone Configured"));
    }

    #[test]
    fn only_policy_zones_no_blocklist_is_ineffective() {
        let srv = mock_server(200, ONLY_POLICY_ZONES);
        let ev = &NetworkZonesObserver.observe(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert!(ev
            .findings
            .iter()
            .any(|f| f.title == "No Blocklist or Threat Intelligence Zone Configured"));
        // Should NOT have a finding about missing policy zone
        assert!(!ev
            .findings
            .iter()
            .any(|f| f.title == "No IP Allowlist Policy Zone Configured"));
    }
}
