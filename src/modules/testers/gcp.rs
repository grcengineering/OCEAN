use std::collections::HashMap;

use anyhow::{anyhow, Result};
use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

use crate::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId,
    TranscriptRecorder,
};
use crate::module::{
    tester::Tester, CredentialReq, EnvironmentScope, Module, SafetyClassification,
};

// ─── Constants ────────────────────────────────────────────────────────────────

const DEFAULT_STORAGE_ENDPOINT: &str = "https://storage.googleapis.com";

// ─── GcpPublicBucketTester ───────────────────────────────────────────────────

/// Verifies that a GCP Cloud Storage bucket is not publicly accessible by
/// performing an unauthenticated HTTP GET. A 403/401 response means access
/// is blocked (effective); a 200 means the bucket is publicly accessible
/// (ineffective).
///
/// Required config: `GCP_TEST_BUCKET` (bucket name).
/// Optional: `GCP_STORAGE_ENDPOINT` (test override).
pub struct GcpPublicBucketTester;

impl Module for GcpPublicBucketTester {
    fn id(&self) -> &str {
        "gcp.public_bucket"
    }
    fn name(&self) -> &str {
        "GCP Public Bucket Tester"
    }
    fn version(&self) -> &str {
        "0.1.0"
    }
    fn source_system(&self) -> &str {
        "gcp"
    }
    fn evidence_types(&self) -> &[i32] {
        &[1002]
    }

    fn credential_requirements(&self) -> Vec<CredentialReq> {
        vec![CredentialReq {
            name: "GCP_TEST_BUCKET".to_string(),
            cred_type: "config".to_string(),
            description: "GCS bucket name to test for public access".to_string(),
            required: true,
        }]
    }
}

impl Tester for GcpPublicBucketTester {
    fn safety_class(&self) -> SafetyClassification {
        SafetyClassification::Safe
    }
    fn environment_scope(&self) -> EnvironmentScope {
        EnvironmentScope::Production
    }

    fn pre_flight_checks(&self) -> Vec<String> {
        vec!["verify test bucket name configured".to_string()]
    }

    fn cleanup_procedures(&self) -> Vec<String> {
        vec![] // Safe read-only test — no cleanup needed.
    }

    fn test(&self, config: &HashMap<String, String>) -> Result<Vec<Evidence>> {
        let bucket_name = config.get("GCP_TEST_BUCKET").ok_or_else(|| {
            anyhow!("GCP_TEST_BUCKET is required: specify the GCS bucket name to test")
        })?;

        let storage_endpoint = config
            .get("GCP_STORAGE_ENDPOINT")
            .map(|s| s.as_str())
            .unwrap_or(DEFAULT_STORAGE_ENDPOINT);

        let bucket_url = format!(
            "{}/storage/v1/b/{}/o",
            storage_endpoint.trim_end_matches('/'),
            bucket_name
        );

        let now = Utc::now();
        let mut recorder = TranscriptRecorder::new();
        let safety_class = "safe".to_string();

        recorder.record_action(
            "pre-flight: verify test bucket name configured",
            Some(json!({ "bucket_name": bucket_name })),
        );
        recorder.record_observation("test bucket name is configured", true);

        recorder.record_action(
            "attempt unauthenticated HTTP GET to GCS bucket listing",
            Some(json!({
                "method": "GET",
                "url": &bucket_url,
                "auth": "none (anonymous)"
            })),
        );

        // Perform unauthenticated GET to list bucket objects.
        let resp = ureq::get(&bucket_url).call();

        let (status_id, status_text, findings, test_result, http_status) = match resp {
            Err(ureq::Error::Status(code, _)) => {
                classify_response(code, bucket_name, &mut recorder)
            }
            Ok(r) => {
                let code = r.status();
                classify_response(code, bucket_name, &mut recorder)
            }
            Err(e) => {
                recorder.record_observation(format!("request failed with error: {}", e), false);
                let transcript = recorder.finalize();
                let raw = json!({
                    "test_scenario": "gcs_public_access_check",
                    "target_bucket": bucket_name,
                    "test_result": "error",
                    "error": e.to_string(),
                });
                return Ok(vec![Evidence {
                    id: Uuid::new_v4(),
                    control_id: "gcs.public_access".to_string(),
                    class_uid: 1002,
                    category_uid: 3,
                    activity_id: 2,
                    time: now,
                    confidence_level: ConfidenceLevel::ActiveVerification,
                    metadata: Metadata {
                        module: ModuleInfo {
                            name: "gcp.public_bucket".to_string(),
                            version: "0.1.0".to_string(),
                            module_type: "tester".to_string(),
                        },
                        source: SourceInfo {
                            system: "gcp".to_string(),
                            api_version: "v1".to_string(),
                            endpoint: bucket_url,
                        },
                        original_time: None,
                        processed_time: now,
                        safety_classification: Some(safety_class),
                    },
                    observables: vec![Observable {
                        obs_type: "resource".to_string(),
                        value: bucket_name.clone(),
                        name: String::new(),
                    }],
                    status_id: StatusId::Unknown,
                    status: format!("Could not reach bucket: {}", e),
                    raw_data: raw,
                    findings: vec![Finding {
                        title: "GCS Public Access Check Failed".to_string(),
                        description: format!(
                            "Could not connect to bucket {}: {}",
                            bucket_name, e
                        ),
                        severity_id: 1,
                    }],
                    test_transcript: Some(transcript),
                    enrichments: vec![],
                }]);
            }
        };

        recorder.record_cleanup("no cleanup required (safe read-only test)", true);
        let transcript = recorder.finalize();

        let raw_data = json!({
            "test_scenario": "gcs_public_access_check",
            "target_bucket": bucket_name,
            "test_result": test_result,
            "http_status": http_status,
        });

        Ok(vec![Evidence {
            id: Uuid::new_v4(),
            control_id: "gcs.public_access".to_string(),
            class_uid: 1002,
            category_uid: 3,
            activity_id: 2,
            time: now,
            confidence_level: ConfidenceLevel::ActiveVerification,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "gcp.public_bucket".to_string(),
                    version: "0.1.0".to_string(),
                    module_type: "tester".to_string(),
                },
                source: SourceInfo {
                    system: "gcp".to_string(),
                    api_version: "v1".to_string(),
                    endpoint: bucket_url,
                },
                original_time: None,
                processed_time: now,
                safety_classification: Some(safety_class),
            },
            observables: vec![Observable {
                obs_type: "resource".to_string(),
                value: bucket_name.clone(),
                name: String::new(),
            }],
            status_id,
            status: status_text,
            raw_data,
            findings,
            test_transcript: Some(transcript),
            enrichments: vec![],
        }])
    }
}

/// Classify an HTTP response code into evidence status.
fn classify_response(
    code: u16,
    bucket_name: &str,
    recorder: &mut TranscriptRecorder,
) -> (StatusId, String, Vec<Finding>, String, u16) {
    match code {
        401 | 403 | 404 => {
            recorder.record_observation(
                format!(
                    "unauthenticated request returned HTTP {} (access denied)",
                    code
                ),
                true,
            );
            (
                StatusId::Effective,
                format!("GCS bucket access blocked with HTTP {}", code),
                vec![Finding {
                    title: "GCS Public Access Blocked".to_string(),
                    description: format!(
                        "Unauthenticated GET to bucket {} returned HTTP {}, confirming public access is denied",
                        bucket_name, code
                    ),
                    severity_id: 0,
                }],
                format!("blocked_{}", code),
                code,
            )
        }
        200 => {
            recorder.record_observation(
                "unauthenticated request returned HTTP 200 (publicly accessible)",
                false,
            );
            (
                StatusId::Ineffective,
                "GCS bucket is publicly accessible".to_string(),
                vec![Finding {
                    title: "GCS Bucket Publicly Accessible".to_string(),
                    description: format!(
                        "Unauthenticated GET to bucket {} returned HTTP 200, indicating the bucket is publicly accessible",
                        bucket_name
                    ),
                    severity_id: 4,
                }],
                "allowed".to_string(),
                200,
            )
        }
        other => {
            recorder.record_observation(
                format!(
                    "unauthenticated request returned unexpected HTTP {}",
                    other
                ),
                false,
            );
            (
                StatusId::Unknown,
                format!("GCS bucket returned unexpected HTTP {}", other),
                vec![Finding {
                    title: "Unexpected GCS Response".to_string(),
                    description: format!(
                        "Unauthenticated GET to bucket {} returned HTTP {} which could not be classified",
                        bucket_name, other
                    ),
                    severity_id: 2,
                }],
                format!("unexpected_http_{}", other),
                other,
            )
        }
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
                    "HTTP/1.1 {status} OK\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
                    len = body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });

        format!("http://127.0.0.1:{}", addr.port())
    }

    fn base_config(endpoint: &str) -> HashMap<String, String> {
        HashMap::from([
            ("GCP_TEST_BUCKET".to_string(), "my-test-bucket".to_string()),
            ("GCP_STORAGE_ENDPOINT".to_string(), endpoint.to_string()),
        ])
    }

    // ── Metadata ─────────────────────────────────────────────────────────────

    #[test]
    fn gcp_tester_id() {
        assert_eq!(GcpPublicBucketTester.id(), "gcp.public_bucket");
    }

    #[test]
    fn gcp_tester_name() {
        assert_eq!(GcpPublicBucketTester.name(), "GCP Public Bucket Tester");
    }

    #[test]
    fn gcp_tester_version() {
        assert_eq!(GcpPublicBucketTester.version(), "0.1.0");
    }

    #[test]
    fn gcp_tester_source_system() {
        assert_eq!(GcpPublicBucketTester.source_system(), "gcp");
    }

    #[test]
    fn gcp_tester_evidence_types() {
        assert_eq!(GcpPublicBucketTester.evidence_types(), &[1002]);
    }

    #[test]
    fn gcp_tester_credential_requirements() {
        let reqs = GcpPublicBucketTester.credential_requirements();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].name, "GCP_TEST_BUCKET");
        assert!(reqs[0].required);
    }

    #[test]
    fn gcp_tester_safety_class() {
        assert_eq!(
            GcpPublicBucketTester.safety_class(),
            SafetyClassification::Safe
        );
    }

    #[test]
    fn gcp_tester_environment_scope() {
        assert_eq!(
            GcpPublicBucketTester.environment_scope(),
            EnvironmentScope::Production
        );
    }

    #[test]
    fn gcp_tester_pre_flight_nonempty() {
        assert!(!GcpPublicBucketTester.pre_flight_checks().is_empty());
    }

    #[test]
    fn gcp_tester_cleanup_empty() {
        assert!(GcpPublicBucketTester.cleanup_procedures().is_empty());
    }

    #[test]
    fn gcp_tester_missing_bucket_errors() {
        let err = GcpPublicBucketTester.test(&HashMap::new()).unwrap_err();
        assert!(err.to_string().contains("GCP_TEST_BUCKET"));
    }

    // ── HTTP integration ─────────────────────────────────────────────────────

    #[test]
    fn gcp_tester_403_means_access_blocked_effective() {
        let srv = mock_server(403, r#"{"error":{"code":403}}"#);
        let ev = &GcpPublicBucketTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert_eq!(ev.findings[0].title, "GCS Public Access Blocked");
        assert_eq!(ev.class_uid, 1002);
        assert_eq!(ev.control_id, "gcs.public_access");
        assert!(ev.test_transcript.is_some());
    }

    #[test]
    fn gcp_tester_401_means_access_blocked_effective() {
        let srv = mock_server(401, r#"{"error":{"code":401}}"#);
        let ev = &GcpPublicBucketTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert_eq!(ev.findings[0].title, "GCS Public Access Blocked");
    }

    #[test]
    fn gcp_tester_404_means_access_blocked_effective() {
        let srv = mock_server(404, r#"{"error":{"code":404}}"#);
        let ev = &GcpPublicBucketTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
    }

    #[test]
    fn gcp_tester_200_means_publicly_accessible_ineffective() {
        let srv = mock_server(200, r#"{"items":[]}"#);
        let ev = &GcpPublicBucketTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert_eq!(ev.findings[0].title, "GCS Bucket Publicly Accessible");
        assert_eq!(ev.findings[0].severity_id, 4);
    }

    #[test]
    fn gcp_tester_500_means_unknown() {
        let srv = mock_server(500, "Internal Server Error");
        let ev = &GcpPublicBucketTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Unknown);
        assert_eq!(ev.findings[0].title, "Unexpected GCS Response");
    }

    #[test]
    fn gcp_tester_has_transcript() {
        let srv = mock_server(403, r#"{"error":{"code":403}}"#);
        let ev = &GcpPublicBucketTester.test(&base_config(&srv)).unwrap()[0];
        let t = ev.test_transcript.as_ref().unwrap();
        assert!(!t.actions_attempted.is_empty());
        assert!(!t.observations.is_empty());
    }

    #[test]
    fn gcp_tester_raw_data_has_expected_keys() {
        let srv = mock_server(403, "Denied");
        let ev = &GcpPublicBucketTester.test(&base_config(&srv)).unwrap()[0];
        assert!(ev.raw_data.get("test_scenario").is_some());
        assert!(ev.raw_data.get("target_bucket").is_some());
        assert!(ev.raw_data.get("test_result").is_some());
    }

    #[test]
    fn gcp_tester_safety_classification_in_metadata() {
        let srv = mock_server(403, "Denied");
        let ev = &GcpPublicBucketTester.test(&base_config(&srv)).unwrap()[0];
        assert_eq!(ev.metadata.safety_classification.as_deref(), Some("safe"));
    }

    #[test]
    fn gcp_tester_unique_ids() {
        let srv1 = mock_server(403, "D");
        let srv2 = mock_server(403, "D");
        let id1 = GcpPublicBucketTester
            .test(&base_config(&srv1))
            .unwrap()[0]
            .id;
        let id2 = GcpPublicBucketTester
            .test(&base_config(&srv2))
            .unwrap()[0]
            .id;
        assert_ne!(id1, id2);
    }
}
