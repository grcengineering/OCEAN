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

// ─── S3PublicAccessTester ─────────────────────────────────────────────────────

/// Verifies that an S3 bucket is not publicly accessible by performing an
/// unauthenticated HTTP GET. A 403/404 response means access is blocked
/// (effective); a 200 means the bucket is publicly accessible (ineffective).
///
/// Required config: `AWS_TEST_BUCKET` (the full S3 URL to test).
/// Optional: Used directly as the URL — no AWS credentials needed.
pub struct S3PublicAccessTester;

impl Module for S3PublicAccessTester {
    fn id(&self) -> &str {
        "aws.s3_public_access"
    }
    fn name(&self) -> &str {
        "AWS S3 Public Access Tester"
    }
    fn version(&self) -> &str {
        "0.1.0"
    }
    fn source_system(&self) -> &str {
        "aws"
    }
    fn evidence_types(&self) -> &[i32] {
        &[1002]
    }

    fn credential_requirements(&self) -> Vec<CredentialReq> {
        vec![CredentialReq {
            name: "AWS_TEST_BUCKET".to_string(),
            cred_type: "config".to_string(),
            description: "S3 bucket URL to test for public access (e.g., https://my-bucket.s3.amazonaws.com/)".to_string(),
            required: true,
        }]
    }
}

impl Tester for S3PublicAccessTester {
    fn safety_class(&self) -> SafetyClassification {
        SafetyClassification::Safe
    }
    fn environment_scope(&self) -> EnvironmentScope {
        EnvironmentScope::Production
    }

    fn pre_flight_checks(&self) -> Vec<String> {
        vec!["verify test bucket URL configured".to_string()]
    }

    fn cleanup_procedures(&self) -> Vec<String> {
        vec![] // Safe read-only test — no cleanup needed.
    }

    fn test(&self, config: &HashMap<String, String>) -> Result<Vec<Evidence>> {
        let bucket_url = config.get("AWS_TEST_BUCKET").ok_or_else(|| {
            anyhow!("AWS_TEST_BUCKET is required: specify the S3 bucket URL to test")
        })?;

        let now = Utc::now();
        let mut recorder = TranscriptRecorder::new();
        let safety_class = "safe".to_string();

        recorder.record_action(
            "pre-flight: verify test bucket URL configured",
            Some(json!({ "bucket_url": bucket_url })),
        );
        recorder.record_observation("test bucket URL is configured", true);

        recorder.record_action(
            "attempt unauthenticated HTTP GET to S3 bucket",
            Some(json!({
                "method": "GET",
                "url": bucket_url,
                "auth": "none (anonymous)"
            })),
        );

        // Perform unauthenticated GET.
        let resp = ureq::get(bucket_url).call();

        let (status_id, status_text, findings, test_result, http_status) = match resp {
            Err(ureq::Error::Status(code, _)) => {
                match code {
                    403 | 404 => {
                        recorder.record_observation(
                            format!(
                                "unauthenticated request returned HTTP {} (access denied)",
                                code
                            ),
                            true,
                        );
                        recorder.record_cleanup("no cleanup required (safe read-only test)", true);
                        (
                            StatusId::Effective,
                            format!("S3 bucket access blocked with HTTP {}", code),
                            vec![Finding {
                                title: "S3 Public Access Blocked".to_string(),
                                description: format!(
                                    "Unauthenticated GET to {} returned HTTP {}, confirming public access is denied",
                                    bucket_url, code
                                ),
                                severity_id: 0,
                            }],
                            format!("blocked_{}", code),
                            code,
                        )
                    }
                    200 => {
                        // 200 via Status error arm — shouldn't happen but handle it
                        recorder.record_observation(
                            "unauthenticated request returned HTTP 200 (publicly accessible)",
                            false,
                        );
                        recorder.record_cleanup("no cleanup required (safe read-only test)", true);
                        (
                            StatusId::Ineffective,
                            "S3 bucket is publicly accessible".to_string(),
                            vec![Finding {
                                title: "S3 Bucket Publicly Accessible".to_string(),
                                description: format!(
                                    "Unauthenticated GET to {} returned HTTP 200, indicating the bucket is publicly accessible",
                                    bucket_url
                                ),
                                severity_id: 4,
                            }],
                            "allowed".to_string(),
                            200u16,
                        )
                    }
                    other => {
                        recorder.record_observation(
                            format!("unauthenticated request returned unexpected HTTP {}", other),
                            false,
                        );
                        recorder.record_cleanup("no cleanup required (safe read-only test)", true);
                        (
                            StatusId::Unknown,
                            format!("S3 bucket returned unexpected HTTP {}", other),
                            vec![Finding {
                                title: "Unexpected S3 Response".to_string(),
                                description: format!(
                                    "Unauthenticated GET to {} returned HTTP {} which could not be classified",
                                    bucket_url, other
                                ),
                                severity_id: 2,
                            }],
                            format!("unexpected_http_{}", other),
                            other,
                        )
                    }
                }
            }
            Ok(r) => {
                let code = r.status();
                if code == 403 || code == 404 {
                    recorder.record_observation(
                        format!(
                            "unauthenticated request returned HTTP {} (access denied)",
                            code
                        ),
                        true,
                    );
                    recorder.record_cleanup("no cleanup required (safe read-only test)", true);
                    (
                        StatusId::Effective,
                        format!("S3 bucket access blocked with HTTP {}", code),
                        vec![Finding {
                            title: "S3 Public Access Blocked".to_string(),
                            description: format!(
                                "Unauthenticated GET to {} returned HTTP {}, confirming public access is denied",
                                bucket_url, code
                            ),
                            severity_id: 0,
                        }],
                        format!("blocked_{}", code),
                        code,
                    )
                } else if code == 200 {
                    recorder.record_observation(
                        "unauthenticated request returned HTTP 200 (publicly accessible)",
                        false,
                    );
                    recorder.record_cleanup("no cleanup required (safe read-only test)", true);
                    (
                        StatusId::Ineffective,
                        "S3 bucket is publicly accessible".to_string(),
                        vec![Finding {
                            title: "S3 Bucket Publicly Accessible".to_string(),
                            description: format!(
                                "Unauthenticated GET to {} returned HTTP 200, indicating the bucket is publicly accessible",
                                bucket_url
                            ),
                            severity_id: 4,
                        }],
                        "allowed".to_string(),
                        code,
                    )
                } else {
                    recorder.record_observation(
                        format!("unauthenticated request returned unexpected HTTP {}", code),
                        false,
                    );
                    recorder.record_cleanup("no cleanup required (safe read-only test)", true);
                    (
                        StatusId::Unknown,
                        format!("S3 bucket returned unexpected HTTP {}", code),
                        vec![Finding {
                            title: "Unexpected S3 Response".to_string(),
                            description: format!(
                                "Unauthenticated GET to {} returned HTTP {} which could not be classified",
                                bucket_url, code
                            ),
                            severity_id: 2,
                        }],
                        format!("unexpected_http_{}", code),
                        code,
                    )
                }
            }
            Err(e) => {
                recorder.record_observation(format!("request failed with error: {}", e), false);
                let transcript = recorder.finalize();
                let raw = json!({
                    "test_scenario": "s3_public_access_check",
                    "target_bucket": bucket_url,
                    "test_result": "error",
                    "error": e.to_string(),
                });
                return Ok(vec![Evidence {
                    id: Uuid::new_v4(),
                    control_id: "s3.public_access".to_string(),
                    class_uid: 1002,
                    category_uid: 3,
                    activity_id: 2,
                    time: now,
                    confidence_level: ConfidenceLevel::ActiveVerification,
                    metadata: Metadata {
                        module: ModuleInfo {
                            name: "aws.s3_public_access".to_string(),
                            version: "0.1.0".to_string(),
                            module_type: "tester".to_string(),
                        },
                        source: SourceInfo {
                            system: "aws".to_string(),
                            api_version: "s3".to_string(),
                            endpoint: bucket_url.clone(),
                        },
                        original_time: None,
                        processed_time: now,
                        safety_classification: Some(safety_class),
                    },
                    observables: vec![Observable {
                        obs_type: "resource".to_string(),
                        value: bucket_url.clone(),
                        name: String::new(),
                    }],
                    status_id: StatusId::Unknown,
                    status: format!("Could not reach bucket: {}", e),
                    raw_data: raw,
                    findings: vec![Finding {
                        title: "S3 Public Access Check Failed".to_string(),
                        description: format!("Could not connect to {}: {}", bucket_url, e),
                        severity_id: 1,
                    }],
                    test_transcript: Some(transcript),
                    enrichments: vec![],
                }]);
            }
        };

        let transcript = recorder.finalize();
        let raw_data = json!({
            "test_scenario": "s3_public_access_check",
            "target_bucket": bucket_url,
            "test_result": test_result,
            "http_status": http_status,
        });

        Ok(vec![Evidence {
            id: Uuid::new_v4(),
            control_id: "s3.public_access".to_string(),
            class_uid: 1002,
            category_uid: 3,
            activity_id: 2,
            time: now,
            confidence_level: ConfidenceLevel::ActiveVerification,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "aws.s3_public_access".to_string(),
                    version: "0.1.0".to_string(),
                    module_type: "tester".to_string(),
                },
                source: SourceInfo {
                    system: "aws".to_string(),
                    api_version: "s3".to_string(),
                    endpoint: bucket_url.clone(),
                },
                original_time: None,
                processed_time: now,
                safety_classification: Some(safety_class),
            },
            observables: vec![Observable {
                obs_type: "resource".to_string(),
                value: bucket_url.clone(),
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

        format!("http://127.0.0.1:{}/", addr.port())
    }

    // ── Metadata ─────────────────────────────────────────────────────────────

    #[test]
    fn s3_tester_id() {
        assert_eq!(S3PublicAccessTester.id(), "aws.s3_public_access");
    }

    #[test]
    fn s3_tester_name() {
        assert_eq!(S3PublicAccessTester.name(), "AWS S3 Public Access Tester");
    }

    #[test]
    fn s3_tester_version() {
        assert_eq!(S3PublicAccessTester.version(), "0.1.0");
    }

    #[test]
    fn s3_tester_source_system() {
        assert_eq!(S3PublicAccessTester.source_system(), "aws");
    }

    #[test]
    fn s3_tester_evidence_types() {
        assert_eq!(S3PublicAccessTester.evidence_types(), &[1002]);
    }

    #[test]
    fn s3_tester_credential_requirements() {
        let reqs = S3PublicAccessTester.credential_requirements();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].name, "AWS_TEST_BUCKET");
        assert!(reqs[0].required);
    }

    #[test]
    fn s3_tester_safety_class() {
        assert_eq!(
            S3PublicAccessTester.safety_class(),
            SafetyClassification::Safe
        );
    }

    #[test]
    fn s3_tester_environment_scope() {
        assert_eq!(
            S3PublicAccessTester.environment_scope(),
            EnvironmentScope::Production
        );
    }

    #[test]
    fn s3_tester_pre_flight_nonempty() {
        assert!(!S3PublicAccessTester.pre_flight_checks().is_empty());
    }

    #[test]
    fn s3_tester_cleanup_empty() {
        assert!(S3PublicAccessTester.cleanup_procedures().is_empty());
    }

    #[test]
    fn s3_tester_missing_bucket_url_errors() {
        let err = S3PublicAccessTester.test(&HashMap::new()).unwrap_err();
        assert!(err.to_string().contains("AWS_TEST_BUCKET"));
    }

    // ── HTTP integration ─────────────────────────────────────────────────────

    #[test]
    fn s3_tester_403_means_access_blocked_effective() {
        let srv = mock_server(403, "AccessDenied");
        let config = HashMap::from([("AWS_TEST_BUCKET".to_string(), srv)]);
        let ev = &S3PublicAccessTester.test(&config).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert_eq!(ev.findings[0].title, "S3 Public Access Blocked");
        assert_eq!(ev.class_uid, 1002);
        assert_eq!(ev.control_id, "s3.public_access");
        assert!(ev.test_transcript.is_some());
    }

    #[test]
    fn s3_tester_404_means_access_blocked_effective() {
        let srv = mock_server(404, "NoSuchBucket");
        let config = HashMap::from([("AWS_TEST_BUCKET".to_string(), srv)]);
        let ev = &S3PublicAccessTester.test(&config).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Effective);
        assert_eq!(ev.findings[0].title, "S3 Public Access Blocked");
    }

    #[test]
    fn s3_tester_200_means_publicly_accessible_ineffective() {
        let srv = mock_server(200, "<ListBucketResult/>");
        let config = HashMap::from([("AWS_TEST_BUCKET".to_string(), srv)]);
        let ev = &S3PublicAccessTester.test(&config).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Ineffective);
        assert_eq!(ev.findings[0].title, "S3 Bucket Publicly Accessible");
        assert_eq!(ev.findings[0].severity_id, 4);
    }

    #[test]
    fn s3_tester_500_means_unknown() {
        let srv = mock_server(500, "Internal Server Error");
        let config = HashMap::from([("AWS_TEST_BUCKET".to_string(), srv)]);
        let ev = &S3PublicAccessTester.test(&config).unwrap()[0];
        assert_eq!(ev.status_id, StatusId::Unknown);
        assert_eq!(ev.findings[0].title, "Unexpected S3 Response");
    }

    #[test]
    fn s3_tester_has_transcript() {
        let srv = mock_server(403, "AccessDenied");
        let config = HashMap::from([("AWS_TEST_BUCKET".to_string(), srv)]);
        let ev = &S3PublicAccessTester.test(&config).unwrap()[0];
        let t = ev.test_transcript.as_ref().unwrap();
        assert!(!t.actions_attempted.is_empty());
        assert!(!t.observations.is_empty());
    }

    #[test]
    fn s3_tester_raw_data_has_expected_keys() {
        let srv = mock_server(403, "Denied");
        let config = HashMap::from([("AWS_TEST_BUCKET".to_string(), srv)]);
        let ev = &S3PublicAccessTester.test(&config).unwrap()[0];
        assert!(ev.raw_data.get("test_scenario").is_some());
        assert!(ev.raw_data.get("target_bucket").is_some());
        assert!(ev.raw_data.get("test_result").is_some());
    }

    #[test]
    fn s3_tester_safety_classification_in_metadata() {
        let srv = mock_server(403, "Denied");
        let config = HashMap::from([("AWS_TEST_BUCKET".to_string(), srv)]);
        let ev = &S3PublicAccessTester.test(&config).unwrap()[0];
        assert_eq!(ev.metadata.safety_classification.as_deref(), Some("safe"));
    }

    #[test]
    fn s3_tester_unique_ids() {
        let srv1 = mock_server(403, "D");
        let srv2 = mock_server(403, "D");
        let id1 = S3PublicAccessTester
            .test(&HashMap::from([("AWS_TEST_BUCKET".to_string(), srv1)]))
            .unwrap()[0]
            .id;
        let id2 = S3PublicAccessTester
            .test(&HashMap::from([("AWS_TEST_BUCKET".to_string(), srv2)]))
            .unwrap()[0]
            .id;
        assert_ne!(id1, id2);
    }
}
