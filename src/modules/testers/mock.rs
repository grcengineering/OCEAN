use std::collections::HashMap;

use anyhow::Result;
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

// ─── MockTester ───────────────────────────────────────────────────────────────

/// Simulates an MFA bypass test that is safely blocked.
/// Produces evidence at active_verification confidence with a full transcript.
/// Requires no credentials and makes no external calls.
pub struct MockTester;

impl Module for MockTester {
    fn id(&self) -> &str { "mock.safety_test" }
    fn name(&self) -> &str { "Mock Safety Test" }
    fn version(&self) -> &str { "0.1.0" }
    fn source_system(&self) -> &str { "mock" }
    fn evidence_types(&self) -> &[i32] { &[1001] }
    fn credential_requirements(&self) -> Vec<CredentialReq> { vec![] }
}

impl Tester for MockTester {
    fn safety_class(&self) -> SafetyClassification { SafetyClassification::Safe }
    fn environment_scope(&self) -> EnvironmentScope { EnvironmentScope::Production }

    fn pre_flight_checks(&self) -> Vec<String> {
        vec!["verify mock target available".to_string()]
    }

    fn cleanup_procedures(&self) -> Vec<String> {
        vec!["remove test artifacts".to_string()]
    }

    fn test(&self, _config: &HashMap<String, String>) -> Result<Vec<Evidence>> {
        let now = Utc::now();
        let mut recorder = TranscriptRecorder::new();

        recorder.record_action(
            "initiate mock MFA bypass attempt",
            Some(json!({
                "target": "mock-idp.example.com",
                "method": "totp_replay",
                "user": "test-user@example.com"
            })),
        );
        recorder.record_action(
            "submit credentials without valid MFA token",
            Some(json!({
                "credentials": "redacted",
                "mfa_token": "expired_token_000000"
            })),
        );
        recorder.record_observation("MFA challenge presented to user", true);
        recorder.record_observation("invalid MFA token rejected with HTTP 403", true);
        recorder.record_observation("authentication attempt logged in audit trail", true);
        recorder.record_cleanup("remove test artifacts", true);

        let transcript = recorder.finalize();
        let safety_class = "safe".to_string();

        Ok(vec![Evidence {
            id: Uuid::new_v4(),
            control_id: "mock.mfa_enforcement".to_string(),
            class_uid: 1001,
            category_uid: 1,
            activity_id: 2, // Active Test
            time: now,
            confidence_level: ConfidenceLevel::ActiveVerification,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "mock.safety_test".to_string(),
                    version: "0.1.0".to_string(),
                    module_type: "tester".to_string(),
                },
                source: SourceInfo {
                    system: "mock".to_string(),
                    api_version: "v1".to_string(),
                    endpoint: "/api/v1/auth/test".to_string(),
                },
                original_time: None,
                processed_time: now,
                safety_classification: Some(safety_class),
            },
            observables: vec![
                Observable {
                    obs_type: "resource".to_string(),
                    value: "mfa_policy_global".to_string(),
                },
                Observable {
                    obs_type: "user".to_string(),
                    value: "test-user@example.com".to_string(),
                },
            ],
            status_id: StatusId::Effective,
            status: "MFA bypass attempt was correctly blocked".to_string(),
            raw_data: json!({
                "test_scenario": "mfa_bypass_attempt",
                "target_system": "mock-idp.example.com",
                "test_result": "blocked",
                "mfa_policy": {
                    "enforcement": "required",
                    "bypass_allowed": false
                },
                "attempt_details": {
                    "method": "totp_replay",
                    "token_status": "expired",
                    "http_status": 403
                }
            }),
            findings: vec![Finding {
                title: "MFA Bypass Blocked".to_string(),
                description: "Simulated MFA bypass with expired TOTP token was correctly rejected with HTTP 403".to_string(),
                severity_id: 0,
            }],
            test_transcript: Some(transcript),
            enrichments: vec![],
        }])
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_tester_id() { assert_eq!(MockTester.id(), "mock.safety_test"); }

    #[test]
    fn mock_tester_name() { assert_eq!(MockTester.name(), "Mock Safety Test"); }

    #[test]
    fn mock_tester_version() { assert_eq!(MockTester.version(), "0.1.0"); }

    #[test]
    fn mock_tester_source_system() { assert_eq!(MockTester.source_system(), "mock"); }

    #[test]
    fn mock_tester_evidence_types() { assert_eq!(MockTester.evidence_types(), &[1001]); }

    #[test]
    fn mock_tester_credential_requirements_empty() {
        assert!(MockTester.credential_requirements().is_empty());
    }

    #[test]
    fn mock_tester_safety_class_is_safe() {
        assert_eq!(MockTester.safety_class(), SafetyClassification::Safe);
    }

    #[test]
    fn mock_tester_environment_scope_production() {
        assert_eq!(MockTester.environment_scope(), EnvironmentScope::Production);
    }

    #[test]
    fn mock_tester_pre_flight_checks_nonempty() {
        assert!(!MockTester.pre_flight_checks().is_empty());
    }

    #[test]
    fn mock_tester_cleanup_procedures_nonempty() {
        assert!(!MockTester.cleanup_procedures().is_empty());
    }

    #[test]
    fn mock_tester_test_returns_one_evidence() {
        let results = MockTester.test(&HashMap::new()).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn mock_tester_test_core_fields() {
        let ev = &MockTester.test(&HashMap::new()).unwrap()[0];
        assert_eq!(ev.control_id, "mock.mfa_enforcement");
        assert_eq!(ev.class_uid, 1001);
        assert_eq!(ev.category_uid, 1);
        assert_eq!(ev.activity_id, 2);
        assert_eq!(ev.confidence_level, ConfidenceLevel::ActiveVerification);
        assert_eq!(ev.status_id, StatusId::Effective);
        assert!(!ev.status.is_empty());
    }

    #[test]
    fn mock_tester_test_metadata() {
        let ev = &MockTester.test(&HashMap::new()).unwrap()[0];
        assert_eq!(ev.metadata.module.name, "mock.safety_test");
        assert_eq!(ev.metadata.module.module_type, "tester");
        assert_eq!(ev.metadata.source.system, "mock");
        assert_eq!(
            ev.metadata.safety_classification.as_deref(),
            Some("safe")
        );
    }

    #[test]
    fn mock_tester_test_has_two_observables() {
        let ev = &MockTester.test(&HashMap::new()).unwrap()[0];
        assert_eq!(ev.observables.len(), 2);
        assert!(ev.observables.iter().any(|o| o.obs_type == "resource"));
        assert!(ev.observables.iter().any(|o| o.obs_type == "user"));
    }

    #[test]
    fn mock_tester_test_has_finding() {
        let ev = &MockTester.test(&HashMap::new()).unwrap()[0];
        assert_eq!(ev.findings.len(), 1);
        assert_eq!(ev.findings[0].title, "MFA Bypass Blocked");
        assert_eq!(ev.findings[0].severity_id, 0);
    }

    #[test]
    fn mock_tester_test_has_transcript() {
        let ev = &MockTester.test(&HashMap::new()).unwrap()[0];
        let transcript = ev.test_transcript.as_ref().unwrap();
        assert!(!transcript.actions_attempted.is_empty());
        assert!(!transcript.observations.is_empty());
        assert!(!transcript.cleanup_actions.is_empty());
    }

    #[test]
    fn mock_tester_test_transcript_observations() {
        let ev = &MockTester.test(&HashMap::new()).unwrap()[0];
        let obs = &ev.test_transcript.as_ref().unwrap().observations;
        assert!(obs.iter().all(|o| o.expected));
    }

    #[test]
    fn mock_tester_test_raw_data_keys() {
        let ev = &MockTester.test(&HashMap::new()).unwrap()[0];
        assert!(ev.raw_data.get("test_scenario").is_some());
        assert!(ev.raw_data.get("test_result").is_some());
        assert_eq!(ev.raw_data["test_result"].as_str().unwrap(), "blocked");
    }

    #[test]
    fn mock_tester_test_unique_ids() {
        let id1 = MockTester.test(&HashMap::new()).unwrap()[0].id;
        let id2 = MockTester.test(&HashMap::new()).unwrap()[0].id;
        assert_ne!(id1, id2);
    }
}
