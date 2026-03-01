use std::collections::HashMap;

use anyhow::Result;
use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

use crate::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId,
};
use crate::module::{observer::Observer, CredentialReq, Module};

// ─── MockObserver ─────────────────────────────────────────────────────────────

/// Mock observer — returns MFA-policy-style evidence with no external calls.
/// Used to test the observation pipeline end-to-end without any credentials.
pub struct MockObserver;

impl Module for MockObserver {
    fn id(&self) -> &str {
        "mock.test"
    }
    fn name(&self) -> &str {
        "Mock Test Observer"
    }
    fn version(&self) -> &str {
        "0.1.0"
    }
    fn source_system(&self) -> &str {
        "mock"
    }
    fn evidence_types(&self) -> &[i32] {
        &[1001]
    }
    fn credential_requirements(&self) -> Vec<CredentialReq> {
        vec![]
    }
}

impl Observer for MockObserver {
    fn observe(&self, _config: &HashMap<String, String>) -> Result<Vec<Evidence>> {
        let now = Utc::now();
        Ok(vec![Evidence {
            id: Uuid::new_v4(),
            control_id: "mock.mfa_enforcement".to_string(),
            class_uid: 1001,
            category_uid: 1,
            activity_id: 1,
            time: now,
            confidence_level: ConfidenceLevel::PassiveObservation,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "mock.test".to_string(),
                    version: "0.1.0".to_string(),
                    module_type: "observer".to_string(),
                },
                source: SourceInfo {
                    system: "mock".to_string(),
                    api_version: "v1".to_string(),
                    endpoint: "/api/v1/policies".to_string(),
                },
                original_time: None,
                processed_time: now,
                safety_classification: None,
            },
            observables: vec![Observable {
                obs_type: "resource".to_string(),
                value: "mfa_policy_global".to_string(),
                name: String::new(),
            }],
            status_id: StatusId::Effective,
            status: "MFA enforcement is required for all users".to_string(),
            raw_data: json!({
                "mfa_policy": {
                    "enforcement": "required",
                    "user_exceptions": [],
                    "factors_allowed": ["push", "totp", "webauthn"]
                },
                "total_users": 150,
                "mfa_enrolled": 150,
                "last_policy_update": "2026-01-15T10:30:00Z"
            }),
            findings: vec![Finding {
                title: "MFA Policy Active".to_string(),
                description: "MFA enforcement is set to 'required' with zero user exceptions"
                    .to_string(),
                severity_id: 0,
            }],
            test_transcript: None,
            enrichments: vec![],
        }])
    }
}

// ─── MockNetworkObserver ──────────────────────────────────────────────────────

/// Mock network observer — returns WAF-config evidence with no external calls.
/// Used alongside MockObserver to test composite control evaluation.
pub struct MockNetworkObserver;

impl Module for MockNetworkObserver {
    fn id(&self) -> &str {
        "mock.network"
    }
    fn name(&self) -> &str {
        "Mock Network Observer"
    }
    fn version(&self) -> &str {
        "0.1.0"
    }
    fn source_system(&self) -> &str {
        "mock"
    }
    fn evidence_types(&self) -> &[i32] {
        &[1002]
    }
    fn credential_requirements(&self) -> Vec<CredentialReq> {
        vec![]
    }
}

impl Observer for MockNetworkObserver {
    fn observe(&self, _config: &HashMap<String, String>) -> Result<Vec<Evidence>> {
        let now = Utc::now();
        Ok(vec![Evidence {
            id: Uuid::new_v4(),
            control_id: "mock.waf_protection".to_string(),
            class_uid: 1002,
            category_uid: 4,
            activity_id: 1,
            time: now,
            confidence_level: ConfidenceLevel::PassiveObservation,
            metadata: Metadata {
                module: ModuleInfo {
                    name: "mock.network".to_string(),
                    version: "0.1.0".to_string(),
                    module_type: "observer".to_string(),
                },
                source: SourceInfo {
                    system: "mock".to_string(),
                    api_version: "v1".to_string(),
                    endpoint: "/api/v1/waf/config".to_string(),
                },
                original_time: None,
                processed_time: now,
                safety_classification: None,
            },
            observables: vec![
                Observable {
                    obs_type: "resource".to_string(),
                    value: "waf_global_config".to_string(),
                    name: String::new(),
                },
                Observable {
                    obs_type: "resource".to_string(),
                    value: "waf_rule_sets".to_string(),
                    name: String::new(),
                },
            ],
            status_id: StatusId::Effective,
            status: "WAF is enabled in block mode with current rule sets".to_string(),
            raw_data: json!({
                "waf_config": {
                    "enabled": true,
                    "mode": "block",
                    "rule_sets": ["OWASP-CRS-3.3", "custom-rules-v2"],
                    "rate_limiting": true,
                    "geo_blocking": false,
                    "bot_protection": true,
                    "ssl_termination": true
                },
                "protected_origins": 3,
                "blocked_requests_24h": 1247,
                "last_rule_update": "2026-01-20T14:00:00Z"
            }),
            findings: vec![Finding {
                title: "WAF Active".to_string(),
                description: "WAF is enabled in block mode with OWASP CRS 3.3 and custom rules"
                    .to_string(),
                severity_id: 0,
            }],
            test_transcript: None,
            enrichments: vec![],
        }])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── MockObserver ────────────────────────────────────────────────────────

    #[test]
    fn mock_observer_id() {
        assert_eq!(MockObserver.id(), "mock.test");
    }

    #[test]
    fn mock_observer_name() {
        assert_eq!(MockObserver.name(), "Mock Test Observer");
    }

    #[test]
    fn mock_observer_version() {
        assert_eq!(MockObserver.version(), "0.1.0");
    }

    #[test]
    fn mock_observer_source_system() {
        assert_eq!(MockObserver.source_system(), "mock");
    }

    #[test]
    fn mock_observer_evidence_types() {
        assert_eq!(MockObserver.evidence_types(), &[1001]);
    }

    #[test]
    fn mock_observer_credential_requirements_empty() {
        assert!(MockObserver.credential_requirements().is_empty());
    }

    #[test]
    fn mock_observer_collect_returns_one() {
        let results = MockObserver.observe(&HashMap::new()).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn mock_observer_collect_core_fields() {
        let ev = &MockObserver.observe(&HashMap::new()).unwrap()[0];
        assert_eq!(ev.control_id, "mock.mfa_enforcement");
        assert_eq!(ev.class_uid, 1001);
        assert_eq!(ev.category_uid, 1);
        assert_eq!(ev.activity_id, 1);
        assert!(!ev.time.to_rfc3339().is_empty());
        assert_eq!(ev.confidence_level, ConfidenceLevel::PassiveObservation);
        assert_eq!(ev.status_id, StatusId::Effective);
        assert!(!ev.status.is_empty());
        assert!(ev.test_transcript.is_none());
    }

    #[test]
    fn mock_observer_collect_metadata() {
        let ev = &MockObserver.observe(&HashMap::new()).unwrap()[0];
        assert_eq!(ev.metadata.module.name, "mock.test");
        assert_eq!(ev.metadata.module.version, "0.1.0");
        assert_eq!(ev.metadata.module.module_type, "observer");
        assert_eq!(ev.metadata.source.system, "mock");
        assert_eq!(ev.metadata.source.api_version, "v1");
        assert!(!ev.metadata.source.endpoint.is_empty());
        assert!(!ev.metadata.processed_time.to_rfc3339().is_empty());
    }

    #[test]
    fn mock_observer_collect_has_observables() {
        let ev = &MockObserver.observe(&HashMap::new()).unwrap()[0];
        assert!(!ev.observables.is_empty());
        assert_eq!(ev.observables[0].obs_type, "resource");
    }

    #[test]
    fn mock_observer_collect_has_findings() {
        let ev = &MockObserver.observe(&HashMap::new()).unwrap()[0];
        assert!(!ev.findings.is_empty());
        assert_eq!(ev.findings[0].title, "MFA Policy Active");
        assert_eq!(ev.findings[0].severity_id, 0);
    }

    #[test]
    fn mock_observer_collect_raw_data_keys() {
        let ev = &MockObserver.observe(&HashMap::new()).unwrap()[0];
        assert!(ev.raw_data.get("mfa_policy").is_some());
        assert!(ev.raw_data.get("total_users").is_some());
        assert!(ev.raw_data.get("mfa_enrolled").is_some());
        let mfa = ev.raw_data["mfa_policy"].as_object().unwrap();
        assert_eq!(mfa["enforcement"].as_str().unwrap(), "required");
    }

    #[test]
    fn mock_observer_collect_unique_ids() {
        let id1 = MockObserver.observe(&HashMap::new()).unwrap()[0].id;
        let id2 = MockObserver.observe(&HashMap::new()).unwrap()[0].id;
        assert_ne!(id1, id2);
    }

    #[test]
    fn mock_observer_collect_no_enrichments() {
        let ev = &MockObserver.observe(&HashMap::new()).unwrap()[0];
        assert!(ev.enrichments.is_empty());
    }

    // ─── MockNetworkObserver ─────────────────────────────────────────────────

    #[test]
    fn mock_network_id() {
        assert_eq!(MockNetworkObserver.id(), "mock.network");
    }

    #[test]
    fn mock_network_name() {
        assert_eq!(MockNetworkObserver.name(), "Mock Network Observer");
    }

    #[test]
    fn mock_network_version() {
        assert_eq!(MockNetworkObserver.version(), "0.1.0");
    }

    #[test]
    fn mock_network_source_system() {
        assert_eq!(MockNetworkObserver.source_system(), "mock");
    }

    #[test]
    fn mock_network_evidence_types() {
        assert_eq!(MockNetworkObserver.evidence_types(), &[1002]);
    }

    #[test]
    fn mock_network_credential_requirements_empty() {
        assert!(MockNetworkObserver.credential_requirements().is_empty());
    }

    #[test]
    fn mock_network_collect_returns_one() {
        let results = MockNetworkObserver.observe(&HashMap::new()).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn mock_network_collect_core_fields() {
        let ev = &MockNetworkObserver.observe(&HashMap::new()).unwrap()[0];
        assert_eq!(ev.control_id, "mock.waf_protection");
        assert_eq!(ev.class_uid, 1002);
        assert_eq!(ev.category_uid, 4);
        assert_eq!(ev.activity_id, 1);
        assert_eq!(ev.confidence_level, ConfidenceLevel::PassiveObservation);
        assert_eq!(ev.status_id, StatusId::Effective);
        assert!(ev.test_transcript.is_none());
    }

    #[test]
    fn mock_network_collect_metadata() {
        let ev = &MockNetworkObserver.observe(&HashMap::new()).unwrap()[0];
        assert_eq!(ev.metadata.module.name, "mock.network");
        assert_eq!(ev.metadata.module.module_type, "observer");
        assert_eq!(ev.metadata.source.system, "mock");
        assert_eq!(ev.metadata.source.api_version, "v1");
        assert_eq!(ev.metadata.source.endpoint, "/api/v1/waf/config");
    }

    #[test]
    fn mock_network_collect_has_two_observables() {
        let ev = &MockNetworkObserver.observe(&HashMap::new()).unwrap()[0];
        assert_eq!(ev.observables.len(), 2);
        assert_eq!(ev.observables[0].obs_type, "resource");
        assert_eq!(ev.observables[1].obs_type, "resource");
    }

    #[test]
    fn mock_network_collect_has_finding() {
        let ev = &MockNetworkObserver.observe(&HashMap::new()).unwrap()[0];
        assert_eq!(ev.findings.len(), 1);
        assert_eq!(ev.findings[0].title, "WAF Active");
    }

    #[test]
    fn mock_network_collect_raw_data_keys() {
        let ev = &MockNetworkObserver.observe(&HashMap::new()).unwrap()[0];
        assert!(ev.raw_data.get("waf_config").is_some());
        assert!(ev.raw_data.get("protected_origins").is_some());
        assert!(ev.raw_data.get("blocked_requests_24h").is_some());
        assert_eq!(
            ev.raw_data["waf_config"]["enabled"].as_bool().unwrap(),
            true
        );
    }

    #[test]
    fn mock_network_collect_unique_ids() {
        let id1 = MockNetworkObserver.observe(&HashMap::new()).unwrap()[0].id;
        let id2 = MockNetworkObserver.observe(&HashMap::new()).unwrap()[0].id;
        assert_ne!(id1, id2);
    }
}
