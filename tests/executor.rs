use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use chrono::Utc;
use uuid::Uuid;

use ocean::evidence::{ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId};
use ocean::module::{CredentialReq, Executor, Module, Observer, Registry};

// ---------------------------------------------------------------------------
// Local mock evidence builder (cannot use ocean::testutil — cfg(test) gated)
// ---------------------------------------------------------------------------

fn make_evidence() -> Evidence {
    Evidence {
        id: Uuid::new_v4(),
        control_id: "test.control".to_string(),
        class_uid: 1001,
        category_uid: 10,
        activity_id: 1,
        time: Utc::now(),
        confidence_level: ConfidenceLevel::PassiveObservation,
        metadata: Metadata {
            module: ModuleInfo {
                name: "local.mock".to_string(),
                version: "0.1.0".to_string(),
                module_type: "observer".to_string(),
            },
            source: SourceInfo {
                system: "mock".to_string(),
                api_version: "v1".to_string(),
                endpoint: "mock://local".to_string(),
            },
            original_time: None,
            processed_time: Utc::now(),
            safety_classification: None,
        },
        observables: vec![Observable {
            obs_type: "resource".to_string(),
            value: "mock-resource".to_string(),
            name: String::new(),
        }],
        status_id: StatusId::Effective,
        status: "effective".to_string(),
        raw_data: serde_json::json!({"mock": true}),
        findings: vec![Finding {
            title: "Mock Finding".to_string(),
            description: "Integration test finding".to_string(),
            severity_id: 1,
        }],
        test_transcript: None,
        enrichments: vec![],
    }
}

// ---------------------------------------------------------------------------
// LocalMockObserver
// ---------------------------------------------------------------------------

struct LocalMockObserver {
    pub id: &'static str,
    pub fail: bool,
}

impl Module for LocalMockObserver {
    fn id(&self) -> &str {
        self.id
    }
    fn name(&self) -> &str {
        "Local Mock Observer"
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

impl Observer for LocalMockObserver {
    fn observe(&self, _config: &HashMap<String, String>) -> Result<Vec<Evidence>> {
        if self.fail {
            anyhow::bail!("mock fail");
        }
        Ok(vec![make_evidence()])
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn executor_observe_returns_evidence() {
    let registry = Arc::new(Registry::new());
    registry.register_observer(Arc::new(LocalMockObserver { id: "local.mock", fail: false }));
    let executor = Executor::new(Arc::clone(&registry));

    let result = executor.execute_observer("local.mock", &HashMap::new());

    assert!(result.is_ok());
    let evidences = result.unwrap();
    assert!(!evidences.is_empty());
}

#[test]
fn executor_observe_failing_module() {
    let registry = Arc::new(Registry::new());
    registry.register_observer(Arc::new(LocalMockObserver { id: "local.fail", fail: true }));
    let executor = Executor::new(Arc::clone(&registry));

    let result = executor.execute_observer("local.fail", &HashMap::new());

    assert!(result.is_err());
}

#[test]
fn executor_unknown_module() {
    let registry = Arc::new(Registry::new());
    let executor = Executor::new(Arc::clone(&registry));

    let result = executor.execute_observer("does.not.exist", &HashMap::new());

    assert!(result.is_err());
}
