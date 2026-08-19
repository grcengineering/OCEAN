use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use chrono::Utc;
use uuid::Uuid;

use ocean::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId,
};
use ocean::module::{CredentialReq, Module, Observer, Registry};
use ocean::scheduler::runner::execute_schedule;
use ocean::scheduler::{
    Schedule, MODULE_STATUS_FAILURE, MODULE_STATUS_SUCCESS, RUN_STATUS_FAILURE, RUN_STATUS_SUCCESS,
};
use ocean::storage::SqliteStore;

// ---------------------------------------------------------------------------
// Local mock helpers
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
                name: "sched.mock".to_string(),
                version: "0.1.0".to_string(),
                module_type: "observer".to_string(),
            },
            source: SourceInfo {
                system: "mock".to_string(),
                api_version: "v1".to_string(),
                endpoint: "mock://sched".to_string(),
            },
            original_time: None,
            processed_time: Utc::now(),
            safety_classification: None,
        },
        observables: vec![Observable {
            obs_type: "resource".to_string(),
            value: "mock-sched-resource".to_string(),
            name: String::new(),
        }],
        status_id: StatusId::Effective,
        status: "effective".to_string(),
        raw_data: serde_json::json!({"schedule_test": true}),
        findings: vec![Finding {
            title: "Schedule Finding".to_string(),
            description: "A schedule test finding".to_string(),
            severity_id: 1,
        }],
        test_transcript: None,
        enrichments: vec![],
    }
}

struct LocalMockObserver {
    pub id: &'static str,
}

impl Module for LocalMockObserver {
    fn id(&self) -> &str {
        self.id
    }
    fn name(&self) -> &str {
        "Local Schedule Mock Observer"
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
        Ok(vec![make_evidence()])
    }
}

fn make_schedule(modules: Vec<&str>) -> Schedule {
    let now = Utc::now();
    Schedule {
        id: Uuid::new_v4().to_string(),
        control_id: String::new(),
        cron_expr: "0 * * * *".to_string(),
        modules: modules.into_iter().map(|s| s.to_string()).collect(),
        max_safety_level: "safe".to_string(),
        environment_scope: "production".to_string(),
        enabled: true,
        catch_up: false,
        last_run: None,
        next_run: None,
        created_at: now,
        updated_at: now,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn schedule_run_empty_modules() {
    let store = SqliteStore::open(":memory:").unwrap();
    let registry = Arc::new(Registry::new());
    let schedule = make_schedule(vec![]);

    // Should complete without panicking
    let run = execute_schedule(&schedule, &store, &registry);

    assert_eq!(run.schedule_id, schedule.id);
    assert_eq!(run.module_results.len(), 0);
    assert_eq!(run.status, RUN_STATUS_SUCCESS);
}

#[test]
fn schedule_run_unknown_module() {
    let store = SqliteStore::open(":memory:").unwrap();
    let registry = Arc::new(Registry::new());
    let schedule = make_schedule(vec!["does.not.exist"]);

    let run = execute_schedule(&schedule, &store, &registry);

    assert_eq!(run.module_results.len(), 1);
    assert_eq!(run.module_results[0].status, MODULE_STATUS_FAILURE);
    assert_eq!(run.status, RUN_STATUS_FAILURE);
}

#[test]
fn schedule_run_with_mock_observer() {
    let store = SqliteStore::open(":memory:").unwrap();
    let registry = Arc::new(Registry::new());
    registry.register_observer(Arc::new(LocalMockObserver { id: "sched.mock" }));

    let schedule = make_schedule(vec!["sched.mock"]);

    // Store schedule so the FK constraint is satisfied when the run is persisted.
    use ocean::storage::Store;
    store.store_schedule(&schedule).unwrap();

    let run = execute_schedule(&schedule, &store, &registry);

    assert_eq!(run.module_results.len(), 1);
    assert_eq!(run.module_results[0].status, MODULE_STATUS_SUCCESS);
    assert_eq!(run.status, RUN_STATUS_SUCCESS);
}
