/// GRC-17 §5.1 — Multi-module pipeline tests
/// GRC-17 §5.6 — Error handling
use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use chrono::Utc;
use uuid::Uuid;

use ocean::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId,
    EVIDENCE_SCHEMA_VERSION,
};
use ocean::module::{CredentialReq, Executor, Module, Observer, Registry};
use ocean::scheduler::runner::execute_schedule;
use ocean::scheduler::{
    Schedule, MODULE_STATUS_FAILURE, MODULE_STATUS_SUCCESS, RUN_STATUS_FAILURE,
    RUN_STATUS_PARTIAL_FAILURE, RUN_STATUS_SUCCESS,
};
use ocean::storage::{EvidenceQuery, SqliteStore, Store};

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn make_evidence(control_id: &str, source: &str) -> Evidence {
    Evidence {
        schema_version: EVIDENCE_SCHEMA_VERSION.to_string(),
        connected_account: None,
        population: None,
        evaluation: None,
        id: Uuid::new_v4(),
        control_id: control_id.to_string(),
        class_uid: 1001,
        category_uid: 10,
        activity_id: 1,
        time: Utc::now(),
        confidence_level: ConfidenceLevel::PassiveObservation,
        metadata: Metadata {
            module: ModuleInfo {
                name: format!("pipeline.{}", source),
                version: "0.1.0".to_string(),
                module_type: "observer".to_string(),
            },
            source: SourceInfo {
                system: source.to_string(),
                api_version: "v1".to_string(),
                endpoint: format!("mock://{}", source),
            },
            original_time: None,
            processed_time: Utc::now(),
            safety_classification: None,
        },
        observables: vec![Observable {
            obs_type: "resource".to_string(),
            value: format!("{}:resource", source),
            name: String::new(),
        }],
        status_id: StatusId::Effective,
        status: "effective".to_string(),
        raw_data: serde_json::json!({"source": source}),
        findings: vec![Finding {
            title: "Pipeline Finding".to_string(),
            description: format!("Finding from {}", source),
            severity_id: 0,
        }],
        test_transcript: None,
        enrichments: vec![],
    }
}

struct PipelineObserver {
    id: &'static str,
    control_id: &'static str,
    source: &'static str,
    fail: bool,
}

impl Module for PipelineObserver {
    fn id(&self) -> &str {
        self.id
    }
    fn name(&self) -> &str {
        "Pipeline Mock Observer"
    }
    fn version(&self) -> &str {
        "0.1.0"
    }
    fn source_system(&self) -> &str {
        self.source
    }
    fn evidence_types(&self) -> &[i32] {
        &[1001]
    }
    fn credential_requirements(&self) -> Vec<CredentialReq> {
        vec![]
    }
}

impl Observer for PipelineObserver {
    fn observe(&self, _: &HashMap<String, String>) -> Result<Vec<Evidence>> {
        if self.fail {
            anyhow::bail!("pipeline observer {} failed", self.id);
        }
        Ok(vec![make_evidence(self.control_id, self.source)])
    }
}

fn make_schedule(modules: Vec<&str>) -> Schedule {
    let now = Utc::now();
    Schedule {
        id: Uuid::new_v4().to_string(),
        control_id: "pipeline.ctrl".to_string(),
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

// ─── 5.1: Multi-module pipeline ──────────────────────────────────────────────

/// Three observers collect evidence for the same control; all evidence is stored
/// and queryable by control_id after the pipeline run.
#[test]
fn pipeline_multi_module_collect_and_store() {
    let store = SqliteStore::open(":memory:").unwrap();
    let registry = Arc::new(Registry::new());

    registry.register_observer(Arc::new(PipelineObserver {
        id: "pipeline.github",
        control_id: "MFA-1",
        source: "github",
        fail: false,
    }));
    registry.register_observer(Arc::new(PipelineObserver {
        id: "pipeline.okta",
        control_id: "MFA-1",
        source: "okta",
        fail: false,
    }));
    registry.register_observer(Arc::new(PipelineObserver {
        id: "pipeline.aws",
        control_id: "MFA-1",
        source: "aws",
        fail: false,
    }));

    let schedule = make_schedule(vec!["pipeline.github", "pipeline.okta", "pipeline.aws"]);
    store.store_schedule(&schedule).unwrap();

    let run = execute_schedule(&schedule, &store, &registry);

    assert_eq!(run.status, RUN_STATUS_SUCCESS);
    assert_eq!(run.module_results.len(), 3);
    assert!(run
        .module_results
        .iter()
        .all(|r| r.status == MODULE_STATUS_SUCCESS));

    let query = EvidenceQuery {
        control_id: Some("MFA-1".to_string()),
        ..Default::default()
    };
    let stored = store.query_evidence(&query).unwrap();
    assert_eq!(
        stored.len(),
        3,
        "all three modules' evidence must be stored"
    );
    let sources: Vec<&str> = stored
        .iter()
        .map(|e| e.metadata.source.system.as_str())
        .collect();
    assert!(sources.contains(&"github"));
    assert!(sources.contains(&"okta"));
    assert!(sources.contains(&"aws"));
}

/// Executor runs multiple observers; evidence from successful ones is stored
/// even when others fail.
#[test]
fn pipeline_mixed_pass_fail_evidence_stored() {
    let store = SqliteStore::open(":memory:").unwrap();
    let registry = Arc::new(Registry::new());

    registry.register_observer(Arc::new(PipelineObserver {
        id: "pipeline.pass1",
        control_id: "MIXED-1",
        source: "okta",
        fail: false,
    }));
    registry.register_observer(Arc::new(PipelineObserver {
        id: "pipeline.fail1",
        control_id: "MIXED-1",
        source: "github",
        fail: true,
    }));
    registry.register_observer(Arc::new(PipelineObserver {
        id: "pipeline.pass2",
        control_id: "MIXED-1",
        source: "aws",
        fail: false,
    }));

    let schedule = make_schedule(vec!["pipeline.pass1", "pipeline.fail1", "pipeline.pass2"]);
    store.store_schedule(&schedule).unwrap();

    let run = execute_schedule(&schedule, &store, &registry);

    // Status should reflect partial failure.
    assert!(
        run.status == RUN_STATUS_PARTIAL_FAILURE || run.status == RUN_STATUS_FAILURE,
        "expected failure status, got: {}",
        run.status
    );

    let successes = run
        .module_results
        .iter()
        .filter(|r| r.status == MODULE_STATUS_SUCCESS)
        .count();
    let failures = run
        .module_results
        .iter()
        .filter(|r| r.status == MODULE_STATUS_FAILURE)
        .count();
    assert_eq!(successes, 2);
    assert_eq!(failures, 1);

    // Successful modules' evidence must still be stored.
    let query = EvidenceQuery {
        control_id: Some("MIXED-1".to_string()),
        ..Default::default()
    };
    let stored = store.query_evidence(&query).unwrap();
    assert_eq!(
        stored.len(),
        2,
        "2 successful modules should have stored evidence"
    );
}

/// Direct executor: two observers registered; execute_observer for each returns evidence.
#[test]
fn pipeline_executor_collects_from_multiple_modules() {
    let registry = Arc::new(Registry::new());
    registry.register_observer(Arc::new(PipelineObserver {
        id: "exec.mod1",
        control_id: "EXEC-1",
        source: "github",
        fail: false,
    }));
    registry.register_observer(Arc::new(PipelineObserver {
        id: "exec.mod2",
        control_id: "EXEC-1",
        source: "okta",
        fail: false,
    }));

    let executor = Executor::new(Arc::clone(&registry));
    let ev1 = executor
        .execute_observer("exec.mod1", &HashMap::new())
        .unwrap();
    let ev2 = executor
        .execute_observer("exec.mod2", &HashMap::new())
        .unwrap();

    assert!(!ev1.is_empty());
    assert!(!ev2.is_empty());
    assert_ne!(ev1[0].metadata.source.system, ev2[0].metadata.source.system);
}

// ─── 5.6: Error handling ─────────────────────────────────────────────────────

/// A failing observer's error is captured in module_results.error field.
#[test]
fn error_handling_module_error_captured_in_run() {
    let store = SqliteStore::open(":memory:").unwrap();
    let registry = Arc::new(Registry::new());

    registry.register_observer(Arc::new(PipelineObserver {
        id: "err.fail",
        control_id: "ERR-1",
        source: "mock",
        fail: true,
    }));

    let schedule = make_schedule(vec!["err.fail"]);
    store.store_schedule(&schedule).unwrap();

    let run = execute_schedule(&schedule, &store, &registry);

    assert_eq!(run.status, RUN_STATUS_FAILURE);
    assert_eq!(run.module_results.len(), 1);
    assert_eq!(run.module_results[0].status, MODULE_STATUS_FAILURE);
    assert!(
        !run.module_results[0].error.is_empty(),
        "error message must be captured"
    );
}

/// Unknown module ID results in a failure run with a descriptive error.
#[test]
fn error_handling_unknown_module_id() {
    let store = SqliteStore::open(":memory:").unwrap();
    let registry = Arc::new(Registry::new());
    let schedule = make_schedule(vec!["nonexistent.module"]);
    store.store_schedule(&schedule).unwrap();

    let run = execute_schedule(&schedule, &store, &registry);

    assert_eq!(run.status, RUN_STATUS_FAILURE);
    assert_eq!(run.module_results[0].status, MODULE_STATUS_FAILURE);
    assert!(!run.module_results[0].error.is_empty());
}

/// After a partial failure run, successfully-collected evidence remains queryable.
#[test]
fn error_handling_partial_failure_does_not_lose_evidence() {
    let store = SqliteStore::open(":memory:").unwrap();
    let registry = Arc::new(Registry::new());

    registry.register_observer(Arc::new(PipelineObserver {
        id: "err.good",
        control_id: "ERR-2",
        source: "github",
        fail: false,
    }));
    registry.register_observer(Arc::new(PipelineObserver {
        id: "err.bad",
        control_id: "ERR-2",
        source: "okta",
        fail: true,
    }));

    let schedule = make_schedule(vec!["err.good", "err.bad"]);
    store.store_schedule(&schedule).unwrap();
    execute_schedule(&schedule, &store, &registry);

    let query = EvidenceQuery {
        control_id: Some("ERR-2".to_string()),
        ..Default::default()
    };
    let stored = store.query_evidence(&query).unwrap();
    assert_eq!(
        stored.len(),
        1,
        "evidence from the good module must survive partial failure"
    );
}
