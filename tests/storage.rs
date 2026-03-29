use chrono::Utc;
use ocean::control::ControlStatus;
use ocean::evidence::{ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId};
use ocean::scheduler::{Schedule, ScheduleRun, ModuleRunResult, RUN_STATUS_SUCCESS, MODULE_STATUS_SUCCESS};
use ocean::storage::{EvidenceQuery, SqliteStore, Store};
use uuid::Uuid;

fn make_store() -> SqliteStore {
    SqliteStore::open(":memory:").unwrap()
}

fn make_evidence(control_id: &str) -> Evidence {
    Evidence {
        id: Uuid::new_v4(),
        control_id: control_id.to_string(),
        class_uid: 1001,
        category_uid: 10,
        activity_id: 1,
        time: Utc::now(),
        confidence_level: ConfidenceLevel::PassiveObservation,
        metadata: Metadata {
            module: ModuleInfo {
                name: "test.module".to_string(),
                version: "0.1.0".to_string(),
                module_type: "observer".to_string(),
            },
            source: SourceInfo {
                system: "mock".to_string(),
                api_version: "v1".to_string(),
                endpoint: "mock://endpoint".to_string(),
            },
            original_time: None,
            processed_time: Utc::now(),
            safety_classification: None,
        },
        observables: vec![Observable {
            obs_type: "resource".to_string(),
            value: "arn:aws:s3:::test-bucket".to_string(),
            name: String::new(),
        }],
        status_id: StatusId::Effective,
        status: "effective".to_string(),
        raw_data: serde_json::json!({"key": "value"}),
        findings: vec![Finding {
            title: "Test Finding".to_string(),
            description: "A test finding".to_string(),
            severity_id: 2,
        }],
        test_transcript: None,
        enrichments: vec![],
    }
}

fn make_schedule() -> Schedule {
    let now = Utc::now();
    Schedule {
        id: Uuid::new_v4().to_string(),
        control_id: "test.control".to_string(),
        cron_expr: "0 * * * *".to_string(),
        modules: vec!["test.module".to_string()],
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

#[test]
fn storage_evidence_round_trip() {
    let store = make_store();
    let ev = make_evidence("test.control");
    let id = ev.id;

    store.store_evidence(&ev).unwrap();
    let fetched = store.get_evidence(id).unwrap();

    assert_eq!(fetched.id, id);
}

#[test]
fn storage_query_by_control_id() {
    let store = make_store();

    let ev1 = make_evidence("test.iam");
    let ev2 = make_evidence("test.iam");
    let ev3 = make_evidence("test.other");

    store.store_evidence(&ev1).unwrap();
    store.store_evidence(&ev2).unwrap();
    store.store_evidence(&ev3).unwrap();

    let query = EvidenceQuery {
        control_id: Some("test.iam".to_string()),
        ..Default::default()
    };
    let results = store.query_evidence(&query).unwrap();
    assert_eq!(results.len(), 2);
    assert!(results.iter().all(|e| e.control_id == "test.iam"));
}

#[test]
fn storage_control_status_round_trip() {
    let store = make_store();

    let status = ControlStatus {
        id: Uuid::new_v4(),
        control_id: "test.ctrl".to_string(),
        timestamp: Utc::now(),
        status: "effective".to_string(),
        confidence: "high".to_string(),
        evidence_ids: vec![],
        evaluation_details: "all checks passed".to_string(),
    };

    store.store_control_status(&status).unwrap();
    let fetched = store.get_control_status("test.ctrl").unwrap();

    assert_eq!(fetched.control_id, "test.ctrl");
    assert_eq!(fetched.status, "effective");
    assert_eq!(fetched.confidence, "high");
}

#[test]
fn storage_schedule_crud() {
    let store = make_store();
    let schedule = make_schedule();
    let id = schedule.id.clone();

    store.store_schedule(&schedule).unwrap();

    let list = store.list_schedules().unwrap();
    assert_eq!(list.len(), 1);

    let fetched = store.get_schedule(&id).unwrap();
    assert_eq!(fetched.id, id);

    store.delete_schedule(&id).unwrap();

    let list_after = store.list_schedules().unwrap();
    assert_eq!(list_after.len(), 0);
}

#[test]
fn storage_schedule_run_round_trip() {
    let store = make_store();

    let schedule = make_schedule();
    store.store_schedule(&schedule).unwrap();

    let run = ScheduleRun {
        id: Uuid::new_v4().to_string(),
        schedule_id: schedule.id.clone(),
        started_at: Utc::now(),
        completed_at: Utc::now(),
        status: RUN_STATUS_SUCCESS.to_string(),
        module_results: vec![ModuleRunResult {
            module_id: "test.module".to_string(),
            status: MODULE_STATUS_SUCCESS.to_string(),
            evidence_count: 1,
            error: String::new(),
        }],
        error: String::new(),
    };
    let run_id = run.id.clone();

    store.store_schedule_run(&run).unwrap();

    let runs = store.list_schedule_runs(&schedule.id, 10).unwrap();
    assert!(!runs.is_empty());
    assert!(runs.iter().any(|r| r.id == run_id));
}
