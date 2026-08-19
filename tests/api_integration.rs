/// GRC-17 §5.4 — API integration tests (REST round-trip + auth enforcement)
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use tower::ServiceExt;
use uuid::Uuid;

use ocean::api::handlers::{router, AppState};
use ocean::evidence::{
    ConfidenceLevel, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo, StatusId,
};
use ocean::module::Registry;
use ocean::modules::{register_all_observers, register_all_testers};
use ocean::storage::{SqliteStore, Store};

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn make_state_no_auth() -> AppState {
    let store = Arc::new(SqliteStore::open(":memory:").unwrap());
    let registry = Arc::new(Registry::new());
    register_all_observers(&registry);
    register_all_testers(&registry);
    AppState {
        store,
        registry,
        auth_token: None,
    }
}

fn make_state_with_auth(token: &str) -> AppState {
    let store = Arc::new(SqliteStore::open(":memory:").unwrap());
    let registry = Arc::new(Registry::new());
    AppState {
        store,
        registry,
        auth_token: Some(token.to_string()),
    }
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
                name: "api.test".to_string(),
                version: "0.1.0".to_string(),
                module_type: "observer".to_string(),
            },
            source: SourceInfo {
                system: "mock".to_string(),
                api_version: "v1".to_string(),
                endpoint: "mock://api-test".to_string(),
            },
            original_time: None,
            processed_time: Utc::now(),
            safety_classification: None,
        },
        observables: vec![Observable {
            obs_type: "resource".to_string(),
            value: "api-resource".to_string(),
            name: String::new(),
        }],
        status_id: StatusId::Effective,
        status: "effective".to_string(),
        raw_data: serde_json::json!({"api_test": true}),
        findings: vec![Finding {
            title: "API Test Finding".to_string(),
            description: "Integration API finding".to_string(),
            severity_id: 0,
        }],
        test_transcript: None,
        enrichments: vec![],
    }
}

async fn get(state: AppState, path: &str) -> axum::response::Response {
    router(state)
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap()
}

async fn get_with_auth(state: AppState, path: &str, token: &str) -> axum::response::Response {
    router(state)
        .oneshot(
            Request::builder()
                .uri(path)
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn body_json(res: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

// ─── 5.4: Health endpoint ────────────────────────────────────────────────────

#[tokio::test]
async fn api_health_returns_200() {
    let res = get(make_state_no_auth(), "/api/v1/health").await;
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn api_health_body_has_status_ok() {
    let res = get(make_state_no_auth(), "/api/v1/health").await;
    let body = body_json(res).await;
    assert_eq!(body["status"], "ok");
}

// ─── 5.4: Evidence round-trip ────────────────────────────────────────────────

/// Store evidence directly, then retrieve it via the API by ID.
#[tokio::test]
async fn api_evidence_store_and_retrieve_by_id() {
    let state = make_state_no_auth();
    let ev = make_evidence("API-CTRL-1");
    let ev_id = ev.id;
    state.store.store_evidence(&ev).unwrap();

    let res = get(state, &format!("/api/v1/evidence/{}", ev_id)).await;
    assert_eq!(res.status(), StatusCode::OK);

    let body = body_json(res).await;
    assert_eq!(body["id"].as_str().unwrap(), ev_id.to_string());
    assert_eq!(body["control_id"].as_str().unwrap(), "API-CTRL-1");
}

/// List evidence returns all stored records.
#[tokio::test]
async fn api_evidence_list_returns_stored_records() {
    let state = make_state_no_auth();
    state
        .store
        .store_evidence(&make_evidence("API-CTRL-2"))
        .unwrap();
    state
        .store
        .store_evidence(&make_evidence("API-CTRL-2"))
        .unwrap();

    let res = get(state, "/api/v1/evidence?control_id=API-CTRL-2").await;
    assert_eq!(res.status(), StatusCode::OK);

    let body = body_json(res).await;
    let arr = body.as_array().unwrap();
    assert_eq!(arr.len(), 2);
}

/// Unknown evidence ID returns 404.
#[tokio::test]
async fn api_evidence_unknown_id_returns_404() {
    let state = make_state_no_auth();
    let fake_id = Uuid::new_v4();
    let res = get(state, &format!("/api/v1/evidence/{}", fake_id)).await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

/// Invalid UUID format returns 400.
#[tokio::test]
async fn api_evidence_bad_id_format_returns_400() {
    let state = make_state_no_auth();
    let res = get(state, "/api/v1/evidence/not-a-uuid").await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

// ─── 5.4: Module listing ─────────────────────────────────────────────────────

/// Module list includes all registered modules.
#[tokio::test]
async fn api_modules_list_includes_registered() {
    let res = get(make_state_no_auth(), "/api/v1/modules").await;
    assert_eq!(res.status(), StatusCode::OK);

    let body = body_json(res).await;
    let modules = body.as_array().unwrap();
    assert!(
        !modules.is_empty(),
        "at least one module must be registered"
    );

    // Check that mock.test is present (always registered).
    let has_mock = modules
        .iter()
        .any(|m| m.get("id").and_then(|v| v.as_str()) == Some("mock.test"));
    assert!(has_mock, "mock.test observer must appear in module list");
}

// ─── 5.4: Schedule lifecycle ─────────────────────────────────────────────────

/// POST schedule → GET schedules → DELETE → GET confirms removal.
#[tokio::test]
async fn api_schedule_create_list_delete() {
    let state = make_state_no_auth();

    // Create a schedule.
    let app = router(state);
    let create_req = Request::builder()
        .method("POST")
        .uri("/api/v1/schedules")
        .header("Content-Type", "application/json")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({
                "control_id": "API-SCHED-1",
                "cron_expr": "0 * * * *",
                "modules": ["mock.test"],
                "max_safety_level": "safe",
                "environment_scope": "production"
            }))
            .unwrap(),
        ))
        .unwrap();

    let create_res = app.clone().oneshot(create_req).await.unwrap();
    assert_eq!(create_res.status(), StatusCode::CREATED);

    let create_body = body_json(create_res).await;
    let schedule_id = create_body["id"].as_str().unwrap().to_string();

    // List schedules — should contain the new one.
    let list_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/schedules")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list_res.status(), StatusCode::OK);
    let list_body = body_json(list_res).await;
    let schedules = list_body.as_array().unwrap();
    assert!(
        schedules
            .iter()
            .any(|s| s["id"].as_str() == Some(&schedule_id)),
        "created schedule must appear in list"
    );

    // Delete the schedule.
    let delete_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(&format!("/api/v1/schedules/{}", schedule_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(delete_res.status(), StatusCode::NO_CONTENT);

    // List again — should be gone.
    let list_after = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/schedules")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let list_after_body = body_json(list_after).await;
    let schedules_after = list_after_body.as_array().unwrap();
    assert!(
        !schedules_after
            .iter()
            .any(|s| s["id"].as_str() == Some(&schedule_id)),
        "deleted schedule must not appear in list"
    );
}

// ─── 5.4: Auth enforcement ───────────────────────────────────────────────────

/// When auth token is configured, missing token returns 401.
#[tokio::test]
async fn api_auth_missing_token_returns_401() {
    let state = make_state_with_auth("secret-token");
    let res = get(state, "/api/v1/health").await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

/// When auth token is configured, correct token is accepted.
#[tokio::test]
async fn api_auth_valid_token_returns_200() {
    let state = make_state_with_auth("secret-token");
    let res = get_with_auth(state, "/api/v1/health", "secret-token").await;
    assert_eq!(res.status(), StatusCode::OK);
}

/// Wrong token is rejected.
#[tokio::test]
async fn api_auth_wrong_token_returns_401() {
    let state = make_state_with_auth("correct-token");
    let res = get_with_auth(state, "/api/v1/health", "wrong-token").await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}
