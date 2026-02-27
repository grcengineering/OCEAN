use axum::{
    extract::{Path, Query, State},
    http::{header::AUTHORIZATION, HeaderMap, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{delete, get},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;

use crate::module::Registry;
use crate::storage::{EvidenceQuery, SqliteStore, Store};

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

/// Shared state injected into every axum handler.
#[derive(Clone)]
pub struct AppState {
    pub store: Arc<SqliteStore>,
    pub registry: Arc<Registry>,
    /// When `Some`, all requests must carry `Authorization: Bearer <token>`.
    pub auth_token: Option<String>,
}

// ---------------------------------------------------------------------------
// Auth middleware
// ---------------------------------------------------------------------------

pub async fn auth_middleware(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    if let Some(expected) = &state.auth_token {
        let provided = headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "));
        if provided != Some(expected.as_str()) {
            return Err(StatusCode::UNAUTHORIZED);
        }
    }
    Ok(next.run(request).await)
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/evidence", get(list_evidence))
        .route("/api/v1/evidence/:id", get(get_evidence))
        .route("/api/v1/controls/:id/status", get(get_control_status))
        .route("/api/v1/controls/:id/history", get(get_control_history))
        .route("/api/v1/modules", get(list_modules))
        .route(
            "/api/v1/schedules",
            get(list_schedules).post(create_schedule),
        )
        .route("/api/v1/schedules/:id", delete(delete_schedule))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Error helper
// ---------------------------------------------------------------------------

fn server_error(e: anyhow::Error) -> (StatusCode, Json<Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": e.to_string()})),
    )
}

// ---------------------------------------------------------------------------
// GET /api/v1/health
// ---------------------------------------------------------------------------

pub async fn health() -> impl IntoResponse {
    Json(json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

// ---------------------------------------------------------------------------
// GET /api/v1/evidence
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct EvidenceParams {
    pub control_id: Option<String>,
    pub source: Option<String>,
    pub limit: Option<usize>,
}

pub async fn list_evidence(
    State(state): State<AppState>,
    Query(params): Query<EvidenceParams>,
) -> impl IntoResponse {
    let query = EvidenceQuery {
        control_id: params.control_id,
        source: params.source,
        limit: params.limit,
        ..Default::default()
    };
    match state.store.query_evidence(&query) {
        Ok(records) => (StatusCode::OK, Json(json!(records))),
        Err(e) => {
            let (s, j) = server_error(e);
            (s, j)
        }
    }
}

// ---------------------------------------------------------------------------
// GET /api/v1/evidence/:id
// ---------------------------------------------------------------------------

pub async fn get_evidence(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let uuid = match id.parse::<Uuid>() {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid UUID"})),
            )
        }
    };
    match state.store.get_evidence(uuid) {
        Ok(ev) => (StatusCode::OK, Json(json!(ev))),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("not found") || msg.contains("no rows") {
                (StatusCode::NOT_FOUND, Json(json!({"error": "not found"})))
            } else {
                let (s, j) = server_error(e);
                (s, j)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// GET /api/v1/controls/:id/status
// ---------------------------------------------------------------------------

pub async fn get_control_status(
    State(state): State<AppState>,
    Path(control_id): Path<String>,
) -> impl IntoResponse {
    match state.store.get_control_status(&control_id) {
        Ok(status) => (StatusCode::OK, Json(json!(status))),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("not found") || msg.contains("no rows") {
                (StatusCode::NOT_FOUND, Json(json!({"error": "not found"})))
            } else {
                let (s, j) = server_error(e);
                (s, j)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// GET /api/v1/controls/:id/history
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct HistoryParams {
    pub from: Option<String>,
    pub to: Option<String>,
}

fn parse_dt(s: &str) -> Option<DateTime<Utc>> {
    // Try RFC3339 first, then YYYY-MM-DD
    if let Ok(dt) = s.parse::<DateTime<Utc>>() {
        return Some(dt);
    }
    if let Ok(date) = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        use chrono::TimeZone;
        return Some(Utc.from_utc_datetime(&date.and_hms_opt(0, 0, 0)?));
    }
    None
}

pub async fn get_control_history(
    State(state): State<AppState>,
    Path(control_id): Path<String>,
    Query(params): Query<HistoryParams>,
) -> impl IntoResponse {
    let now = Utc::now();
    let from = params
        .from
        .as_deref()
        .and_then(parse_dt)
        .unwrap_or_else(|| now - chrono::Duration::days(30));
    let to = params.to.as_deref().and_then(parse_dt).unwrap_or(now);

    match state.store.query_history(&control_id, from, to) {
        Ok(history) => (StatusCode::OK, Json(json!(history))),
        Err(e) => {
            let (s, j) = server_error(e);
            (s, j)
        }
    }
}

// ---------------------------------------------------------------------------
// GET /api/v1/modules
// ---------------------------------------------------------------------------

pub async fn list_modules(State(state): State<AppState>) -> impl IntoResponse {
    let modules = state.registry.list_modules();
    Json(json!(modules))
}

// ---------------------------------------------------------------------------
// GET /api/v1/schedules
// ---------------------------------------------------------------------------

pub async fn list_schedules(State(state): State<AppState>) -> impl IntoResponse {
    match state.store.list_schedules() {
        Ok(schedules) => (StatusCode::OK, Json(json!(schedules))),
        Err(e) => {
            let (s, j) = server_error(e);
            (s, j)
        }
    }
}

// ---------------------------------------------------------------------------
// POST /api/v1/schedules
// ---------------------------------------------------------------------------

#[derive(Deserialize, Serialize)]
pub struct CreateScheduleRequest {
    pub cron_expr: String,
    pub modules: Vec<String>,
    pub max_safety_level: String,
    pub environment_scope: String,
    #[serde(default)]
    pub control_id: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub catch_up: bool,
}

fn default_true() -> bool {
    true
}

pub async fn create_schedule(
    State(state): State<AppState>,
    Json(body): Json<CreateScheduleRequest>,
) -> impl IntoResponse {
    // Validate cron expression before persisting.
    if let Err(e) = crate::scheduler::cron::parse_cron(&body.cron_expr) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": e.to_string()})),
        );
    }

    let now = Utc::now();
    let next_run = crate::scheduler::cron::next_run(&body.cron_expr, &now).ok();

    let schedule = crate::scheduler::Schedule {
        id: Uuid::new_v4().to_string(),
        control_id: body.control_id,
        cron_expr: body.cron_expr,
        modules: body.modules,
        max_safety_level: body.max_safety_level,
        environment_scope: body.environment_scope,
        enabled: body.enabled,
        catch_up: body.catch_up,
        last_run: None,
        next_run,
        created_at: now,
        updated_at: now,
    };

    match state.store.store_schedule(&schedule) {
        Ok(()) => (StatusCode::CREATED, Json(json!(schedule))),
        Err(e) => {
            let (s, j) = server_error(e);
            (s, j)
        }
    }
}

// ---------------------------------------------------------------------------
// DELETE /api/v1/schedules/:id
// ---------------------------------------------------------------------------

pub async fn delete_schedule(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.store.delete_schedule(&id) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("not found") || msg.contains("no rows") {
                (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response()
            } else {
                server_error(e).into_response()
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;
    use uuid::Uuid;

    use crate::modules::{register_all_collectors, register_all_testers};
    use crate::storage::SqliteStore;

    fn make_state() -> AppState {
        let dir = std::env::temp_dir();
        let path = dir
            .join(format!("ocean_api_{}.db", Uuid::new_v4()))
            .to_str()
            .unwrap()
            .to_string();
        let store = Arc::new(SqliteStore::open(&path).unwrap());
        let registry = Arc::new(Registry::new());
        register_all_collectors(&registry);
        register_all_testers(&registry);
        AppState {
            store,
            registry,
            auth_token: None,
        }
    }

    async fn oneshot_get(path: &str, state: AppState) -> axum::response::Response {
        let app = router(state);
        app.oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn health_returns_200() {
        let state = make_state();
        let res = oneshot_get("/api/v1/health", state).await;
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn health_body_has_status_ok() {
        let state = make_state();
        let app = router(state);
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["status"], "ok");
    }

    #[tokio::test]
    async fn list_evidence_empty_returns_200() {
        let state = make_state();
        let res = oneshot_get("/api/v1/evidence", state).await;
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn get_evidence_bad_id_returns_400() {
        let state = make_state();
        let res = oneshot_get("/api/v1/evidence/not-a-uuid", state).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_evidence_unknown_id_returns_404() {
        let state = make_state();
        let res = oneshot_get(&format!("/api/v1/evidence/{}", Uuid::new_v4()), state).await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn list_modules_returns_all() {
        let state = make_state();
        let app = router(state);
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/modules")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(v.as_array().map_or(0, |a| a.len()) >= 9);
    }

    #[tokio::test]
    async fn list_schedules_empty_returns_200() {
        let state = make_state();
        let res = oneshot_get("/api/v1/schedules", state).await;
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn create_schedule_invalid_cron_returns_400() {
        let state = make_state();
        let app = router(state);
        let body = serde_json::to_string(&json!({
            "cron_expr": "bad_cron",
            "modules": ["mock.test"],
            "max_safety_level": "safe",
            "environment_scope": "production",
        }))
        .unwrap();
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/schedules")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn create_and_delete_schedule() {
        let state = make_state();
        let app = router(state);

        let body = serde_json::to_string(&json!({
            "cron_expr": "0 * * * *",
            "modules": ["mock.test"],
            "max_safety_level": "safe",
            "environment_scope": "production",
        }))
        .unwrap();

        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/schedules")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);

        let resp_body = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let created: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
        let id = created["id"].as_str().unwrap().to_string();

        let del_res = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/v1/schedules/{id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(del_res.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn auth_middleware_rejects_missing_token() {
        let dir = std::env::temp_dir();
        let path = dir
            .join(format!("ocean_api_auth_{}.db", Uuid::new_v4()))
            .to_str()
            .unwrap()
            .to_string();
        let state = AppState {
            store: Arc::new(SqliteStore::open(&path).unwrap()),
            registry: Arc::new(Registry::new()),
            auth_token: Some("secret-token".to_string()),
        };
        let res = oneshot_get("/api/v1/health", state).await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_middleware_accepts_valid_token() {
        let dir = std::env::temp_dir();
        let path = dir
            .join(format!("ocean_api_auth2_{}.db", Uuid::new_v4()))
            .to_str()
            .unwrap()
            .to_string();
        let state = AppState {
            store: Arc::new(SqliteStore::open(&path).unwrap()),
            registry: Arc::new(Registry::new()),
            auth_token: Some("my-token".to_string()),
        };
        let app = router(state);
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/health")
                    .header("Authorization", "Bearer my-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }
}
