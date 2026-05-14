use anyhow::Result;
use std::sync::Arc;
use tokio::net::TcpListener;

use super::handlers::{router, AppState};
use crate::module::Registry;
use crate::modules::{register_all_observers, register_all_testers};
use crate::storage::SqliteStore;

/// Start the OCEAN REST API server.
///
/// Opens the SQLite store at `db_path`, registers all built-in modules, then
/// binds a TCP listener on `0.0.0.0:{port}` and serves the axum application.
///
/// This function is `async` and intended to be driven by a `tokio` runtime.
/// The CLI's `cmd_serve` creates a `tokio::runtime::Runtime` and calls
/// `block_on(serve(...))`.
pub async fn serve(port: u16, auth_token: Option<String>, db_path: String) -> Result<()> {
    let store = Arc::new(SqliteStore::open(&db_path)?);

    let registry = Arc::new(Registry::new());
    register_all_observers(&registry);
    register_all_testers(&registry);

    let state = AppState {
        store,
        registry,
        auth_token,
    };

    let app = router(state);
    let addr = format!("0.0.0.0:{port}");
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!("ocean serve listening on {addr}");
    axum::serve(listener, app).await?;
    Ok(())
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

    use crate::api::handlers::{router, AppState};
    use crate::modules::{register_all_observers, register_all_testers};

    fn make_test_state(auth_token: Option<String>) -> AppState {
        let db_path = std::env::temp_dir()
            .join(format!("ocean_srv_test_{}.db", Uuid::new_v4()))
            .to_str()
            .unwrap()
            .to_string();
        let store = Arc::new(crate::storage::SqliteStore::open(&db_path).unwrap());
        let registry = Arc::new(Registry::new());
        register_all_observers(&registry);
        register_all_testers(&registry);
        AppState {
            store,
            registry,
            auth_token,
        }
    }

    #[test]
    fn serve_signature_compiles() {
        // Verify the function exists and has the right signature by calling
        // it with a type-check only (we don't actually run a server here).
        let _: fn(u16, Option<String>, String) -> _ = serve;
    }

    #[tokio::test]
    async fn health_endpoint_returns_ok() {
        let app = router(make_test_state(None));
        let req = Request::builder()
            .uri("/api/v1/health")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn auth_middleware_rejects_without_token() {
        let app = router(make_test_state(Some("secret".to_string())));
        let req = Request::builder()
            .uri("/api/v1/health")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_middleware_accepts_correct_token() {
        let app = router(make_test_state(Some("mytoken".to_string())));
        let req = Request::builder()
            .uri("/api/v1/health")
            .header("Authorization", "Bearer mytoken")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
