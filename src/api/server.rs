use anyhow::Result;
use std::sync::Arc;
use tokio::net::TcpListener;

use crate::module::Registry;
use crate::modules::{register_all_collectors, register_all_testers};
use crate::storage::SqliteStore;
use super::handlers::{AppState, router};

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
    register_all_collectors(&registry);
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

    #[test]
    fn serve_signature_compiles() {
        // Verify the function exists and has the right signature by calling
        // it with a type-check only (we don't actually run a server here).
        let _: fn(u16, Option<String>, String) -> _ = serve;
    }
}
