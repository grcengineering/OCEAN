// Storage — Store trait + SqliteStore implementation.
pub mod sqlite;
pub mod postgres;

pub use sqlite::SqliteStore;
#[cfg(feature = "postgres")]
pub use postgres::PostgresStore;

use anyhow::Result;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::control::ControlStatus;
use crate::evidence::{ConfidenceLevel, Evidence};
use crate::scheduler::{Schedule, ScheduleRun};

/// Filters for querying evidence records.
#[derive(Debug, Default, Clone)]
pub struct EvidenceQuery {
    pub control_id: Option<String>,
    pub source: Option<String>,
    pub from_time: Option<DateTime<Utc>>,
    pub to_time: Option<DateTime<Utc>>,
    pub min_confidence: Option<ConfidenceLevel>,
    pub limit: Option<usize>,
    pub cursor: Option<String>,
}

/// The persistence interface. Implementations may use SQLite (default)
/// or any other backend that satisfies these contracts.
pub trait Store: Send + Sync {
    // --- Evidence ---
    fn store_evidence(&self, ev: &Evidence) -> Result<()>;
    fn get_evidence(&self, id: Uuid) -> Result<Evidence>;
    fn query_evidence(&self, query: &EvidenceQuery) -> Result<Vec<Evidence>>;

    // --- Control Status ---
    fn store_control_status(&self, status: &ControlStatus) -> Result<()>;
    fn get_control_status(&self, control_id: &str) -> Result<ControlStatus>;
    fn query_history(
        &self,
        control_id: &str,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<Vec<ControlStatus>>;

    // --- Schedules ---
    fn store_schedule(&self, schedule: &Schedule) -> Result<()>;
    fn get_schedule(&self, id: &str) -> Result<Schedule>;
    fn list_schedules(&self) -> Result<Vec<Schedule>>;
    fn delete_schedule(&self, id: &str) -> Result<()>;

    // --- Schedule Runs ---
    fn store_schedule_run(&self, run: &ScheduleRun) -> Result<()>;
    fn list_schedule_runs(&self, schedule_id: &str, limit: usize) -> Result<Vec<ScheduleRun>>;

    // --- Lifecycle ---
    fn prune_evidence(&self, older_than: DateTime<Utc>) -> Result<u64>;
    fn close(&self) -> Result<()>;
}

/// Open the configured storage backend.
///
/// - If `OCEAN_POSTGRES_URL` is set (and the `postgres` feature is enabled),
///   returns a [`PostgresStore`] connected to that URL.
/// - Otherwise returns a [`SqliteStore`] at the given `sqlite_path`.
pub fn open_store(sqlite_path: &str) -> Result<Box<dyn Store>> {
    #[cfg(feature = "postgres")]
    if let Ok(url) = std::env::var("OCEAN_POSTGRES_URL") {
        if !url.is_empty() {
            let pool_size: u32 = std::env::var("OCEAN_POSTGRES_POOL_SIZE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10);
            return Ok(Box::new(PostgresStore::connect(&url, pool_size)?));
        }
    }
    Ok(Box::new(SqliteStore::open(sqlite_path)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_query_default_all_none() {
        let q = EvidenceQuery::default();
        assert!(q.control_id.is_none());
        assert!(q.source.is_none());
        assert!(q.from_time.is_none());
        assert!(q.to_time.is_none());
        assert!(q.min_confidence.is_none());
        assert!(q.limit.is_none());
        assert!(q.cursor.is_none());
    }

    #[test]
    fn evidence_query_with_fields() {
        let q = EvidenceQuery {
            control_id: Some("cc6.1".to_string()),
            limit: Some(50),
            ..Default::default()
        };
        assert_eq!(q.control_id.as_deref(), Some("cc6.1"));
        assert_eq!(q.limit, Some(50));
        assert!(q.from_time.is_none());
    }
}
