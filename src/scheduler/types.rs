use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const RUN_STATUS_SUCCESS: &str = "success";
pub const RUN_STATUS_PARTIAL_FAILURE: &str = "partial_failure";
pub const RUN_STATUS_FAILURE: &str = "failure";

pub const MODULE_STATUS_SUCCESS: &str = "success";
pub const MODULE_STATUS_FAILURE: &str = "failure";
pub const MODULE_STATUS_SKIPPED: &str = "skipped";

/// A recurring job that collects evidence for one or more controls.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Schedule {
    pub id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub control_id: String,
    pub cron_expr: String,
    pub modules: Vec<String>,
    pub max_safety_level: String,
    pub environment_scope: String,
    pub enabled: bool,
    pub catch_up: bool,
    pub last_run: Option<DateTime<Utc>>,
    pub next_run: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Records the outcome of a single execution of a schedule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleRun {
    pub id: String,
    pub schedule_id: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    /// "success", "partial_failure", "failure"
    pub status: String,
    pub module_results: Vec<ModuleRunResult>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
}

/// The outcome of executing a single module within a scheduled run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleRunResult {
    pub module_id: String,
    /// "success", "failure", "skipped"
    pub status: String,
    pub evidence_count: i32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
}
