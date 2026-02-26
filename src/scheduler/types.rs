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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_schedule() -> Schedule {
        Schedule {
            id: "sched-1".to_string(),
            control_id: "cc6.1".to_string(),
            cron_expr: "0 * * * *".to_string(),
            modules: vec!["aws.iam".to_string()],
            max_safety_level: "safe".to_string(),
            environment_scope: "production".to_string(),
            enabled: true,
            catch_up: false,
            last_run: None,
            next_run: Some(Utc::now()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn run_status_constants() {
        assert_eq!(RUN_STATUS_SUCCESS, "success");
        assert_eq!(RUN_STATUS_PARTIAL_FAILURE, "partial_failure");
        assert_eq!(RUN_STATUS_FAILURE, "failure");
    }

    #[test]
    fn module_status_constants() {
        assert_eq!(MODULE_STATUS_SUCCESS, "success");
        assert_eq!(MODULE_STATUS_FAILURE, "failure");
        assert_eq!(MODULE_STATUS_SKIPPED, "skipped");
    }

    #[test]
    fn schedule_serde_round_trip() {
        let sched = make_schedule();
        let json = serde_json::to_string(&sched).unwrap();
        let decoded: Schedule = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.id, sched.id);
        assert_eq!(decoded.cron_expr, sched.cron_expr);
        assert_eq!(decoded.modules, sched.modules);
        assert!(decoded.enabled);
        assert!(!decoded.catch_up);
    }

    #[test]
    fn schedule_empty_control_id_omitted_in_json() {
        let mut sched = make_schedule();
        sched.control_id = String::new();
        let json = serde_json::to_string(&sched).unwrap();
        assert!(!json.contains("\"control_id\""));
    }

    #[test]
    fn schedule_run_serde() {
        let run = ScheduleRun {
            id: "run-1".to_string(),
            schedule_id: "sched-1".to_string(),
            started_at: Utc::now(),
            completed_at: Utc::now(),
            status: RUN_STATUS_SUCCESS.to_string(),
            module_results: vec![ModuleRunResult {
                module_id: "aws.iam".to_string(),
                status: MODULE_STATUS_SUCCESS.to_string(),
                evidence_count: 3,
                error: String::new(),
            }],
            error: String::new(),
        };
        let json = serde_json::to_string(&run).unwrap();
        let decoded: ScheduleRun = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.id, run.id);
        assert_eq!(decoded.module_results.len(), 1);
        assert_eq!(decoded.module_results[0].evidence_count, 3);
        assert!(!json.contains("\"error\""));
    }

    #[test]
    fn module_run_result_with_error_serde() {
        let result = ModuleRunResult {
            module_id: "mock.test".to_string(),
            status: MODULE_STATUS_FAILURE.to_string(),
            evidence_count: 0,
            error: "connection refused".to_string(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let decoded: ModuleRunResult = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.status, MODULE_STATUS_FAILURE);
        assert_eq!(decoded.error, "connection refused");
    }
}
