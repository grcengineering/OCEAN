use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

use crate::module::{AutoAuthorizer, EnvironmentScope, Executor, Registry, TestConfig};
use crate::scheduler::{
    ModuleRunResult, Schedule, ScheduleRun, MODULE_STATUS_FAILURE, MODULE_STATUS_SKIPPED,
    MODULE_STATUS_SUCCESS, RUN_STATUS_FAILURE, RUN_STATUS_PARTIAL_FAILURE, RUN_STATUS_SUCCESS,
};
use crate::storage::Store;

// ---------------------------------------------------------------------------
// Safety level ordering
// ---------------------------------------------------------------------------

fn safety_level_rank(level: &str) -> i32 {
    match level.to_lowercase().as_str() {
        "safe" => 0,
        "observable" => 1,
        "reversible" => 2,
        "destructive" => 3,
        _ => -1,
    }
}

/// Returns true if `classification` is within the allowed `max_level`.
pub fn safety_level_allows(max_level: &str, classification: &str) -> bool {
    let max = safety_level_rank(max_level);
    let cls = safety_level_rank(classification);
    max >= 0 && cls >= 0 && cls <= max
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

/// Execute all modules configured in a schedule, persist evidence, and return
/// a ScheduleRun record. Module-level failures are captured in the run results
/// rather than propagated as errors.
pub fn execute_schedule(
    schedule: &Schedule,
    store: &dyn Store,
    registry: &Arc<Registry>,
) -> ScheduleRun {
    let started_at = Utc::now();
    let run_id = Uuid::new_v4().to_string();
    let module_config: HashMap<String, String> = std::env::vars().collect();
    let executor = Executor::new(Arc::clone(registry));

    let mut results = Vec::with_capacity(schedule.modules.len());
    let mut success_count = 0usize;
    let mut fail_count = 0usize;
    let mut skip_count = 0usize;

    for mod_id in &schedule.modules {
        let result = run_one_module(mod_id, schedule, &module_config, store, &executor, registry);
        match result.status.as_str() {
            s if s == MODULE_STATUS_SUCCESS => success_count += 1,
            s if s == MODULE_STATUS_FAILURE => fail_count += 1,
            _ => skip_count += 1,
        }
        results.push(result);
    }

    let run_status = if fail_count == 0 && skip_count == 0 {
        RUN_STATUS_SUCCESS
    } else if success_count > 0 {
        RUN_STATUS_PARTIAL_FAILURE
    } else {
        RUN_STATUS_FAILURE
    }
    .to_string();

    let run = ScheduleRun {
        id: run_id,
        schedule_id: schedule.id.clone(),
        started_at,
        completed_at: Utc::now(),
        status: run_status,
        module_results: results,
        error: String::new(),
    };

    // Best-effort persist of the run record.
    let _ = store.store_schedule_run(&run);

    run
}

// ---------------------------------------------------------------------------
// Internal: run a single module
// ---------------------------------------------------------------------------

fn run_one_module(
    mod_id: &str,
    schedule: &Schedule,
    module_config: &HashMap<String, String>,
    store: &dyn Store,
    executor: &Executor,
    registry: &Arc<Registry>,
) -> ModuleRunResult {
    // Determine if this is a tester or collector by checking the registry.
    let is_tester = registry.get_tester(mod_id).is_ok();

    if is_tester {
        run_tester(mod_id, schedule, module_config, store, executor, registry)
    } else {
        run_collector(mod_id, module_config, store, executor)
    }
}

fn run_collector(
    mod_id: &str,
    module_config: &HashMap<String, String>,
    store: &dyn Store,
    executor: &Executor,
) -> ModuleRunResult {
    match executor.execute_collector(mod_id, module_config) {
        Err(e) => ModuleRunResult {
            module_id: mod_id.to_string(),
            status: MODULE_STATUS_FAILURE.to_string(),
            evidence_count: 0,
            error: e.to_string(),
        },
        Ok(evidences) => {
            let count = evidences.len() as i32;
            let mut store_err = String::new();
            for ev in &evidences {
                if let Err(e) = store.store_evidence(ev) {
                    store_err = e.to_string();
                    break;
                }
            }
            if store_err.is_empty() {
                ModuleRunResult {
                    module_id: mod_id.to_string(),
                    status: MODULE_STATUS_SUCCESS.to_string(),
                    evidence_count: count,
                    error: String::new(),
                }
            } else {
                ModuleRunResult {
                    module_id: mod_id.to_string(),
                    status: MODULE_STATUS_FAILURE.to_string(),
                    evidence_count: count,
                    error: format!("evidence store error: {store_err}"),
                }
            }
        }
    }
}

fn run_tester(
    mod_id: &str,
    schedule: &Schedule,
    module_config: &HashMap<String, String>,
    store: &dyn Store,
    executor: &Executor,
    registry: &Arc<Registry>,
) -> ModuleRunResult {
    // Check safety level before running.
    let tester = match registry.get_tester(mod_id) {
        Ok(t) => t,
        Err(e) => {
            return ModuleRunResult {
                module_id: mod_id.to_string(),
                status: MODULE_STATUS_FAILURE.to_string(),
                evidence_count: 0,
                error: e.to_string(),
            }
        }
    };

    let safety_class = tester.safety_class().to_string();
    if !safety_level_allows(&schedule.max_safety_level, &safety_class) {
        return ModuleRunResult {
            module_id: mod_id.to_string(),
            status: MODULE_STATUS_SKIPPED.to_string(),
            evidence_count: 0,
            error: format!(
                "skipped: safety class '{}' exceeds schedule max '{}'",
                safety_class, schedule.max_safety_level,
            ),
        };
    }

    let scope = match schedule.environment_scope.to_lowercase().as_str() {
        "staging" | "stage" => EnvironmentScope::Staging,
        "isolated" | "lab" => EnvironmentScope::Isolated,
        _ => EnvironmentScope::Production,
    };

    let cfg = TestConfig {
        module_config: module_config.clone(),
        target_environment: scope,
        authorizer: Box::new(AutoAuthorizer),
    };

    match executor.execute_tester(mod_id, &cfg) {
        Err(e) => ModuleRunResult {
            module_id: mod_id.to_string(),
            status: MODULE_STATUS_FAILURE.to_string(),
            evidence_count: 0,
            error: e.to_string(),
        },
        Ok(evidences) => {
            let count = evidences.len() as i32;
            let mut store_err = String::new();
            for ev in &evidences {
                if let Err(e) = store.store_evidence(ev) {
                    store_err = e.to_string();
                    break;
                }
            }
            if store_err.is_empty() {
                ModuleRunResult {
                    module_id: mod_id.to_string(),
                    status: MODULE_STATUS_SUCCESS.to_string(),
                    evidence_count: count,
                    error: String::new(),
                }
            } else {
                ModuleRunResult {
                    module_id: mod_id.to_string(),
                    status: MODULE_STATUS_FAILURE.to_string(),
                    evidence_count: count,
                    error: format!("evidence store error: {store_err}"),
                }
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
    use crate::modules::{register_all_collectors, register_all_testers};
    use crate::storage::SqliteStore;
    use chrono::Utc;

    fn make_store() -> SqliteStore {
        let dir = std::env::temp_dir();
        let path = dir
            .join(format!("ocean_runner_{}.db", Uuid::new_v4()))
            .to_str()
            .unwrap()
            .to_string();
        SqliteStore::open(&path).unwrap()
    }

    fn make_registry() -> Arc<Registry> {
        let r = Arc::new(Registry::new());
        register_all_collectors(&r);
        register_all_testers(&r);
        r
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

    #[test]
    fn safety_level_allows_same() {
        assert!(safety_level_allows("safe", "safe"));
        assert!(safety_level_allows("observable", "observable"));
    }

    #[test]
    fn safety_level_allows_lower() {
        assert!(safety_level_allows("observable", "safe"));
        assert!(safety_level_allows("reversible", "safe"));
        assert!(safety_level_allows("destructive", "reversible"));
    }

    #[test]
    fn safety_level_disallows_higher() {
        assert!(!safety_level_allows("safe", "observable"));
        assert!(!safety_level_allows("safe", "destructive"));
        assert!(!safety_level_allows("observable", "reversible"));
    }

    #[test]
    fn safety_level_unknown_returns_false() {
        assert!(!safety_level_allows("unknown", "safe"));
        assert!(!safety_level_allows("safe", "unknown"));
    }

    #[test]
    fn execute_schedule_mock_collector_success() {
        let store = make_store();
        let registry = make_registry();
        let schedule = make_schedule(vec!["mock.test"]);

        let run = execute_schedule(&schedule, &store, &registry);

        assert_eq!(run.schedule_id, schedule.id);
        assert_eq!(run.module_results.len(), 1);
        assert_eq!(run.module_results[0].status, MODULE_STATUS_SUCCESS);
        assert!(run.module_results[0].evidence_count > 0);
        assert_eq!(run.status, RUN_STATUS_SUCCESS);
    }

    #[test]
    fn execute_schedule_unknown_module_fails() {
        let store = make_store();
        let registry = make_registry();
        let schedule = make_schedule(vec!["nonexistent.module"]);

        let run = execute_schedule(&schedule, &store, &registry);

        assert_eq!(run.module_results[0].status, MODULE_STATUS_FAILURE);
        assert_eq!(run.status, RUN_STATUS_FAILURE);
    }

    #[test]
    fn execute_schedule_tester_skipped_safety_exceeded() {
        let store = make_store();
        let registry = make_registry();
        // mock.safety_test is SafetyClassification::Safe — should pass
        // but set max_safety to "none" equivalent (low threshold)
        let mut schedule = make_schedule(vec!["mock.safety_test"]);
        // Set max_safety to an unknown level that maps to -1 → disallows all
        schedule.max_safety_level = "none_allowed".to_string();

        let run = execute_schedule(&schedule, &store, &registry);
        assert_eq!(run.module_results[0].status, MODULE_STATUS_SKIPPED);
    }

    #[test]
    fn execute_schedule_mixed_modules() {
        let store = make_store();
        let registry = make_registry();
        let schedule = make_schedule(vec!["mock.test", "mock.network"]);

        let run = execute_schedule(&schedule, &store, &registry);

        assert_eq!(run.module_results.len(), 2);
        for result in &run.module_results {
            assert_eq!(result.status, MODULE_STATUS_SUCCESS);
        }
        assert_eq!(run.status, RUN_STATUS_SUCCESS);
    }

    #[test]
    fn execute_schedule_partial_failure() {
        let store = make_store();
        let registry = make_registry();
        let schedule = make_schedule(vec!["mock.test", "nonexistent.module"]);

        let run = execute_schedule(&schedule, &store, &registry);

        assert_eq!(run.status, RUN_STATUS_PARTIAL_FAILURE);
        let success = run
            .module_results
            .iter()
            .filter(|r| r.status == MODULE_STATUS_SUCCESS)
            .count();
        let fail = run
            .module_results
            .iter()
            .filter(|r| r.status == MODULE_STATUS_FAILURE)
            .count();
        assert_eq!(success, 1);
        assert_eq!(fail, 1);
    }

    #[test]
    fn execute_schedule_run_record_stored() {
        let store = make_store();
        let registry = make_registry();
        let schedule = make_schedule(vec!["mock.test"]);

        // Store the schedule first (schedule_runs FK references schedules).
        use crate::storage::Store;
        store.store_schedule(&schedule).unwrap();

        let run = execute_schedule(&schedule, &store, &registry);

        let runs = store.list_schedule_runs(&schedule.id, 10).unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].id, run.id);
    }
}
