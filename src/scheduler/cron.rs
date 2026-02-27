use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::RwLock;

use crate::scheduler::Schedule;

// ---------------------------------------------------------------------------
// Cron expression helpers
// ---------------------------------------------------------------------------

/// Normalize a 5-field or 6-field cron expression to the 7-field format
/// that the `cron` crate requires: `sec min hour dom month dow year`.
///
/// Standard 5-field (min hour dom month dow) → prepend `0`, append `*`
/// 6-field (sec min hour dom month dow)       → append `*`
/// 7-field or other                           → pass through unchanged
pub fn normalize_cron(expr: &str) -> String {
    let parts: Vec<&str> = expr.split_whitespace().collect();
    match parts.len() {
        5 => format!("0 {} *", expr),
        6 => format!("{} *", expr),
        _ => expr.to_string(),
    }
}

/// Parse and validate a cron expression. Accepts 5, 6, or 7 field formats.
pub fn parse_cron(expr: &str) -> Result<cron::Schedule> {
    let normalized = normalize_cron(expr);
    cron::Schedule::from_str(&normalized)
        .map_err(|e| anyhow!("invalid cron expression '{}': {}", expr, e))
}

/// Calculate the next run time after `after` for the given cron expression.
pub fn next_run(expr: &str, after: &DateTime<Utc>) -> Result<DateTime<Utc>> {
    let sched = parse_cron(expr)?;
    sched
        .after(after)
        .next()
        .ok_or_else(|| anyhow!("cron expression '{}' has no upcoming runs", expr))
}

// ---------------------------------------------------------------------------
// Scheduler
// ---------------------------------------------------------------------------

/// In-memory registry of scheduled jobs. Validates cron expressions on add.
///
/// This is intentionally simple: it tracks schedules and computes due times.
/// Actual execution is handled by the [`super::runner`] module. The `serve`
/// command drives the polling loop in a tokio task.
#[derive(Default)]
pub struct Scheduler {
    schedules: RwLock<HashMap<String, Schedule>>,
}

impl Scheduler {
    pub fn new() -> Self {
        Self {
            schedules: RwLock::new(HashMap::new()),
        }
    }

    /// Register a schedule, validating its cron expression.
    /// Overwrites any existing schedule with the same ID.
    pub fn add(&self, schedule: Schedule) -> Result<()> {
        parse_cron(&schedule.cron_expr)?;
        self.schedules
            .write()
            .unwrap()
            .insert(schedule.id.clone(), schedule);
        Ok(())
    }

    /// Remove a schedule by ID. Returns `true` if it existed.
    pub fn remove(&self, id: &str) -> bool {
        self.schedules.write().unwrap().remove(id).is_some()
    }

    /// List all registered schedules.
    pub fn list(&self) -> Vec<Schedule> {
        self.schedules.read().unwrap().values().cloned().collect()
    }

    /// Return all **enabled** schedules whose `next_run` is at or before `now`.
    pub fn due_now(&self, now: DateTime<Utc>) -> Vec<Schedule> {
        self.schedules
            .read()
            .unwrap()
            .values()
            .filter(|s| s.enabled)
            .filter(|s| s.next_run.is_some_and(|nr| nr <= now))
            .cloned()
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn make_schedule(id: &str, cron_expr: &str) -> Schedule {
        let now = Utc::now();
        Schedule {
            id: id.to_string(),
            control_id: String::new(),
            cron_expr: cron_expr.to_string(),
            modules: vec!["mock.test".to_string()],
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

    // --- normalize_cron ---

    #[test]
    fn normalize_5_field() {
        let n = normalize_cron("0 * * * *");
        assert_eq!(n, "0 0 * * * * *");
    }

    #[test]
    fn normalize_6_field() {
        let n = normalize_cron("0 0 * * * *");
        assert_eq!(n, "0 0 * * * * *");
    }

    #[test]
    fn normalize_7_field_unchanged() {
        let n = normalize_cron("0 0 * * * * *");
        assert_eq!(n, "0 0 * * * * *");
    }

    // --- parse_cron ---

    #[test]
    fn parse_valid_5_field() {
        assert!(parse_cron("0 * * * *").is_ok());
        assert!(parse_cron("*/15 * * * *").is_ok());
    }

    #[test]
    fn parse_valid_6_field() {
        assert!(parse_cron("0 0 * * * *").is_ok());
    }

    #[test]
    fn parse_invalid_expression() {
        assert!(parse_cron("not_a_cron").is_err());
        assert!(parse_cron("99 99 99 99 99").is_err());
    }

    // --- next_run ---

    #[test]
    fn next_run_returns_future_time() {
        let now = Utc::now();
        let next = next_run("0 * * * *", &now).unwrap();
        assert!(next > now, "next_run should be in the future");
    }

    #[test]
    fn next_run_invalid_expr() {
        let now = Utc::now();
        assert!(next_run("bad_expr", &now).is_err());
    }

    // --- Scheduler ---

    #[test]
    fn add_and_list() {
        let s = Scheduler::new();
        let sched = make_schedule("s1", "0 * * * *");
        s.add(sched).unwrap();
        assert_eq!(s.list().len(), 1);
    }

    #[test]
    fn add_invalid_cron_fails() {
        let s = Scheduler::new();
        let mut sched = make_schedule("s1", "bad_cron");
        sched.cron_expr = "bad_cron".to_string();
        assert!(s.add(sched).is_err());
    }

    #[test]
    fn remove_existing() {
        let s = Scheduler::new();
        s.add(make_schedule("s1", "0 * * * *")).unwrap();
        assert!(s.remove("s1"));
        assert_eq!(s.list().len(), 0);
    }

    #[test]
    fn remove_nonexistent_returns_false() {
        let s = Scheduler::new();
        assert!(!s.remove("nope"));
    }

    #[test]
    fn due_now_returns_past_next_run() {
        let s = Scheduler::new();
        let mut sched = make_schedule("s1", "0 * * * *");
        // Set next_run to 1 hour ago
        sched.next_run = Some(Utc::now() - chrono::Duration::hours(1));
        s.add(sched).unwrap();

        let due = s.due_now(Utc::now());
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].id, "s1");
    }

    #[test]
    fn due_now_skips_future_schedule() {
        let s = Scheduler::new();
        let mut sched = make_schedule("s1", "0 * * * *");
        sched.next_run = Some(Utc::now() + chrono::Duration::hours(1));
        s.add(sched).unwrap();

        assert_eq!(s.due_now(Utc::now()).len(), 0);
    }

    #[test]
    fn due_now_skips_disabled_schedule() {
        let s = Scheduler::new();
        let mut sched = make_schedule("s1", "0 * * * *");
        sched.next_run = Some(Utc::now() - chrono::Duration::hours(1));
        sched.enabled = false;
        s.add(sched).unwrap();

        assert_eq!(s.due_now(Utc::now()).len(), 0);
    }

    #[test]
    fn add_overwrites_existing_id() {
        let s = Scheduler::new();
        let mut sched1 = make_schedule("s1", "0 * * * *");
        sched1.control_id = "cc6.1".to_string();
        s.add(sched1).unwrap();

        let mut sched2 = make_schedule("s1", "*/30 * * * *");
        sched2.control_id = "cc6.2".to_string();
        s.add(sched2).unwrap();

        let list = s.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].control_id, "cc6.2");
    }
}
