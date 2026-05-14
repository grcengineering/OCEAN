use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json;
use std::path::Path;
use std::sync::Mutex;
use uuid::Uuid;

use crate::control::ControlStatus;
use crate::evidence::{
    ConfidenceLevel, Enrichment, Evidence, Finding, Metadata, Observable, StatusId,
};
use crate::scheduler::{ModuleRunResult, Schedule, ScheduleRun};
use crate::storage::{EvidenceQuery, Store};

/// SQLite-backed implementation of the Store trait.
/// Uses a Mutex for connection sharing — suitable for single-process CLI use.
/// WAL mode is enabled for better concurrent read performance.
pub struct SqliteStore {
    conn: Mutex<Connection>,
}

impl SqliteStore {
    /// Open or create a SQLite database at the given path and run migrations.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating storage directory: {}", parent.display()))?;
        }

        let conn = Connection::open(path)
            .with_context(|| format!("opening SQLite database: {}", path.display()))?;

        // WAL mode + busy timeout for better concurrency.
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON;",
        )?;

        let store = Self {
            conn: Mutex::new(conn),
        };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS evidence (
                id                   TEXT PRIMARY KEY,
                control_id           TEXT NOT NULL,
                class_uid            INTEGER NOT NULL,
                category_uid         INTEGER NOT NULL,
                activity_id          INTEGER NOT NULL,
                timestamp            TEXT NOT NULL,
                confidence_level     TEXT NOT NULL,
                metadata_json        TEXT NOT NULL,
                observables_json     TEXT NOT NULL DEFAULT '[]',
                status_id            INTEGER NOT NULL,
                status               TEXT NOT NULL,
                raw_data             TEXT NOT NULL DEFAULT 'null',
                findings_json        TEXT NOT NULL DEFAULT '[]',
                test_transcript_json TEXT,
                enrichments_json     TEXT,
                created_at           TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_evidence_control_id ON evidence(control_id);
            CREATE INDEX IF NOT EXISTS idx_evidence_timestamp  ON evidence(timestamp);

            CREATE TABLE IF NOT EXISTS control_status (
                id                 TEXT PRIMARY KEY,
                control_id         TEXT NOT NULL,
                timestamp          TEXT NOT NULL,
                status             TEXT NOT NULL,
                confidence         TEXT NOT NULL,
                evidence_ids_json  TEXT NOT NULL DEFAULT '[]',
                evaluation_details TEXT NOT NULL DEFAULT '',
                created_at         TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_control_status_control_id ON control_status(control_id);
            CREATE INDEX IF NOT EXISTS idx_control_status_timestamp   ON control_status(timestamp);

            CREATE TABLE IF NOT EXISTS schedules (
                id                TEXT PRIMARY KEY,
                control_id        TEXT NOT NULL DEFAULT '',
                cron_expr         TEXT NOT NULL,
                modules_json      TEXT NOT NULL,
                enabled           INTEGER NOT NULL DEFAULT 1,
                max_safety_level  TEXT NOT NULL DEFAULT 'safe',
                environment_scope TEXT NOT NULL DEFAULT 'production',
                catch_up          INTEGER NOT NULL DEFAULT 0,
                last_run          TEXT,
                next_run          TEXT,
                created_at        TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at        TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS schedule_runs (
                id                  TEXT PRIMARY KEY,
                schedule_id         TEXT NOT NULL,
                started_at          TEXT NOT NULL,
                completed_at        TEXT NOT NULL,
                status              TEXT NOT NULL,
                module_results_json TEXT NOT NULL DEFAULT '[]',
                error_message       TEXT NOT NULL DEFAULT '',
                created_at          TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (schedule_id) REFERENCES schedules(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_schedule_runs_schedule_id ON schedule_runs(schedule_id);
            CREATE INDEX IF NOT EXISTS idx_schedule_runs_started_at  ON schedule_runs(started_at);
        "#,
        )?;
        Ok(())
    }
}

impl Store for SqliteStore {
    // -----------------------------------------------------------------------
    // Evidence
    // -----------------------------------------------------------------------

    fn store_evidence(&self, ev: &Evidence) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let metadata_json = serde_json::to_string(&ev.metadata)?;
        let observables_json = serde_json::to_string(&ev.observables)?;
        let findings_json = serde_json::to_string(&ev.findings)?;
        let raw_data = serde_json::to_string(&ev.raw_data)?;
        let transcript_json = ev
            .test_transcript
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let enrichments_json = if ev.enrichments.is_empty() {
            None
        } else {
            Some(serde_json::to_string(&ev.enrichments)?)
        };
        let status_id_int: i32 = ev.status_id.into();
        let confidence_str = match &ev.confidence_level {
            ConfidenceLevel::PassiveObservation => "passive_observation",
            ConfidenceLevel::ActiveVerification => "active_verification",
        };

        conn.execute(
            r#"INSERT INTO evidence (
                id, control_id, class_uid, category_uid, activity_id,
                timestamp, confidence_level, metadata_json, observables_json,
                status_id, status, raw_data, findings_json,
                test_transcript_json, enrichments_json
            ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)"#,
            params![
                ev.id.to_string(),
                ev.control_id,
                ev.class_uid,
                ev.category_uid,
                ev.activity_id,
                ev.time.to_rfc3339(),
                confidence_str,
                metadata_json,
                observables_json,
                status_id_int,
                ev.status,
                raw_data,
                findings_json,
                transcript_json,
                enrichments_json,
            ],
        )
        .context("inserting evidence")?;
        Ok(())
    }

    fn get_evidence(&self, id: Uuid) -> Result<Evidence> {
        let conn = self.conn.lock().unwrap();
        let row = conn
            .query_row(
                r#"SELECT id, control_id, class_uid, category_uid, activity_id,
                    timestamp, confidence_level, metadata_json, observables_json,
                    status_id, status, raw_data, findings_json,
                    test_transcript_json, enrichments_json
                   FROM evidence WHERE id = ?1"#,
                params![id.to_string()],
                scan_evidence,
            )
            .optional()?
            .ok_or_else(|| anyhow!("evidence {id} not found"))?;
        Ok(row)
    }

    fn query_evidence(&self, query: &EvidenceQuery) -> Result<Vec<Evidence>> {
        let conn = self.conn.lock().unwrap();
        let mut sql = String::from(
            r#"SELECT id, control_id, class_uid, category_uid, activity_id,
                timestamp, confidence_level, metadata_json, observables_json,
                status_id, status, raw_data, findings_json,
                test_transcript_json, enrichments_json
               FROM evidence WHERE 1=1"#,
        );
        let mut args: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

        if let Some(cid) = &query.control_id {
            sql.push_str(" AND control_id = ?");
            args.push(Box::new(cid.clone()));
        }
        if let Some(src) = &query.source {
            sql.push_str(" AND json_extract(metadata_json, '$.source.system') = ?");
            args.push(Box::new(src.clone()));
        }
        if let Some(from) = &query.from_time {
            sql.push_str(" AND timestamp >= ?");
            args.push(Box::new(from.to_rfc3339()));
        }
        if let Some(to) = &query.to_time {
            sql.push_str(" AND timestamp <= ?");
            args.push(Box::new(to.to_rfc3339()));
        }

        sql.push_str(" ORDER BY timestamp DESC");

        if let Some(limit) = query.limit {
            sql.push_str(&format!(" LIMIT {limit}"));
        }

        let refs: Vec<&dyn rusqlite::ToSql> = args.iter().map(|b| b.as_ref()).collect();
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt
            .query_map(refs.as_slice(), scan_evidence)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("querying evidence")?;
        Ok(rows)
    }

    // -----------------------------------------------------------------------
    // Control Status
    // -----------------------------------------------------------------------

    fn store_control_status(&self, status: &ControlStatus) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let evidence_ids_json = serde_json::to_string(&status.evidence_ids)?;
        conn.execute(
            r#"INSERT INTO control_status (
                id, control_id, timestamp, status, confidence,
                evidence_ids_json, evaluation_details
            ) VALUES (?1,?2,?3,?4,?5,?6,?7)"#,
            params![
                status.id.to_string(),
                status.control_id,
                status.timestamp.to_rfc3339(),
                status.status,
                status.confidence,
                evidence_ids_json,
                status.evaluation_details,
            ],
        )
        .context("inserting control status")?;
        Ok(())
    }

    fn get_control_status(&self, control_id: &str) -> Result<ControlStatus> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            r#"SELECT id, control_id, timestamp, status, confidence,
                evidence_ids_json, evaluation_details
               FROM control_status WHERE control_id = ?1
               ORDER BY timestamp DESC LIMIT 1"#,
            params![control_id],
            scan_control_status,
        )
        .optional()?
        .ok_or_else(|| anyhow!("no status found for control {control_id:?}"))
    }

    fn query_history(
        &self,
        control_id: &str,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<Vec<ControlStatus>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"SELECT id, control_id, timestamp, status, confidence,
                evidence_ids_json, evaluation_details
               FROM control_status
               WHERE control_id = ?1 AND timestamp >= ?2 AND timestamp <= ?3
               ORDER BY timestamp ASC"#,
        )?;
        let rows = stmt
            .query_map(
                params![control_id, from.to_rfc3339(), to.to_rfc3339()],
                scan_control_status,
            )?
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("querying control history")?;
        Ok(rows)
    }

    // -----------------------------------------------------------------------
    // Schedules
    // -----------------------------------------------------------------------

    fn store_schedule(&self, sched: &Schedule) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let modules_json = serde_json::to_string(&sched.modules)?;
        conn.execute(
            r#"INSERT OR REPLACE INTO schedules (
                id, control_id, cron_expr, modules_json, enabled,
                max_safety_level, environment_scope, catch_up,
                last_run, next_run, created_at, updated_at
            ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)"#,
            params![
                sched.id,
                sched.control_id,
                sched.cron_expr,
                modules_json,
                sched.enabled as i32,
                sched.max_safety_level,
                sched.environment_scope,
                sched.catch_up as i32,
                sched.last_run.map(|t| t.to_rfc3339()),
                sched.next_run.map(|t| t.to_rfc3339()),
                sched.created_at.to_rfc3339(),
                sched.updated_at.to_rfc3339(),
            ],
        )
        .context("storing schedule")?;
        Ok(())
    }

    fn get_schedule(&self, id: &str) -> Result<Schedule> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            r#"SELECT id, control_id, cron_expr, modules_json, enabled,
                max_safety_level, environment_scope, catch_up,
                last_run, next_run, created_at, updated_at
               FROM schedules WHERE id = ?1"#,
            params![id],
            scan_schedule,
        )
        .optional()?
        .ok_or_else(|| anyhow!("schedule {id:?} not found"))
    }

    fn list_schedules(&self) -> Result<Vec<Schedule>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"SELECT id, control_id, cron_expr, modules_json, enabled,
                max_safety_level, environment_scope, catch_up,
                last_run, next_run, created_at, updated_at
               FROM schedules ORDER BY created_at ASC"#,
        )?;
        let rows = stmt
            .query_map([], scan_schedule)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("listing schedules")?;
        Ok(rows)
    }

    fn delete_schedule(&self, id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let affected = conn
            .execute("DELETE FROM schedules WHERE id = ?1", params![id])
            .context("deleting schedule")?;
        if affected == 0 {
            return Err(anyhow!("schedule {id:?} not found"));
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Schedule Runs
    // -----------------------------------------------------------------------

    fn store_schedule_run(&self, run: &ScheduleRun) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let results_json = serde_json::to_string(&run.module_results)?;
        conn.execute(
            r#"INSERT INTO schedule_runs (
                id, schedule_id, started_at, completed_at, status,
                module_results_json, error_message
            ) VALUES (?1,?2,?3,?4,?5,?6,?7)"#,
            params![
                run.id,
                run.schedule_id,
                run.started_at.to_rfc3339(),
                run.completed_at.to_rfc3339(),
                run.status,
                results_json,
                run.error,
            ],
        )
        .context("storing schedule run")?;
        Ok(())
    }

    fn list_schedule_runs(&self, schedule_id: &str, limit: usize) -> Result<Vec<ScheduleRun>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"SELECT id, schedule_id, started_at, completed_at, status,
                module_results_json, error_message
               FROM schedule_runs WHERE schedule_id = ?1
               ORDER BY started_at DESC LIMIT ?2"#,
        )?;
        let rows = stmt
            .query_map(params![schedule_id, limit as i64], scan_schedule_run)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("listing schedule runs")?;
        Ok(rows)
    }

    // -----------------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------------

    fn prune_evidence(&self, older_than: DateTime<Utc>) -> Result<u64> {
        let conn = self.conn.lock().unwrap();
        let affected = conn
            .execute(
                "DELETE FROM evidence WHERE timestamp < ?1",
                params![older_than.to_rfc3339()],
            )
            .context("pruning evidence")?;
        Ok(affected as u64)
    }

    fn close(&self) -> Result<()> {
        // Connection is dropped when the store is dropped.
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Row scan helpers
// ---------------------------------------------------------------------------

fn parse_rfc3339(s: &str) -> Result<DateTime<Utc>, chrono::ParseError> {
    DateTime::parse_from_rfc3339(s).map(|dt| dt.with_timezone(&Utc))
}

fn scan_evidence(row: &rusqlite::Row<'_>) -> rusqlite::Result<Evidence> {
    let id_str: String = row.get(0)?;
    let timestamp_str: String = row.get(5)?;
    let confidence_str: String = row.get(6)?;
    let metadata_json: String = row.get(7)?;
    let observables_json: String = row.get(8)?;
    let status_id_int: i32 = row.get(9)?;
    let raw_data_str: String = row.get(11)?;
    let findings_json: String = row.get(12)?;
    let transcript_json: Option<String> = row.get(13)?;
    let enrichments_json: Option<String> = row.get(14)?;

    let id = Uuid::parse_str(&id_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let time = parse_rfc3339(&timestamp_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let confidence_level = match confidence_str.as_str() {
        "active_verification" => ConfidenceLevel::ActiveVerification,
        _ => ConfidenceLevel::PassiveObservation,
    };
    let metadata: Metadata = serde_json::from_str(&metadata_json).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(7, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let observables: Vec<Observable> = serde_json::from_str(&observables_json).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(8, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let raw_data: serde_json::Value = serde_json::from_str(&raw_data_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(11, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let findings: Vec<Finding> = serde_json::from_str(&findings_json).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(12, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let test_transcript = transcript_json
        .as_deref()
        .map(serde_json::from_str)
        .transpose()
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(13, rusqlite::types::Type::Text, Box::new(e))
        })?;
    let enrichments: Vec<Enrichment> = enrichments_json
        .as_deref()
        .map(serde_json::from_str)
        .transpose()
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(14, rusqlite::types::Type::Text, Box::new(e))
        })?
        .unwrap_or_default();

    Ok(Evidence {
        id,
        control_id: row.get(1)?,
        class_uid: row.get(2)?,
        category_uid: row.get(3)?,
        activity_id: row.get(4)?,
        time,
        confidence_level,
        metadata,
        observables,
        status_id: StatusId::from(status_id_int),
        status: row.get(10)?,
        raw_data,
        findings,
        test_transcript,
        enrichments,
    })
}

fn scan_control_status(row: &rusqlite::Row<'_>) -> rusqlite::Result<ControlStatus> {
    let id_str: String = row.get(0)?;
    let timestamp_str: String = row.get(2)?;
    let evidence_ids_json: String = row.get(5)?;

    let id = Uuid::parse_str(&id_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let timestamp = parse_rfc3339(&timestamp_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let evidence_ids: Vec<Uuid> = serde_json::from_str(&evidence_ids_json).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(e))
    })?;

    Ok(ControlStatus {
        id,
        control_id: row.get(1)?,
        timestamp,
        status: row.get(3)?,
        confidence: row.get(4)?,
        evidence_ids,
        evaluation_details: row.get(6)?,
    })
}

fn scan_schedule(row: &rusqlite::Row<'_>) -> rusqlite::Result<Schedule> {
    let modules_json: String = row.get(3)?;
    let enabled: i32 = row.get(4)?;
    let catch_up: i32 = row.get(7)?;
    let last_run_str: Option<String> = row.get(8)?;
    let next_run_str: Option<String> = row.get(9)?;
    let created_str: String = row.get(10)?;
    let updated_str: String = row.get(11)?;

    let modules: Vec<String> = serde_json::from_str(&modules_json).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let created_at = parse_rfc3339(&created_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(10, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let updated_at = parse_rfc3339(&updated_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(11, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let last_run = last_run_str
        .as_deref()
        .map(parse_rfc3339)
        .transpose()
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(8, rusqlite::types::Type::Text, Box::new(e))
        })?;
    let next_run = next_run_str
        .as_deref()
        .map(parse_rfc3339)
        .transpose()
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(9, rusqlite::types::Type::Text, Box::new(e))
        })?;

    Ok(Schedule {
        id: row.get(0)?,
        control_id: row.get(1)?,
        cron_expr: row.get(2)?,
        modules,
        enabled: enabled != 0,
        max_safety_level: row.get(5)?,
        environment_scope: row.get(6)?,
        catch_up: catch_up != 0,
        last_run,
        next_run,
        created_at,
        updated_at,
    })
}

fn scan_schedule_run(row: &rusqlite::Row<'_>) -> rusqlite::Result<ScheduleRun> {
    let started_str: String = row.get(2)?;
    let completed_str: String = row.get(3)?;
    let results_json: String = row.get(5)?;

    let started_at = parse_rfc3339(&started_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let completed_at = parse_rfc3339(&completed_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let module_results: Vec<ModuleRunResult> =
        serde_json::from_str(&results_json).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(e))
        })?;

    Ok(ScheduleRun {
        id: row.get(0)?,
        schedule_id: row.get(1)?,
        started_at,
        completed_at,
        status: row.get(4)?,
        module_results,
        error: row.get(6)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler::types::{MODULE_STATUS_SUCCESS, RUN_STATUS_SUCCESS};
    use crate::storage::{EvidenceQuery, Store};
    use chrono::Duration;
    use tempfile::TempDir;

    // ---------------------------------------------------------------------------
    // Test helpers
    // ---------------------------------------------------------------------------

    fn open_store() -> (SqliteStore, TempDir) {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("test.db");
        let store = SqliteStore::open(&db_path).unwrap();
        (store, dir)
    }

    fn make_evidence() -> Evidence {
        crate::testutil::make_evidence()
    }

    fn make_control_status(control_id: &str) -> ControlStatus {
        ControlStatus {
            id: Uuid::new_v4(),
            control_id: control_id.to_string(),
            timestamp: Utc::now(),
            status: "effective".to_string(),
            confidence: "high".to_string(),
            evidence_ids: vec![Uuid::new_v4()],
            evaluation_details: "all clear".to_string(),
        }
    }

    fn make_schedule(id: &str) -> Schedule {
        Schedule {
            id: id.to_string(),
            control_id: "cc6.1".to_string(),
            cron_expr: "0 * * * *".to_string(),
            modules: vec!["mock.test".to_string()],
            max_safety_level: "safe".to_string(),
            environment_scope: "production".to_string(),
            enabled: true,
            catch_up: false,
            last_run: None,
            next_run: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn make_schedule_run(schedule_id: &str, run_id: &str) -> ScheduleRun {
        ScheduleRun {
            id: run_id.to_string(),
            schedule_id: schedule_id.to_string(),
            started_at: Utc::now(),
            completed_at: Utc::now(),
            status: RUN_STATUS_SUCCESS.to_string(),
            module_results: vec![ModuleRunResult {
                module_id: "mock.test".to_string(),
                status: MODULE_STATUS_SUCCESS.to_string(),
                evidence_count: 1,
                error: String::new(),
            }],
            error: String::new(),
        }
    }

    // ---------------------------------------------------------------------------
    // Open / schema
    // ---------------------------------------------------------------------------

    #[test]
    fn open_creates_db_file() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("subdir").join("ocean.db");
        let store = SqliteStore::open(&db_path).unwrap();
        assert!(db_path.exists());
        store.close().unwrap();
    }

    // ---------------------------------------------------------------------------
    // Evidence CRUD
    // ---------------------------------------------------------------------------

    #[test]
    fn store_and_get_evidence() {
        let (store, _dir) = open_store();
        let ev = make_evidence();
        let id = ev.id;
        store.store_evidence(&ev).unwrap();
        let retrieved = store.get_evidence(id).unwrap();
        assert_eq!(retrieved.id, id);
        assert_eq!(retrieved.control_id, ev.control_id);
        assert_eq!(retrieved.status_id, ev.status_id);
        assert_eq!(retrieved.status, ev.status);
    }

    #[test]
    fn get_evidence_not_found() {
        let (store, _dir) = open_store();
        let err = store.get_evidence(Uuid::new_v4()).unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn store_evidence_with_transcript() {
        let (store, _dir) = open_store();
        let mut ev = make_evidence();
        ev.test_transcript = Some(crate::evidence::TestTranscript {
            actions_attempted: vec![],
            observations: vec![],
            cleanup_actions: vec![],
        });
        let id = ev.id;
        store.store_evidence(&ev).unwrap();
        let retrieved = store.get_evidence(id).unwrap();
        assert!(retrieved.test_transcript.is_some());
    }

    #[test]
    fn store_evidence_with_enrichments() {
        let (store, _dir) = open_store();
        let mut ev = make_evidence();
        ev.enrichments = vec![Enrichment {
            enrichment_type: "geo".to_string(),
            data: serde_json::json!({"cc": "US"}),
            enriched_time: Utc::now(),
        }];
        let id = ev.id;
        store.store_evidence(&ev).unwrap();
        let retrieved = store.get_evidence(id).unwrap();
        assert_eq!(retrieved.enrichments.len(), 1);
    }

    #[test]
    fn store_evidence_active_verification_confidence() {
        let (store, _dir) = open_store();
        let mut ev = make_evidence();
        ev.confidence_level = ConfidenceLevel::ActiveVerification;
        let id = ev.id;
        store.store_evidence(&ev).unwrap();
        let retrieved = store.get_evidence(id).unwrap();
        assert_eq!(
            retrieved.confidence_level,
            ConfidenceLevel::ActiveVerification
        );
    }

    // --- query_evidence ---

    #[test]
    fn query_all_evidence() {
        let (store, _dir) = open_store();
        for _ in 0..3 {
            store.store_evidence(&make_evidence()).unwrap();
        }
        let results = store.query_evidence(&EvidenceQuery::default()).unwrap();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn query_by_control_id() {
        let (store, _dir) = open_store();
        let mut ev1 = make_evidence();
        ev1.control_id = "cc6.1".to_string();
        let mut ev2 = make_evidence();
        ev2.control_id = "cc7.2".to_string();
        store.store_evidence(&ev1).unwrap();
        store.store_evidence(&ev2).unwrap();

        let q = EvidenceQuery {
            control_id: Some("cc6.1".to_string()),
            ..Default::default()
        };
        let results = store.query_evidence(&q).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].control_id, "cc6.1");
    }

    #[test]
    fn query_by_source() {
        let (store, _dir) = open_store();
        store.store_evidence(&make_evidence()).unwrap();
        let q = EvidenceQuery {
            source: Some("mock".to_string()),
            ..Default::default()
        };
        let results = store.query_evidence(&q).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn query_by_time_range() {
        let (store, _dir) = open_store();
        let ev = make_evidence();
        store.store_evidence(&ev).unwrap();

        let from = Utc::now() - Duration::hours(1);
        let to = Utc::now() + Duration::hours(1);
        let q = EvidenceQuery {
            from_time: Some(from),
            to_time: Some(to),
            ..Default::default()
        };
        let results = store.query_evidence(&q).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn query_with_limit() {
        let (store, _dir) = open_store();
        for _ in 0..5 {
            store.store_evidence(&make_evidence()).unwrap();
        }
        let q = EvidenceQuery {
            limit: Some(2),
            ..Default::default()
        };
        let results = store.query_evidence(&q).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn query_empty_returns_empty() {
        let (store, _dir) = open_store();
        let results = store.query_evidence(&EvidenceQuery::default()).unwrap();
        assert!(results.is_empty());
    }

    // --- prune_evidence ---

    #[test]
    fn prune_evidence_removes_old() {
        let (store, _dir) = open_store();
        // Insert evidence — its timestamp is Utc::now()
        store.store_evidence(&make_evidence()).unwrap();
        // Prune anything older than 1 hour from now — should prune nothing
        let cutoff = Utc::now() - Duration::hours(1);
        let pruned = store.prune_evidence(cutoff).unwrap();
        assert_eq!(pruned, 0);
        // Prune everything (cutoff in future)
        let cutoff_future = Utc::now() + Duration::hours(1);
        let pruned2 = store.prune_evidence(cutoff_future).unwrap();
        assert_eq!(pruned2, 1);
    }

    // ---------------------------------------------------------------------------
    // Control Status
    // ---------------------------------------------------------------------------

    #[test]
    fn store_and_get_control_status() {
        let (store, _dir) = open_store();
        let cs = make_control_status("cc6.1");
        store.store_control_status(&cs).unwrap();
        let retrieved = store.get_control_status("cc6.1").unwrap();
        assert_eq!(retrieved.id, cs.id);
        assert_eq!(retrieved.status, "effective");
        assert_eq!(retrieved.confidence, "high");
        assert_eq!(retrieved.evidence_ids.len(), 1);
    }

    #[test]
    fn get_control_status_returns_latest() {
        let (store, _dir) = open_store();
        let mut cs1 = make_control_status("cc6.1");
        cs1.timestamp = Utc::now() - Duration::hours(2);
        cs1.status = "ineffective".to_string();
        let mut cs2 = make_control_status("cc6.1");
        cs2.timestamp = Utc::now();
        cs2.status = "effective".to_string();
        store.store_control_status(&cs1).unwrap();
        store.store_control_status(&cs2).unwrap();
        let latest = store.get_control_status("cc6.1").unwrap();
        assert_eq!(latest.status, "effective");
    }

    #[test]
    fn get_control_status_not_found() {
        let (store, _dir) = open_store();
        let err = store.get_control_status("nonexistent").unwrap_err();
        assert!(err.to_string().contains("no status found"));
    }

    #[test]
    fn query_history() {
        let (store, _dir) = open_store();
        let cs = make_control_status("cc6.1");
        store.store_control_status(&cs).unwrap();
        let from = Utc::now() - Duration::hours(1);
        let to = Utc::now() + Duration::hours(1);
        let history = store.query_history("cc6.1", from, to).unwrap();
        assert_eq!(history.len(), 1);
    }

    #[test]
    fn query_history_outside_range() {
        let (store, _dir) = open_store();
        let cs = make_control_status("cc6.1");
        store.store_control_status(&cs).unwrap();
        // Query a range in the past — should find nothing
        let from = Utc::now() - Duration::days(7);
        let to = Utc::now() - Duration::days(6);
        let history = store.query_history("cc6.1", from, to).unwrap();
        assert!(history.is_empty());
    }

    // ---------------------------------------------------------------------------
    // Schedules
    // ---------------------------------------------------------------------------

    #[test]
    fn store_and_get_schedule() {
        let (store, _dir) = open_store();
        let sched = make_schedule("sched-1");
        store.store_schedule(&sched).unwrap();
        let retrieved = store.get_schedule("sched-1").unwrap();
        assert_eq!(retrieved.id, "sched-1");
        assert_eq!(retrieved.cron_expr, sched.cron_expr);
        assert!(retrieved.enabled);
        assert!(!retrieved.catch_up);
    }

    #[test]
    fn store_schedule_with_optional_times() {
        let (store, _dir) = open_store();
        let mut sched = make_schedule("sched-opt");
        sched.last_run = Some(Utc::now() - Duration::hours(1));
        sched.next_run = Some(Utc::now() + Duration::hours(1));
        store.store_schedule(&sched).unwrap();
        let retrieved = store.get_schedule("sched-opt").unwrap();
        assert!(retrieved.last_run.is_some());
        assert!(retrieved.next_run.is_some());
    }

    #[test]
    fn get_schedule_not_found() {
        let (store, _dir) = open_store();
        let err = store.get_schedule("ghost").unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn list_schedules() {
        let (store, _dir) = open_store();
        store.store_schedule(&make_schedule("s1")).unwrap();
        store.store_schedule(&make_schedule("s2")).unwrap();
        let list = store.list_schedules().unwrap();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn delete_schedule() {
        let (store, _dir) = open_store();
        store.store_schedule(&make_schedule("del-me")).unwrap();
        store.delete_schedule("del-me").unwrap();
        assert!(store.get_schedule("del-me").is_err());
    }

    #[test]
    fn delete_schedule_not_found_error() {
        let (store, _dir) = open_store();
        let err = store.delete_schedule("ghost").unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn store_schedule_upserts() {
        let (store, _dir) = open_store();
        let mut sched = make_schedule("upsert-1");
        store.store_schedule(&sched).unwrap();
        sched.enabled = false;
        store.store_schedule(&sched).unwrap();
        let retrieved = store.get_schedule("upsert-1").unwrap();
        assert!(!retrieved.enabled);
    }

    // ---------------------------------------------------------------------------
    // Schedule Runs
    // ---------------------------------------------------------------------------

    #[test]
    fn store_and_list_schedule_runs() {
        let (store, _dir) = open_store();
        store.store_schedule(&make_schedule("sched-1")).unwrap();
        store
            .store_schedule_run(&make_schedule_run("sched-1", "run-1"))
            .unwrap();
        store
            .store_schedule_run(&make_schedule_run("sched-1", "run-2"))
            .unwrap();
        let runs = store.list_schedule_runs("sched-1", 10).unwrap();
        assert_eq!(runs.len(), 2);
    }

    #[test]
    fn list_schedule_runs_respects_limit() {
        let (store, _dir) = open_store();
        store.store_schedule(&make_schedule("sched-2")).unwrap();
        for i in 0..5 {
            store
                .store_schedule_run(&make_schedule_run("sched-2", &format!("run-{i}")))
                .unwrap();
        }
        let runs = store.list_schedule_runs("sched-2", 3).unwrap();
        assert_eq!(runs.len(), 3);
    }

    #[test]
    fn list_schedule_runs_empty() {
        let (store, _dir) = open_store();
        store.store_schedule(&make_schedule("sched-3")).unwrap();
        let runs = store.list_schedule_runs("sched-3", 10).unwrap();
        assert!(runs.is_empty());
    }

    #[test]
    fn schedule_run_cascade_delete() {
        let (store, _dir) = open_store();
        store.store_schedule(&make_schedule("sched-del")).unwrap();
        store
            .store_schedule_run(&make_schedule_run("sched-del", "run-del"))
            .unwrap();
        store.delete_schedule("sched-del").unwrap();
        // After cascade delete, runs should be gone
        let runs = store.list_schedule_runs("sched-del", 10).unwrap();
        assert!(runs.is_empty());
    }

    // ---------------------------------------------------------------------------
    // Lifecycle
    // ---------------------------------------------------------------------------

    #[test]
    fn close_is_noop() {
        let (store, _dir) = open_store();
        assert!(store.close().is_ok());
    }

    // ---------------------------------------------------------------------------
    // Corrupt-data scan error paths
    // ---------------------------------------------------------------------------

    #[test]
    fn scan_evidence_bad_uuid_errors() {
        let (store, _dir) = open_store();
        let conn = store.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO evidence (id, control_id, class_uid, category_uid, activity_id,
             timestamp, confidence_level, metadata_json, observables_json,
             status_id, status, raw_data, findings_json) VALUES
             ('NOT-A-UUID','c',1,1,1,'2024-01-01T00:00:00Z','passive_observation',
              '{}','[]',1,'ok','null','[]')",
            [],
        )
        .unwrap();
        drop(conn);
        let result = store.query_evidence(&EvidenceQuery::default());
        assert!(result.is_err());
    }

    #[test]
    fn scan_evidence_bad_timestamp_errors() {
        let (store, _dir) = open_store();
        let id = Uuid::new_v4().to_string();
        let conn = store.conn.lock().unwrap();
        conn.execute(
            &format!(
                "INSERT INTO evidence (id, control_id, class_uid, category_uid, activity_id,
                 timestamp, confidence_level, metadata_json, observables_json,
                 status_id, status, raw_data, findings_json) VALUES
                 ('{id}','c',1,1,1,'not-a-date','passive_observation',
                  '{{}}','[]',1,'ok','null','[]')"
            ),
            [],
        )
        .unwrap();
        drop(conn);
        let result = store.query_evidence(&EvidenceQuery::default());
        assert!(result.is_err());
    }

    #[test]
    fn scan_evidence_bad_metadata_json_errors() {
        let (store, _dir) = open_store();
        let id = Uuid::new_v4().to_string();
        let conn = store.conn.lock().unwrap();
        conn.execute(
            &format!(
                "INSERT INTO evidence (id, control_id, class_uid, category_uid, activity_id,
                 timestamp, confidence_level, metadata_json, observables_json,
                 status_id, status, raw_data, findings_json) VALUES
                 ('{id}','c',1,1,1,'2024-01-01T00:00:00Z','passive_observation',
                  'BAD','[]',1,'ok','null','[]')"
            ),
            [],
        )
        .unwrap();
        drop(conn);
        let result = store.query_evidence(&EvidenceQuery::default());
        assert!(result.is_err());
    }

    #[test]
    fn scan_evidence_bad_observables_json_errors() {
        let (store, _dir) = open_store();
        let id = Uuid::new_v4().to_string();
        let meta = r#"{"module":{"name":"m","version":"0","module_type":"observer"},"source":{"system":"s","api_version":"v1","endpoint":"e"},"original_time":null,"processed_time":"2024-01-01T00:00:00Z","safety_classification":null}"#;
        let conn = store.conn.lock().unwrap();
        conn.execute(
            &format!(
                "INSERT INTO evidence (id, control_id, class_uid, category_uid, activity_id,
                 timestamp, confidence_level, metadata_json, observables_json,
                 status_id, status, raw_data, findings_json) VALUES
                 ('{id}','c',1,1,1,'2024-01-01T00:00:00Z','passive_observation',
                  '{meta}','BAD',1,'ok','null','[]')"
            ),
            [],
        )
        .unwrap();
        drop(conn);
        let result = store.query_evidence(&EvidenceQuery::default());
        assert!(result.is_err());
    }

    #[test]
    fn scan_evidence_bad_raw_data_errors() {
        let (store, _dir) = open_store();
        let id = Uuid::new_v4().to_string();
        let meta = r#"{"module":{"name":"m","version":"0","module_type":"observer"},"source":{"system":"s","api_version":"v1","endpoint":"e"},"original_time":null,"processed_time":"2024-01-01T00:00:00Z","safety_classification":null}"#;
        let conn = store.conn.lock().unwrap();
        conn.execute(
            &format!(
                "INSERT INTO evidence (id, control_id, class_uid, category_uid, activity_id,
                 timestamp, confidence_level, metadata_json, observables_json,
                 status_id, status, raw_data, findings_json) VALUES
                 ('{id}','c',1,1,1,'2024-01-01T00:00:00Z','passive_observation',
                  '{meta}','[]',1,'ok','BAD','[]')"
            ),
            [],
        )
        .unwrap();
        drop(conn);
        let result = store.query_evidence(&EvidenceQuery::default());
        assert!(result.is_err());
    }

    #[test]
    fn scan_evidence_bad_findings_json_errors() {
        let (store, _dir) = open_store();
        let id = Uuid::new_v4().to_string();
        let meta = r#"{"module":{"name":"m","version":"0","module_type":"observer"},"source":{"system":"s","api_version":"v1","endpoint":"e"},"original_time":null,"processed_time":"2024-01-01T00:00:00Z","safety_classification":null}"#;
        let conn = store.conn.lock().unwrap();
        conn.execute(
            &format!(
                "INSERT INTO evidence (id, control_id, class_uid, category_uid, activity_id,
                 timestamp, confidence_level, metadata_json, observables_json,
                 status_id, status, raw_data, findings_json) VALUES
                 ('{id}','c',1,1,1,'2024-01-01T00:00:00Z','passive_observation',
                  '{meta}','[]',1,'ok','null','BAD')"
            ),
            [],
        )
        .unwrap();
        drop(conn);
        let result = store.query_evidence(&EvidenceQuery::default());
        assert!(result.is_err());
    }

    #[test]
    fn scan_evidence_bad_transcript_json_errors() {
        let (store, _dir) = open_store();
        let id = Uuid::new_v4().to_string();
        let meta = r#"{"module":{"name":"m","version":"0","module_type":"observer"},"source":{"system":"s","api_version":"v1","endpoint":"e"},"original_time":null,"processed_time":"2024-01-01T00:00:00Z","safety_classification":null}"#;
        let conn = store.conn.lock().unwrap();
        conn.execute(
            &format!(
                "INSERT INTO evidence (id, control_id, class_uid, category_uid, activity_id,
                 timestamp, confidence_level, metadata_json, observables_json,
                 status_id, status, raw_data, findings_json, test_transcript_json) VALUES
                 ('{id}','c',1,1,1,'2024-01-01T00:00:00Z','passive_observation',
                  '{meta}','[]',1,'ok','null','[]','BAD')"
            ),
            [],
        )
        .unwrap();
        drop(conn);
        let result = store.query_evidence(&EvidenceQuery::default());
        assert!(result.is_err());
    }

    #[test]
    fn scan_evidence_bad_enrichments_json_errors() {
        let (store, _dir) = open_store();
        let id = Uuid::new_v4().to_string();
        let meta = r#"{"module":{"name":"m","version":"0","module_type":"observer"},"source":{"system":"s","api_version":"v1","endpoint":"e"},"original_time":null,"processed_time":"2024-01-01T00:00:00Z","safety_classification":null}"#;
        let conn = store.conn.lock().unwrap();
        conn.execute(
            &format!(
                "INSERT INTO evidence (id, control_id, class_uid, category_uid, activity_id,
                 timestamp, confidence_level, metadata_json, observables_json,
                 status_id, status, raw_data, findings_json, enrichments_json) VALUES
                 ('{id}','c',1,1,1,'2024-01-01T00:00:00Z','passive_observation',
                  '{meta}','[]',1,'ok','null','[]','BAD')"
            ),
            [],
        )
        .unwrap();
        drop(conn);
        let result = store.query_evidence(&EvidenceQuery::default());
        assert!(result.is_err());
    }

    #[test]
    fn scan_control_status_bad_uuid_errors() {
        let (store, _dir) = open_store();
        let conn = store.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO control_status (id, control_id, timestamp, status, confidence,
             evidence_ids_json, evaluation_details) VALUES
             ('NOT-UUID','cc6.1','2024-01-01T00:00:00Z','effective','high','[]','ok')",
            [],
        )
        .unwrap();
        drop(conn);
        let result = store.get_control_status("cc6.1");
        assert!(result.is_err());
    }

    #[test]
    fn scan_control_status_bad_timestamp_errors() {
        let (store, _dir) = open_store();
        let id = Uuid::new_v4().to_string();
        let conn = store.conn.lock().unwrap();
        conn.execute(
            &format!(
                "INSERT INTO control_status (id, control_id, timestamp, status, confidence,
                 evidence_ids_json, evaluation_details) VALUES
                 ('{id}','cc6.1','bad-time','effective','high','[]','ok')"
            ),
            [],
        )
        .unwrap();
        drop(conn);
        let result = store.get_control_status("cc6.1");
        assert!(result.is_err());
    }

    #[test]
    fn scan_control_status_bad_evidence_ids_errors() {
        let (store, _dir) = open_store();
        let id = Uuid::new_v4().to_string();
        let conn = store.conn.lock().unwrap();
        conn.execute(
            &format!(
                "INSERT INTO control_status (id, control_id, timestamp, status, confidence,
                 evidence_ids_json, evaluation_details) VALUES
                 ('{id}','cc6.1','2024-01-01T00:00:00Z','effective','high','BAD','ok')"
            ),
            [],
        )
        .unwrap();
        drop(conn);
        let result = store.get_control_status("cc6.1");
        assert!(result.is_err());
    }

    #[test]
    fn scan_schedule_bad_modules_json_errors() {
        let (store, _dir) = open_store();
        let conn = store.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO schedules (id, control_id, cron_expr, modules_json, enabled,
             max_safety_level, environment_scope, catch_up, last_run, next_run,
             created_at, updated_at) VALUES
             ('s1','cc6.1','0 * * * *','BAD',1,'safe','production',0,NULL,NULL,
              '2024-01-01T00:00:00Z','2024-01-01T00:00:00Z')",
            [],
        )
        .unwrap();
        drop(conn);
        let result = store.get_schedule("s1");
        assert!(result.is_err());
    }

    #[test]
    fn scan_schedule_bad_created_at_errors() {
        let (store, _dir) = open_store();
        let conn = store.conn.lock().unwrap();
        conn.execute(
            r#"INSERT INTO schedules (id, control_id, cron_expr, modules_json, enabled,
             max_safety_level, environment_scope, catch_up, last_run, next_run,
             created_at, updated_at) VALUES
             ('s2','cc6.1','0 * * * *','["m"]',1,'safe','production',0,NULL,NULL,
              'bad-date','2024-01-01T00:00:00Z')"#,
            [],
        )
        .unwrap();
        drop(conn);
        let result = store.get_schedule("s2");
        assert!(result.is_err());
    }

    #[test]
    fn scan_schedule_bad_updated_at_errors() {
        let (store, _dir) = open_store();
        let conn = store.conn.lock().unwrap();
        conn.execute(
            r#"INSERT INTO schedules (id, control_id, cron_expr, modules_json, enabled,
             max_safety_level, environment_scope, catch_up, last_run, next_run,
             created_at, updated_at) VALUES
             ('s3','cc6.1','0 * * * *','["m"]',1,'safe','production',0,NULL,NULL,
              '2024-01-01T00:00:00Z','bad-date')"#,
            [],
        )
        .unwrap();
        drop(conn);
        let result = store.get_schedule("s3");
        assert!(result.is_err());
    }

    #[test]
    fn scan_schedule_bad_last_run_errors() {
        let (store, _dir) = open_store();
        let conn = store.conn.lock().unwrap();
        conn.execute(
            r#"INSERT INTO schedules (id, control_id, cron_expr, modules_json, enabled,
             max_safety_level, environment_scope, catch_up, last_run, next_run,
             created_at, updated_at) VALUES
             ('s4','cc6.1','0 * * * *','["m"]',1,'safe','production',0,'bad-date',NULL,
              '2024-01-01T00:00:00Z','2024-01-01T00:00:00Z')"#,
            [],
        )
        .unwrap();
        drop(conn);
        let result = store.get_schedule("s4");
        assert!(result.is_err());
    }

    #[test]
    fn scan_schedule_bad_next_run_errors() {
        let (store, _dir) = open_store();
        let conn = store.conn.lock().unwrap();
        conn.execute(
            r#"INSERT INTO schedules (id, control_id, cron_expr, modules_json, enabled,
             max_safety_level, environment_scope, catch_up, last_run, next_run,
             created_at, updated_at) VALUES
             ('s5','cc6.1','0 * * * *','["m"]',1,'safe','production',0,NULL,'bad-date',
              '2024-01-01T00:00:00Z','2024-01-01T00:00:00Z')"#,
            [],
        )
        .unwrap();
        drop(conn);
        let result = store.get_schedule("s5");
        assert!(result.is_err());
    }

    #[test]
    fn scan_schedule_run_bad_started_at_errors() {
        let (store, _dir) = open_store();
        store.store_schedule(&make_schedule("sr1")).unwrap();
        let conn = store.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO schedule_runs (id, schedule_id, started_at, completed_at, status,
             module_results_json) VALUES
             ('r1','sr1','bad-date','2024-01-01T00:00:00Z','success','[]')",
            [],
        )
        .unwrap();
        drop(conn);
        let result = store.list_schedule_runs("sr1", 10);
        assert!(result.is_err());
    }

    #[test]
    fn scan_schedule_run_bad_completed_at_errors() {
        let (store, _dir) = open_store();
        store.store_schedule(&make_schedule("sr2")).unwrap();
        let conn = store.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO schedule_runs (id, schedule_id, started_at, completed_at, status,
             module_results_json) VALUES
             ('r2','sr2','2024-01-01T00:00:00Z','bad-date','success','[]')",
            [],
        )
        .unwrap();
        drop(conn);
        let result = store.list_schedule_runs("sr2", 10);
        assert!(result.is_err());
    }

    #[test]
    fn scan_schedule_run_bad_results_json_errors() {
        let (store, _dir) = open_store();
        store.store_schedule(&make_schedule("sr3")).unwrap();
        let conn = store.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO schedule_runs (id, schedule_id, started_at, completed_at, status,
             module_results_json) VALUES
             ('r3','sr3','2024-01-01T00:00:00Z','2024-01-01T00:00:00Z','success','BAD')",
            [],
        )
        .unwrap();
        drop(conn);
        let result = store.list_schedule_runs("sr3", 10);
        assert!(result.is_err());
    }

    #[test]
    fn query_evidence_with_min_confidence() {
        let (store, _dir) = open_store();
        store.store_evidence(&make_evidence()).unwrap();
        let q = EvidenceQuery {
            min_confidence: Some(ConfidenceLevel::PassiveObservation),
            ..Default::default()
        };
        let results = store.query_evidence(&q).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn query_evidence_with_cursor() {
        let (store, _dir) = open_store();
        store.store_evidence(&make_evidence()).unwrap();
        let q = EvidenceQuery {
            cursor: Some("cursor-token".to_string()),
            ..Default::default()
        };
        let results = store.query_evidence(&q).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn parse_rfc3339_valid() {
        let dt = parse_rfc3339("2024-06-15T12:00:00Z").unwrap();
        assert_eq!(dt.date_naive().to_string(), "2024-06-15");
    }

    #[test]
    fn parse_rfc3339_invalid() {
        assert!(parse_rfc3339("not-a-date").is_err());
    }
}
