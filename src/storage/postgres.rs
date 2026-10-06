// PostgreSQL-backed implementation of the Store trait.
// Enabled only when the `postgres` cargo feature is active.
//
// Uses `r2d2_postgres` for synchronous connection pooling, matching the
// synchronous `Store` trait contract. The pool is capped by `pool_size`
// from config (default 10) and is safe to share across threads.
//
// Schema is kept identical to the SQLite backend — TEXT columns store
// JSON blobs, timestamps are ISO-8601 strings — so evidence data is
// portable between the two backends.

#[cfg(feature = "postgres")]
mod inner {
    use anyhow::{anyhow, Context, Result};
    use chrono::{DateTime, Utc};
    use r2d2::Pool;
    use r2d2_postgres::{postgres::NoTls, PostgresConnectionManager};
    use serde_json;
    use uuid::Uuid;

    use crate::control::ControlStatus;
    use crate::evidence::{
        ConfidenceLevel, Enrichment, Evidence, Finding, Metadata, Observable, StatusId,
    };
    use crate::scheduler::{ModuleRunResult, Schedule, ScheduleRun};
    use crate::storage::{EvidenceQuery, Store};

    /// PostgreSQL-backed implementation of [`Store`].
    ///
    /// # Example
    /// ```no_run
    /// use ocean::storage::postgres::PostgresStore;
    /// let store = PostgresStore::connect("postgres://user:pass@localhost/ocean", 10).unwrap();
    /// ```
    pub struct PostgresStore {
        pool: Pool<PostgresConnectionManager<NoTls>>,
    }

    impl PostgresStore {
        /// Connect to PostgreSQL and run schema migrations.
        ///
        /// `url` is a standard libpq connection string.
        /// `pool_size` is the maximum number of pooled connections.
        pub fn connect(url: &str, pool_size: u32) -> Result<Self> {
            let manager = PostgresConnectionManager::new(
                url.parse().context("parsing PostgreSQL connection URL")?,
                NoTls,
            );
            let pool = Pool::builder()
                .max_size(pool_size)
                .build(manager)
                .context("building PostgreSQL connection pool")?;

            let store = Self { pool };
            store.migrate()?;
            Ok(store)
        }

        fn migrate(&self) -> Result<()> {
            let mut conn = self.pool.get().context("acquiring connection for migration")?;
            conn.batch_execute(
                r#"
                CREATE TABLE IF NOT EXISTS evidence (
                    id                   TEXT PRIMARY KEY,
                    control_id           TEXT NOT NULL,
                    class_uid            BIGINT NOT NULL,
                    category_uid         BIGINT NOT NULL,
                    activity_id          BIGINT NOT NULL,
                    timestamp            TEXT NOT NULL,
                    confidence_level     TEXT NOT NULL,
                    metadata_json        TEXT NOT NULL,
                    observables_json     TEXT NOT NULL DEFAULT '[]',
                    status_id            BIGINT NOT NULL,
                    status               TEXT NOT NULL,
                    raw_data             TEXT NOT NULL DEFAULT 'null',
                    findings_json        TEXT NOT NULL DEFAULT '[]',
                    test_transcript_json TEXT,
                    enrichments_json     TEXT,
                    created_at           TEXT NOT NULL DEFAULT to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
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
                    created_at         TEXT NOT NULL DEFAULT to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
                );
                CREATE INDEX IF NOT EXISTS idx_control_status_control_id ON control_status(control_id);
                CREATE INDEX IF NOT EXISTS idx_control_status_timestamp   ON control_status(timestamp);

                CREATE TABLE IF NOT EXISTS schedules (
                    id                TEXT PRIMARY KEY,
                    control_id        TEXT NOT NULL DEFAULT '',
                    cron_expr         TEXT NOT NULL,
                    modules_json      TEXT NOT NULL,
                    enabled           BIGINT NOT NULL DEFAULT 1,
                    max_safety_level  TEXT NOT NULL DEFAULT 'safe',
                    environment_scope TEXT NOT NULL DEFAULT 'production',
                    catch_up          BIGINT NOT NULL DEFAULT 0,
                    last_run          TEXT,
                    next_run          TEXT,
                    created_at        TEXT NOT NULL DEFAULT to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
                    updated_at        TEXT NOT NULL DEFAULT to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
                );

                CREATE TABLE IF NOT EXISTS schedule_runs (
                    id                  TEXT PRIMARY KEY,
                    schedule_id         TEXT NOT NULL,
                    started_at          TEXT NOT NULL,
                    completed_at        TEXT NOT NULL,
                    status              TEXT NOT NULL,
                    module_results_json TEXT NOT NULL DEFAULT '[]',
                    error_message       TEXT NOT NULL DEFAULT '',
                    created_at          TEXT NOT NULL DEFAULT to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
                    FOREIGN KEY (schedule_id) REFERENCES schedules(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_schedule_runs_schedule_id ON schedule_runs(schedule_id);
                CREATE INDEX IF NOT EXISTS idx_schedule_runs_started_at  ON schedule_runs(started_at);
                "#,
            )
            .context("running PostgreSQL migrations")?;
            Ok(())
        }
    }

    impl Store for PostgresStore {
        // -----------------------------------------------------------------------
        // Evidence
        // -----------------------------------------------------------------------

        fn store_evidence(&self, ev: &Evidence) -> Result<()> {
            let mut conn = self.pool.get().context("acquiring connection")?;
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
                ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
                ON CONFLICT (id) DO NOTHING"#,
                &[
                    &ev.id.to_string(),
                    &ev.control_id,
                    &(ev.class_uid as i64),
                    &(ev.category_uid as i64),
                    &(ev.activity_id as i64),
                    &ev.time.to_rfc3339(),
                    &confidence_str,
                    &metadata_json,
                    &observables_json,
                    &(status_id_int as i64),
                    &ev.status,
                    &raw_data,
                    &findings_json,
                    &transcript_json,
                    &enrichments_json,
                ],
            )
            .context("inserting evidence")?;
            Ok(())
        }

        fn get_evidence(&self, id: Uuid) -> Result<Evidence> {
            let mut conn = self.pool.get().context("acquiring connection")?;
            let rows = conn
                .query(
                    r#"SELECT id, control_id, class_uid, category_uid, activity_id,
                        timestamp, confidence_level, metadata_json, observables_json,
                        status_id, status, raw_data, findings_json,
                        test_transcript_json, enrichments_json
                       FROM evidence WHERE id = $1"#,
                    &[&id.to_string()],
                )
                .context("querying evidence by id")?;
            let row = rows
                .into_iter()
                .next()
                .ok_or_else(|| anyhow!("evidence {id} not found"))?;
            scan_evidence(&row)
        }

        fn query_evidence(&self, query: &EvidenceQuery) -> Result<Vec<Evidence>> {
            let mut conn = self.pool.get().context("acquiring connection")?;
            let mut sql = String::from(
                r#"SELECT id, control_id, class_uid, category_uid, activity_id,
                    timestamp, confidence_level, metadata_json, observables_json,
                    status_id, status, raw_data, findings_json,
                    test_transcript_json, enrichments_json
                   FROM evidence WHERE 1=1"#,
            );
            let mut params: Vec<Box<dyn r2d2_postgres::postgres::types::ToSql + Sync>> = Vec::new();
            let mut idx = 1usize;

            if let Some(cid) = &query.control_id {
                sql.push_str(&format!(" AND control_id = ${idx}"));
                params.push(Box::new(cid.clone()));
                idx += 1;
            }
            if let Some(src) = &query.source {
                // JSON path filter: metadata_json contains source.system
                sql.push_str(&format!(
                    " AND metadata_json::jsonb -> 'source' ->> 'system' = ${idx}"
                ));
                params.push(Box::new(src.clone()));
                idx += 1;
            }
            if let Some(from) = &query.from_time {
                sql.push_str(&format!(" AND timestamp >= ${idx}"));
                params.push(Box::new(from.to_rfc3339()));
                idx += 1;
            }
            if let Some(to) = &query.to_time {
                sql.push_str(&format!(" AND timestamp <= ${idx}"));
                params.push(Box::new(to.to_rfc3339()));
                idx += 1;
            }

            sql.push_str(" ORDER BY timestamp DESC");

            if let Some(limit) = query.limit {
                sql.push_str(&format!(" LIMIT {limit}"));
            }

            let refs: Vec<&(dyn r2d2_postgres::postgres::types::ToSql + Sync)> =
                params.iter().map(|b| b.as_ref()).collect();
            let rows = conn
                .query(sql.as_str(), refs.as_slice())
                .context("querying evidence")?;
            rows.iter().map(scan_evidence).collect()
        }

        // -----------------------------------------------------------------------
        // Control Status
        // -----------------------------------------------------------------------

        fn store_control_status(&self, status: &ControlStatus) -> Result<()> {
            let mut conn = self.pool.get().context("acquiring connection")?;
            let evidence_ids_json = serde_json::to_string(&status.evidence_ids)?;
            conn.execute(
                r#"INSERT INTO control_status (
                    id, control_id, timestamp, status, confidence,
                    evidence_ids_json, evaluation_details
                ) VALUES ($1,$2,$3,$4,$5,$6,$7)
                ON CONFLICT (id) DO NOTHING"#,
                &[
                    &status.id.to_string(),
                    &status.control_id,
                    &status.timestamp.to_rfc3339(),
                    &status.status,
                    &status.confidence,
                    &evidence_ids_json,
                    &status.evaluation_details,
                ],
            )
            .context("inserting control status")?;
            Ok(())
        }

        fn get_control_status(&self, control_id: &str) -> Result<ControlStatus> {
            let mut conn = self.pool.get().context("acquiring connection")?;
            let rows = conn
                .query(
                    r#"SELECT id, control_id, timestamp, status, confidence,
                        evidence_ids_json, evaluation_details
                       FROM control_status WHERE control_id = $1
                       ORDER BY timestamp DESC LIMIT 1"#,
                    &[&control_id],
                )
                .context("querying control status")?;
            let row = rows
                .into_iter()
                .next()
                .ok_or_else(|| anyhow!("no status found for control {control_id:?}"))?;
            scan_control_status(&row)
        }

        fn query_history(
            &self,
            control_id: &str,
            from: DateTime<Utc>,
            to: DateTime<Utc>,
        ) -> Result<Vec<ControlStatus>> {
            let mut conn = self.pool.get().context("acquiring connection")?;
            let rows = conn
                .query(
                    r#"SELECT id, control_id, timestamp, status, confidence,
                        evidence_ids_json, evaluation_details
                       FROM control_status
                       WHERE control_id = $1 AND timestamp >= $2 AND timestamp <= $3
                       ORDER BY timestamp ASC"#,
                    &[&control_id, &from.to_rfc3339(), &to.to_rfc3339()],
                )
                .context("querying control history")?;
            rows.iter().map(scan_control_status).collect()
        }

        // -----------------------------------------------------------------------
        // Schedules
        // -----------------------------------------------------------------------

        fn store_schedule(&self, sched: &Schedule) -> Result<()> {
            let mut conn = self.pool.get().context("acquiring connection")?;
            let modules_json = serde_json::to_string(&sched.modules)?;
            conn.execute(
                r#"INSERT INTO schedules (
                    id, control_id, cron_expr, modules_json, enabled,
                    max_safety_level, environment_scope, catch_up,
                    last_run, next_run, created_at, updated_at
                ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
                ON CONFLICT (id) DO UPDATE SET
                    control_id = EXCLUDED.control_id,
                    cron_expr = EXCLUDED.cron_expr,
                    modules_json = EXCLUDED.modules_json,
                    enabled = EXCLUDED.enabled,
                    max_safety_level = EXCLUDED.max_safety_level,
                    environment_scope = EXCLUDED.environment_scope,
                    catch_up = EXCLUDED.catch_up,
                    last_run = EXCLUDED.last_run,
                    next_run = EXCLUDED.next_run,
                    updated_at = EXCLUDED.updated_at"#,
                &[
                    &sched.id,
                    &sched.control_id,
                    &sched.cron_expr,
                    &modules_json,
                    &(sched.enabled as i64),
                    &sched.max_safety_level,
                    &sched.environment_scope,
                    &(sched.catch_up as i64),
                    &sched.last_run.map(|t| t.to_rfc3339()),
                    &sched.next_run.map(|t| t.to_rfc3339()),
                    &sched.created_at.to_rfc3339(),
                    &sched.updated_at.to_rfc3339(),
                ],
            )
            .context("storing schedule")?;
            Ok(())
        }

        fn get_schedule(&self, id: &str) -> Result<Schedule> {
            let mut conn = self.pool.get().context("acquiring connection")?;
            let rows = conn
                .query(
                    r#"SELECT id, control_id, cron_expr, modules_json, enabled,
                        max_safety_level, environment_scope, catch_up,
                        last_run, next_run, created_at, updated_at
                       FROM schedules WHERE id = $1"#,
                    &[&id],
                )
                .context("querying schedule")?;
            let row = rows
                .into_iter()
                .next()
                .ok_or_else(|| anyhow!("schedule {id:?} not found"))?;
            scan_schedule(&row)
        }

        fn list_schedules(&self) -> Result<Vec<Schedule>> {
            let mut conn = self.pool.get().context("acquiring connection")?;
            let rows = conn
                .query(
                    r#"SELECT id, control_id, cron_expr, modules_json, enabled,
                        max_safety_level, environment_scope, catch_up,
                        last_run, next_run, created_at, updated_at
                       FROM schedules ORDER BY created_at ASC"#,
                    &[],
                )
                .context("listing schedules")?;
            rows.iter().map(scan_schedule).collect()
        }

        fn delete_schedule(&self, id: &str) -> Result<()> {
            let mut conn = self.pool.get().context("acquiring connection")?;
            let affected = conn
                .execute("DELETE FROM schedules WHERE id = $1", &[&id])
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
            let mut conn = self.pool.get().context("acquiring connection")?;
            let results_json = serde_json::to_string(&run.module_results)?;
            conn.execute(
                r#"INSERT INTO schedule_runs (
                    id, schedule_id, started_at, completed_at, status,
                    module_results_json, error_message
                ) VALUES ($1,$2,$3,$4,$5,$6,$7)"#,
                &[
                    &run.id,
                    &run.schedule_id,
                    &run.started_at.to_rfc3339(),
                    &run.completed_at.to_rfc3339(),
                    &run.status,
                    &results_json,
                    &run.error,
                ],
            )
            .context("storing schedule run")?;
            Ok(())
        }

        fn list_schedule_runs(&self, schedule_id: &str, limit: usize) -> Result<Vec<ScheduleRun>> {
            let mut conn = self.pool.get().context("acquiring connection")?;
            let rows = conn
                .query(
                    r#"SELECT id, schedule_id, started_at, completed_at, status,
                        module_results_json, error_message
                       FROM schedule_runs WHERE schedule_id = $1
                       ORDER BY started_at DESC LIMIT $2"#,
                    &[&schedule_id, &(limit as i64)],
                )
                .context("listing schedule runs")?;
            rows.iter().map(scan_schedule_run).collect()
        }

        // -----------------------------------------------------------------------
        // Lifecycle
        // -----------------------------------------------------------------------

        fn prune_evidence(&self, older_than: DateTime<Utc>) -> Result<u64> {
            let mut conn = self.pool.get().context("acquiring connection")?;
            let affected = conn
                .execute(
                    "DELETE FROM evidence WHERE timestamp < $1",
                    &[&older_than.to_rfc3339()],
                )
                .context("pruning evidence")?;
            Ok(affected)
        }

        fn close(&self) -> Result<()> {
            // Pool handles connection cleanup on drop.
            Ok(())
        }
    }

    // ---------------------------------------------------------------------------
    // Row scan helpers
    // ---------------------------------------------------------------------------

    fn parse_rfc3339(s: &str) -> Result<DateTime<Utc>> {
        DateTime::parse_from_rfc3339(s)
            .map(|dt| dt.with_timezone(&Utc))
            .with_context(|| format!("parsing timestamp: {s}"))
    }

    fn scan_evidence(row: &r2d2_postgres::postgres::Row) -> Result<Evidence> {
        let id_str: String = row.get(0);
        let timestamp_str: String = row.get(5);
        let confidence_str: String = row.get(6);
        let metadata_json: String = row.get(7);
        let observables_json: String = row.get(8);
        let status_id_int: i64 = row.get(9);
        let raw_data_str: String = row.get(11);
        let findings_json: String = row.get(12);
        let transcript_json: Option<String> = row.get(13);
        let enrichments_json: Option<String> = row.get(14);

        let id = Uuid::parse_str(&id_str).context("parsing evidence UUID")?;
        let time = parse_rfc3339(&timestamp_str)?;
        let confidence_level = match confidence_str.as_str() {
            "active_verification" => ConfidenceLevel::ActiveVerification,
            _ => ConfidenceLevel::PassiveObservation,
        };
        let metadata: Metadata =
            serde_json::from_str(&metadata_json).context("parsing metadata JSON")?;
        let observables: Vec<Observable> =
            serde_json::from_str(&observables_json).context("parsing observables JSON")?;
        let raw_data: serde_json::Value =
            serde_json::from_str(&raw_data_str).context("parsing raw_data JSON")?;
        let findings: Vec<Finding> =
            serde_json::from_str(&findings_json).context("parsing findings JSON")?;
        let test_transcript = transcript_json
            .as_deref()
            .map(serde_json::from_str)
            .transpose()
            .context("parsing test_transcript JSON")?;
        let enrichments: Vec<Enrichment> = enrichments_json
            .as_deref()
            .map(serde_json::from_str)
            .transpose()
            .context("parsing enrichments JSON")?
            .unwrap_or_default();

        Ok(Evidence {
            id,
            control_id: row.get(1),
            class_uid: row.get::<_, i64>(2) as u32,
            category_uid: row.get::<_, i64>(3) as u32,
            activity_id: row.get::<_, i64>(4) as u32,
            time,
            confidence_level,
            metadata,
            observables,
            status_id: StatusId::from(status_id_int as i32),
            status: row.get(10),
            raw_data,
            findings,
            test_transcript,
            enrichments,
        })
    }

    fn scan_control_status(row: &r2d2_postgres::postgres::Row) -> Result<ControlStatus> {
        let id_str: String = row.get(0);
        let timestamp_str: String = row.get(2);
        let evidence_ids_json: String = row.get(5);

        let id = Uuid::parse_str(&id_str).context("parsing ControlStatus UUID")?;
        let timestamp = parse_rfc3339(&timestamp_str)?;
        let evidence_ids: Vec<Uuid> =
            serde_json::from_str(&evidence_ids_json).context("parsing evidence_ids JSON")?;

        Ok(ControlStatus {
            id,
            control_id: row.get(1),
            timestamp,
            status: row.get(3),
            confidence: row.get(4),
            evidence_ids,
            evaluation_details: row.get(6),
        })
    }

    fn scan_schedule(row: &r2d2_postgres::postgres::Row) -> Result<Schedule> {
        let modules_json: String = row.get(3);
        let enabled: i64 = row.get(4);
        let catch_up: i64 = row.get(7);

        let modules: Vec<String> =
            serde_json::from_str(&modules_json).context("parsing schedule modules JSON")?;
        let last_run = row
            .get::<_, Option<String>>(8)
            .as_deref()
            .map(parse_rfc3339)
            .transpose()?;
        let next_run = row
            .get::<_, Option<String>>(9)
            .as_deref()
            .map(parse_rfc3339)
            .transpose()?;
        let created_at = parse_rfc3339(&row.get::<_, String>(10))?;
        let updated_at = parse_rfc3339(&row.get::<_, String>(11))?;

        Ok(Schedule {
            id: row.get(0),
            control_id: row.get(1),
            cron_expr: row.get(2),
            modules,
            enabled: enabled != 0,
            max_safety_level: row.get(5),
            environment_scope: row.get(6),
            catch_up: catch_up != 0,
            last_run,
            next_run,
            created_at,
            updated_at,
        })
    }

    fn scan_schedule_run(row: &r2d2_postgres::postgres::Row) -> Result<ScheduleRun> {
        let results_json: String = row.get(5);
        let module_results: Vec<ModuleRunResult> =
            serde_json::from_str(&results_json).context("parsing module_results JSON")?;
        let started_at = parse_rfc3339(&row.get::<_, String>(2))?;
        let completed_at = parse_rfc3339(&row.get::<_, String>(3))?;

        Ok(ScheduleRun {
            id: row.get(0),
            schedule_id: row.get(1),
            started_at,
            completed_at,
            status: row.get(4),
            module_results,
            error: row.get(6),
        })
    }

    // ---------------------------------------------------------------------------
    // Tests (require a live PostgreSQL instance — skipped by default)
    // ---------------------------------------------------------------------------

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::evidence::testutil::EvidenceBuilder;

        fn pg_url() -> Option<String> {
            std::env::var("OCEAN_POSTGRES_URL").ok()
        }

        #[test]
        fn postgres_store_connect_and_migrate() {
            let Some(url) = pg_url() else {
                eprintln!("OCEAN_POSTGRES_URL not set — skipping postgres integration test");
                return;
            };
            let store = PostgresStore::connect(&url, 2).expect("connect");
            // Migrations are idempotent — running again should not fail.
            store.migrate().expect("re-migrate");
        }

        #[test]
        fn store_and_retrieve_evidence() {
            let Some(url) = pg_url() else {
                return;
            };
            let store = PostgresStore::connect(&url, 2).expect("connect");
            let ev = EvidenceBuilder::new("mock.mfa_enforcement").build();
            store.store_evidence(&ev).expect("store");
            let fetched = store.get_evidence(ev.id).expect("get");
            assert_eq!(fetched.id, ev.id);
            assert_eq!(fetched.control_id, ev.control_id);
        }

        #[test]
        fn prune_evidence_removes_old_records() {
            let Some(url) = pg_url() else {
                return;
            };
            let store = PostgresStore::connect(&url, 2).expect("connect");
            let ev = EvidenceBuilder::new("prune.test").build();
            store.store_evidence(&ev).expect("store");
            // Prune everything older than now + 1 second — should catch just-stored record.
            let future = Utc::now() + chrono::Duration::seconds(1);
            let pruned = store.prune_evidence(future).expect("prune");
            assert!(pruned >= 1);
        }

        #[test]
        fn store_and_list_schedule() {
            let Some(url) = pg_url() else {
                return;
            };
            let store = PostgresStore::connect(&url, 2).expect("connect");
            let sched = Schedule {
                id: Uuid::new_v4().to_string(),
                control_id: "cc6.1".to_string(),
                cron_expr: "0 * * * *".to_string(),
                modules: vec!["mock.test".to_string()],
                enabled: true,
                max_safety_level: "safe".to_string(),
                environment_scope: "production".to_string(),
                catch_up: false,
                last_run: None,
                next_run: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };
            store.store_schedule(&sched).expect("store schedule");
            let all = store.list_schedules().expect("list");
            assert!(all.iter().any(|s| s.id == sched.id));
            store.delete_schedule(&sched.id).expect("delete");
        }

        #[test]
        fn connection_failure_returns_error() {
            let result = PostgresStore::connect("postgres://invalid:5432/nodb", 1);
            assert!(result.is_err(), "expected error for bad connection URL");
        }
    }
}

// Re-export at module level when the feature is active.
#[cfg(feature = "postgres")]
pub use inner::PostgresStore;
