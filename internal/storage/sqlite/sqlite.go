// Package sqlite implements the storage.Store interface using a SQLite database
// via the pure-Go modernc.org/sqlite driver (no CGO required).
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"

	"github.com/grcengineering/ocean/internal/control"
	"github.com/grcengineering/ocean/internal/evidence"
	"github.com/grcengineering/ocean/internal/scheduler"
	"github.com/grcengineering/ocean/internal/storage"
)

// Store implements the storage.Store interface backed by SQLite.
type Store struct {
	db *sql.DB
}

// Open creates or opens a SQLite database at the given path and runs
// schema migrations. The parent directory is created if it does not exist.
func Open(dbPath string) (*Store, error) {
	// Ensure parent directory exists.
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("creating storage directory: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(wal)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("opening SQLite database: %w", err)
	}

	// Verify connection.
	if err := db.PingContext(context.Background()); err != nil {
		db.Close()
		return nil, fmt.Errorf("pinging SQLite database: %w", err)
	}

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("running migrations: %w", err)
	}

	return s, nil
}

// migrate creates the database tables if they do not exist.
func (s *Store) migrate() error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS evidence (
			id TEXT PRIMARY KEY,
			control_id TEXT NOT NULL,
			class_uid INTEGER NOT NULL,
			category_uid INTEGER NOT NULL,
			activity_id INTEGER NOT NULL,
			timestamp TEXT NOT NULL,
			confidence_level TEXT NOT NULL,
			metadata_json TEXT NOT NULL,
			observables_json TEXT,
			status_id INTEGER NOT NULL,
			status TEXT NOT NULL,
			raw_data TEXT,
			findings_json TEXT,
			test_transcript_json TEXT,
			attestation_json TEXT,
			enrichments_json TEXT,
			created_at TEXT NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE INDEX IF NOT EXISTS idx_evidence_control_id ON evidence(control_id)`,
		`CREATE INDEX IF NOT EXISTS idx_evidence_timestamp ON evidence(timestamp)`,
		`CREATE TABLE IF NOT EXISTS control_status (
			id TEXT PRIMARY KEY,
			control_id TEXT NOT NULL,
			timestamp TEXT NOT NULL,
			status TEXT NOT NULL,
			confidence TEXT NOT NULL,
			evidence_ids_json TEXT,
			evaluation_details TEXT,
			evaluation_attestation_ref TEXT,
			created_at TEXT NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE INDEX IF NOT EXISTS idx_control_status_control_id ON control_status(control_id)`,
		`CREATE INDEX IF NOT EXISTS idx_control_status_timestamp ON control_status(timestamp)`,
		`CREATE TABLE IF NOT EXISTS attestations (
			ref TEXT PRIMARY KEY,
			envelope TEXT NOT NULL,
			created_at TEXT NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IF NOT EXISTS schedules (
			id TEXT PRIMARY KEY,
			control_id TEXT,
			cron_expr TEXT NOT NULL,
			modules_json TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			max_safety_level TEXT NOT NULL DEFAULT 'safe',
			environment_scope TEXT NOT NULL DEFAULT 'production',
			catch_up INTEGER NOT NULL DEFAULT 0,
			last_run TEXT,
			next_run TEXT,
			created_at TEXT NOT NULL DEFAULT (datetime('now')),
			updated_at TEXT NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IF NOT EXISTS schedule_runs (
			id TEXT PRIMARY KEY,
			schedule_id TEXT NOT NULL,
			started_at TEXT NOT NULL,
			completed_at TEXT NOT NULL,
			status TEXT NOT NULL,
			module_results_json TEXT,
			error_message TEXT,
			created_at TEXT NOT NULL DEFAULT (datetime('now')),
			FOREIGN KEY (schedule_id) REFERENCES schedules(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_schedule_runs_schedule_id ON schedule_runs(schedule_id)`,
		`CREATE INDEX IF NOT EXISTS idx_schedule_runs_started_at ON schedule_runs(started_at)`,
	}

	for _, m := range migrations {
		if _, err := s.db.Exec(m); err != nil {
			return fmt.Errorf("executing migration: %w", err)
		}
	}

	return nil
}

// StoreEvidence persists an evidence record to SQLite.
func (s *Store) StoreEvidence(ctx context.Context, ev evidence.Evidence) error {
	metadataJSON, err := json.Marshal(ev.Metadata)
	if err != nil {
		return fmt.Errorf("marshaling metadata: %w", err)
	}

	observablesJSON, err := json.Marshal(ev.Observables)
	if err != nil {
		return fmt.Errorf("marshaling observables: %w", err)
	}

	findingsJSON, err := json.Marshal(ev.Findings)
	if err != nil {
		return fmt.Errorf("marshaling findings: %w", err)
	}

	var transcriptJSON []byte
	if ev.TestTranscript != nil {
		transcriptJSON, err = json.Marshal(ev.TestTranscript)
		if err != nil {
			return fmt.Errorf("marshaling test transcript: %w", err)
		}
	}

	attestationJSON, err := json.Marshal(ev.Attestation)
	if err != nil {
		return fmt.Errorf("marshaling attestation: %w", err)
	}

	var enrichmentsJSON []byte
	if len(ev.Enrichments) > 0 {
		enrichmentsJSON, err = json.Marshal(ev.Enrichments)
		if err != nil {
			return fmt.Errorf("marshaling enrichments: %w", err)
		}
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO evidence (
			id, control_id, class_uid, category_uid, activity_id,
			timestamp, confidence_level, metadata_json, observables_json,
			status_id, status, raw_data, findings_json,
			test_transcript_json, attestation_json, enrichments_json
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ev.ID.String(),
		ev.ControlID,
		ev.ClassUID,
		ev.CategoryUID,
		ev.ActivityID,
		ev.Time.Format(time.RFC3339Nano),
		string(ev.ConfidenceLevel),
		string(metadataJSON),
		string(observablesJSON),
		ev.StatusID,
		ev.Status,
		string(ev.RawData),
		string(findingsJSON),
		nullableString(transcriptJSON),
		string(attestationJSON),
		nullableString(enrichmentsJSON),
	)
	if err != nil {
		return fmt.Errorf("inserting evidence: %w", err)
	}

	return nil
}

// GetEvidence retrieves a single evidence record by ID.
func (s *Store) GetEvidence(ctx context.Context, id uuid.UUID) (*evidence.Evidence, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, control_id, class_uid, category_uid, activity_id,
			timestamp, confidence_level, metadata_json, observables_json,
			status_id, status, raw_data, findings_json,
			test_transcript_json, attestation_json, enrichments_json
		FROM evidence WHERE id = ?`, id.String())

	return scanEvidence(row)
}

// QueryEvidence returns evidence records matching the given query filters.
func (s *Store) QueryEvidence(ctx context.Context, query storage.EvidenceQuery) ([]evidence.Evidence, error) {
	q := `SELECT id, control_id, class_uid, category_uid, activity_id,
		timestamp, confidence_level, metadata_json, observables_json,
		status_id, status, raw_data, findings_json,
		test_transcript_json, attestation_json, enrichments_json
		FROM evidence WHERE 1=1`
	var args []interface{}

	if query.ControlID != "" {
		q += " AND control_id = ?"
		args = append(args, query.ControlID)
	}
	if query.Source != "" {
		q += " AND json_extract(metadata_json, '$.source.system') = ?"
		args = append(args, query.Source)
	}
	if query.FromTime != nil {
		q += " AND timestamp >= ?"
		args = append(args, query.FromTime.Format(time.RFC3339Nano))
	}
	if query.ToTime != nil {
		q += " AND timestamp <= ?"
		args = append(args, query.ToTime.Format(time.RFC3339Nano))
	}

	q += " ORDER BY timestamp DESC"

	if query.Limit > 0 {
		q += fmt.Sprintf(" LIMIT %d", query.Limit)
	}

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("querying evidence: %w", err)
	}
	defer rows.Close()

	var results []evidence.Evidence
	for rows.Next() {
		ev, err := scanEvidenceRows(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, *ev)
	}

	return results, rows.Err()
}

// StoreControlStatus persists a control status record.
func (s *Store) StoreControlStatus(ctx context.Context, status control.ControlStatus) error {
	evidenceIDsJSON, err := json.Marshal(status.EvidenceIDs)
	if err != nil {
		return fmt.Errorf("marshaling evidence IDs: %w", err)
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO control_status (
			id, control_id, timestamp, status, confidence,
			evidence_ids_json, evaluation_details, evaluation_attestation_ref
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		status.ID.String(),
		status.ControlID,
		status.Timestamp.Format(time.RFC3339Nano),
		status.Status,
		status.Confidence,
		string(evidenceIDsJSON),
		status.EvaluationDetails,
		status.EvaluationAttestationRef,
	)
	if err != nil {
		return fmt.Errorf("inserting control status: %w", err)
	}

	return nil
}

// GetControlStatus retrieves the most recent status for a control.
func (s *Store) GetControlStatus(ctx context.Context, controlID string) (*control.ControlStatus, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, control_id, timestamp, status, confidence,
			evidence_ids_json, evaluation_details, evaluation_attestation_ref
		FROM control_status WHERE control_id = ?
		ORDER BY timestamp DESC LIMIT 1`, controlID)

	return scanControlStatus(row)
}

// QueryHistory returns control statuses for a control within a time range.
func (s *Store) QueryHistory(ctx context.Context, controlID string, from, to time.Time) ([]control.ControlStatus, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, control_id, timestamp, status, confidence,
			evidence_ids_json, evaluation_details, evaluation_attestation_ref
		FROM control_status
		WHERE control_id = ? AND timestamp >= ? AND timestamp <= ?
		ORDER BY timestamp ASC`,
		controlID,
		from.Format(time.RFC3339Nano),
		to.Format(time.RFC3339Nano),
	)
	if err != nil {
		return nil, fmt.Errorf("querying control history: %w", err)
	}
	defer rows.Close()

	var results []control.ControlStatus
	for rows.Next() {
		cs, err := scanControlStatusRows(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, *cs)
	}

	return results, rows.Err()
}

// StoreAttestation persists a DSSE attestation envelope.
func (s *Store) StoreAttestation(ctx context.Context, ref string, envelope []byte) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO attestations (ref, envelope) VALUES (?, ?)`,
		ref, string(envelope))
	if err != nil {
		return fmt.Errorf("storing attestation: %w", err)
	}
	return nil
}

// GetAttestation retrieves an attestation envelope by reference.
func (s *Store) GetAttestation(ctx context.Context, ref string) ([]byte, error) {
	var envelope string
	err := s.db.QueryRowContext(ctx,
		`SELECT envelope FROM attestations WHERE ref = ?`, ref).Scan(&envelope)
	if err != nil {
		return nil, fmt.Errorf("getting attestation: %w", err)
	}
	return []byte(envelope), nil
}

// PruneEvidence deletes evidence records older than maxAge from the database.
// It preserves attestation chain validity by not deleting attestations that are
// still referenced by remaining evidence. Returns the number of records deleted.
func (s *Store) PruneEvidence(ctx context.Context, maxAge time.Duration) (int, error) {
	cutoff := time.Now().UTC().Add(-maxAge).Format(time.RFC3339Nano)

	result, err := s.db.ExecContext(ctx,
		`DELETE FROM evidence WHERE timestamp < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("pruning evidence: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("checking rows affected: %w", err)
	}

	return int(affected), nil
}

// PruneOldEvidence removes evidence records older than maxAge while preserving
// attestation chain validity. It uses a transaction for atomicity and cleans up
// orphaned attestations that no longer reference any evidence. Returns the
// number of pruned evidence records.
func (s *Store) PruneOldEvidence(ctx context.Context, maxAge time.Duration) (int64, error) {
	cutoff := time.Now().UTC().Add(-maxAge).Format(time.RFC3339Nano)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("beginning prune transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // rollback is a no-op after commit

	// Delete old evidence records.
	result, err := tx.ExecContext(ctx,
		`DELETE FROM evidence WHERE timestamp < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("pruning old evidence: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("checking rows affected: %w", err)
	}

	// Clean up orphaned attestations: remove any attestation whose ref is not
	// referenced by any remaining evidence record's attestation_json.
	_, err = tx.ExecContext(ctx,
		`DELETE FROM attestations WHERE ref NOT IN (
			SELECT DISTINCT json_extract(attestation_json, '$.dsse_envelope_ref')
			FROM evidence
			WHERE json_extract(attestation_json, '$.dsse_envelope_ref') IS NOT NULL
		)`)
	if err != nil {
		return 0, fmt.Errorf("cleaning orphaned attestations: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("committing prune transaction: %w", err)
	}

	return affected, nil
}

// Close closes the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// --- Schedule CRUD ---

// StoreSchedule persists a schedule record to SQLite. If a schedule with the
// same ID already exists, it is updated.
func (s *Store) StoreSchedule(ctx context.Context, sched scheduler.Schedule) error {
	modulesJSON, err := json.Marshal(sched.Modules)
	if err != nil {
		return fmt.Errorf("marshaling modules: %w", err)
	}

	enabled := 0
	if sched.Enabled {
		enabled = 1
	}
	catchUp := 0
	if sched.CatchUp {
		catchUp = 1
	}

	var lastRun, nextRun sql.NullString
	if sched.LastRun != nil {
		lastRun = sql.NullString{String: sched.LastRun.Format(time.RFC3339Nano), Valid: true}
	}
	if sched.NextRun != nil {
		nextRun = sql.NullString{String: sched.NextRun.Format(time.RFC3339Nano), Valid: true}
	}

	now := time.Now()
	if sched.CreatedAt.IsZero() {
		sched.CreatedAt = now
	}
	sched.UpdatedAt = now

	_, err = s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO schedules (
			id, control_id, cron_expr, modules_json, enabled,
			max_safety_level, environment_scope, catch_up,
			last_run, next_run, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sched.ID,
		sched.ControlID,
		sched.CronExpr,
		string(modulesJSON),
		enabled,
		sched.MaxSafetyLevel,
		sched.EnvironmentScope,
		catchUp,
		lastRun,
		nextRun,
		sched.CreatedAt.Format(time.RFC3339Nano),
		sched.UpdatedAt.Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("inserting schedule: %w", err)
	}
	return nil
}

// GetSchedule retrieves a schedule by ID.
func (s *Store) GetSchedule(ctx context.Context, id string) (*scheduler.Schedule, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, control_id, cron_expr, modules_json, enabled,
			max_safety_level, environment_scope, catch_up,
			last_run, next_run, created_at, updated_at
		FROM schedules WHERE id = ?`, id)

	return scanSchedule(row)
}

// ListSchedules returns all schedules.
func (s *Store) ListSchedules(ctx context.Context) ([]scheduler.Schedule, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, control_id, cron_expr, modules_json, enabled,
			max_safety_level, environment_scope, catch_up,
			last_run, next_run, created_at, updated_at
		FROM schedules ORDER BY created_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("querying schedules: %w", err)
	}
	defer rows.Close()

	var results []scheduler.Schedule
	for rows.Next() {
		sched, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, *sched)
	}
	return results, rows.Err()
}

// DeleteSchedule removes a schedule and its runs by ID.
func (s *Store) DeleteSchedule(ctx context.Context, id string) error {
	// Delete runs first (FK relationship).
	_, err := s.db.ExecContext(ctx, `DELETE FROM schedule_runs WHERE schedule_id = ?`, id)
	if err != nil {
		return fmt.Errorf("deleting schedule runs: %w", err)
	}

	result, err := s.db.ExecContext(ctx, `DELETE FROM schedules WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("deleting schedule: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking rows affected: %w", err)
	}
	if affected == 0 {
		return fmt.Errorf("schedule %q not found", id)
	}
	return nil
}

// StoreScheduleRun persists a schedule run record.
func (s *Store) StoreScheduleRun(ctx context.Context, run scheduler.ScheduleRun) error {
	resultsJSON, err := json.Marshal(run.ModuleResults)
	if err != nil {
		return fmt.Errorf("marshaling module results: %w", err)
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO schedule_runs (
			id, schedule_id, started_at, completed_at, status,
			module_results_json, error_message
		) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		run.ID,
		run.ScheduleID,
		run.StartedAt.Format(time.RFC3339Nano),
		run.CompletedAt.Format(time.RFC3339Nano),
		run.Status,
		string(resultsJSON),
		run.Error,
	)
	if err != nil {
		return fmt.Errorf("inserting schedule run: %w", err)
	}
	return nil
}

// ListScheduleRuns returns recent runs for a schedule, ordered by most recent first.
func (s *Store) ListScheduleRuns(ctx context.Context, scheduleID string, limit int) ([]scheduler.ScheduleRun, error) {
	if limit <= 0 {
		limit = 10
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT id, schedule_id, started_at, completed_at, status,
			module_results_json, error_message
		FROM schedule_runs WHERE schedule_id = ?
		ORDER BY started_at DESC LIMIT ?`,
		scheduleID, limit)
	if err != nil {
		return nil, fmt.Errorf("querying schedule runs: %w", err)
	}
	defer rows.Close()

	var results []scheduler.ScheduleRun
	for rows.Next() {
		run, err := scanScheduleRun(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, *run)
	}
	return results, rows.Err()
}

// --- scan helpers ---

func scanSchedule(row scanner) (*scheduler.Schedule, error) {
	var (
		id, controlID, cronExpr, modulesJSON string
		maxSafety, envScope                  string
		createdStr, updatedStr               string
		lastRunStr, nextRunStr               sql.NullString
		enabled, catchUp                     int
	)

	err := row.Scan(
		&id, &controlID, &cronExpr, &modulesJSON, &enabled,
		&maxSafety, &envScope, &catchUp,
		&lastRunStr, &nextRunStr, &createdStr, &updatedStr,
	)
	if err != nil {
		return nil, fmt.Errorf("scanning schedule: %w", err)
	}

	var modules []string
	if err := json.Unmarshal([]byte(modulesJSON), &modules); err != nil {
		return nil, fmt.Errorf("unmarshaling modules: %w", err)
	}

	createdAt, err := time.Parse(time.RFC3339Nano, createdStr)
	if err != nil {
		return nil, fmt.Errorf("parsing created_at: %w", err)
	}
	updatedAt, err := time.Parse(time.RFC3339Nano, updatedStr)
	if err != nil {
		return nil, fmt.Errorf("parsing updated_at: %w", err)
	}

	sched := &scheduler.Schedule{
		ID:               id,
		ControlID:        controlID,
		CronExpr:         cronExpr,
		Modules:          modules,
		MaxSafetyLevel:   maxSafety,
		EnvironmentScope: envScope,
		Enabled:          enabled != 0,
		CatchUp:          catchUp != 0,
		CreatedAt:        createdAt,
		UpdatedAt:        updatedAt,
	}

	if lastRunStr.Valid {
		t, err := time.Parse(time.RFC3339Nano, lastRunStr.String)
		if err != nil {
			return nil, fmt.Errorf("parsing last_run: %w", err)
		}
		sched.LastRun = &t
	}
	if nextRunStr.Valid {
		t, err := time.Parse(time.RFC3339Nano, nextRunStr.String)
		if err != nil {
			return nil, fmt.Errorf("parsing next_run: %w", err)
		}
		sched.NextRun = &t
	}

	return sched, nil
}

func scanScheduleRun(row scanner) (*scheduler.ScheduleRun, error) {
	var (
		id, scheduleID, startedStr, completedStr string
		status, resultsJSON, errorMsg             string
	)

	err := row.Scan(
		&id, &scheduleID, &startedStr, &completedStr,
		&status, &resultsJSON, &errorMsg,
	)
	if err != nil {
		return nil, fmt.Errorf("scanning schedule run: %w", err)
	}

	startedAt, err := time.Parse(time.RFC3339Nano, startedStr)
	if err != nil {
		return nil, fmt.Errorf("parsing started_at: %w", err)
	}
	completedAt, err := time.Parse(time.RFC3339Nano, completedStr)
	if err != nil {
		return nil, fmt.Errorf("parsing completed_at: %w", err)
	}

	var moduleResults []scheduler.ModuleRunResult
	if resultsJSON != "" {
		if err := json.Unmarshal([]byte(resultsJSON), &moduleResults); err != nil {
			return nil, fmt.Errorf("unmarshaling module results: %w", err)
		}
	}

	return &scheduler.ScheduleRun{
		ID:            id,
		ScheduleID:    scheduleID,
		StartedAt:     startedAt,
		CompletedAt:   completedAt,
		Status:        status,
		ModuleResults: moduleResults,
		Error:         errorMsg,
	}, nil
}

// --- evidence/control scan helpers ---

type scanner interface {
	Scan(dest ...interface{}) error
}

func scanEvidence(row scanner) (*evidence.Evidence, error) {
	var (
		idStr, controlID, ts, confLevel            string
		metadataJSON, observablesJSON               string
		status, rawData, findingsJSON               string
		attestationJSON                             string
		transcriptJSON, enrichmentsJSON             sql.NullString
		classUID, categoryUID, activityID, statusID int
	)

	err := row.Scan(
		&idStr, &controlID, &classUID, &categoryUID, &activityID,
		&ts, &confLevel, &metadataJSON, &observablesJSON,
		&statusID, &status, &rawData, &findingsJSON,
		&transcriptJSON, &attestationJSON, &enrichmentsJSON,
	)
	if err != nil {
		return nil, fmt.Errorf("scanning evidence: %w", err)
	}

	id, err := uuid.Parse(idStr)
	if err != nil {
		return nil, fmt.Errorf("parsing evidence ID: %w", err)
	}

	timestamp, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return nil, fmt.Errorf("parsing timestamp: %w", err)
	}

	ev := &evidence.Evidence{
		ID:              id,
		ControlID:       controlID,
		ClassUID:        classUID,
		CategoryUID:     categoryUID,
		ActivityID:      activityID,
		Time:            timestamp,
		ConfidenceLevel: evidence.ConfidenceLevel(confLevel),
		StatusID:        evidence.StatusID(statusID),
		Status:          status,
		RawData:         json.RawMessage(rawData),
	}

	if err := json.Unmarshal([]byte(metadataJSON), &ev.Metadata); err != nil {
		return nil, fmt.Errorf("unmarshaling metadata: %w", err)
	}
	if err := json.Unmarshal([]byte(observablesJSON), &ev.Observables); err != nil {
		return nil, fmt.Errorf("unmarshaling observables: %w", err)
	}
	if err := json.Unmarshal([]byte(findingsJSON), &ev.Findings); err != nil {
		return nil, fmt.Errorf("unmarshaling findings: %w", err)
	}
	if err := json.Unmarshal([]byte(attestationJSON), &ev.Attestation); err != nil {
		return nil, fmt.Errorf("unmarshaling attestation: %w", err)
	}

	if transcriptJSON.Valid {
		ev.TestTranscript = &evidence.TestTranscript{}
		if err := json.Unmarshal([]byte(transcriptJSON.String), ev.TestTranscript); err != nil {
			return nil, fmt.Errorf("unmarshaling test transcript: %w", err)
		}
	}

	if enrichmentsJSON.Valid {
		if err := json.Unmarshal([]byte(enrichmentsJSON.String), &ev.Enrichments); err != nil {
			return nil, fmt.Errorf("unmarshaling enrichments: %w", err)
		}
	}

	return ev, nil
}

func scanEvidenceRows(rows *sql.Rows) (*evidence.Evidence, error) {
	return scanEvidence(rows)
}

func scanControlStatus(row scanner) (*control.ControlStatus, error) {
	var (
		idStr, controlID, ts, status, confidence string
		evidenceIDsJSON                           string
		evaluationDetails, evalAttestRef           string
	)

	err := row.Scan(
		&idStr, &controlID, &ts, &status, &confidence,
		&evidenceIDsJSON, &evaluationDetails, &evalAttestRef,
	)
	if err != nil {
		return nil, fmt.Errorf("scanning control status: %w", err)
	}

	id, err := uuid.Parse(idStr)
	if err != nil {
		return nil, fmt.Errorf("parsing control status ID: %w", err)
	}

	timestamp, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return nil, fmt.Errorf("parsing timestamp: %w", err)
	}

	cs := &control.ControlStatus{
		ID:                       id,
		ControlID:                controlID,
		Timestamp:                timestamp,
		Status:                   status,
		Confidence:               confidence,
		EvaluationDetails:        evaluationDetails,
		EvaluationAttestationRef: evalAttestRef,
	}

	if err := json.Unmarshal([]byte(evidenceIDsJSON), &cs.EvidenceIDs); err != nil {
		return nil, fmt.Errorf("unmarshaling evidence IDs: %w", err)
	}

	return cs, nil
}

func scanControlStatusRows(rows *sql.Rows) (*control.ControlStatus, error) {
	return scanControlStatus(rows)
}

// nullableString converts a byte slice to a sql.NullString for nullable TEXT columns.
func nullableString(b []byte) sql.NullString {
	if b == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: string(b), Valid: true}
}

// Compile-time assertion that *Store implements storage.Store.
var _ storage.Store = (*Store)(nil)
