// Package storage defines the persistence interface for OCEAN's evidence,
// control status, and attestation data.
package storage

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/grcengineering/ocean/internal/control"
	"github.com/grcengineering/ocean/internal/evidence"
	"github.com/grcengineering/ocean/internal/scheduler"
)

// Store is the persistence interface. Implementations may use SQLite (default),
// PostgreSQL (enterprise), or any other backend that satisfies these contracts.
type Store interface {
	// Evidence
	StoreEvidence(ctx context.Context, ev evidence.Evidence) error
	GetEvidence(ctx context.Context, id uuid.UUID) (*evidence.Evidence, error)
	QueryEvidence(ctx context.Context, query EvidenceQuery) ([]evidence.Evidence, error)

	// Control Status
	StoreControlStatus(ctx context.Context, status control.ControlStatus) error
	GetControlStatus(ctx context.Context, controlID string) (*control.ControlStatus, error)
	QueryHistory(ctx context.Context, controlID string, from, to time.Time) ([]control.ControlStatus, error)

	// Attestation
	StoreAttestation(ctx context.Context, ref string, envelope []byte) error
	GetAttestation(ctx context.Context, ref string) ([]byte, error)

	// Schedules
	StoreSchedule(ctx context.Context, schedule scheduler.Schedule) error
	GetSchedule(ctx context.Context, id string) (*scheduler.Schedule, error)
	ListSchedules(ctx context.Context) ([]scheduler.Schedule, error)
	DeleteSchedule(ctx context.Context, id string) error
	StoreScheduleRun(ctx context.Context, run scheduler.ScheduleRun) error
	ListScheduleRuns(ctx context.Context, scheduleID string, limit int) ([]scheduler.ScheduleRun, error)

	// Lifecycle
	Close() error
}

// EvidenceQuery defines filters for querying evidence.
type EvidenceQuery struct {
	ControlID     string
	Source        string
	FromTime      *time.Time
	ToTime        *time.Time
	MinConfidence *evidence.ConfidenceLevel
	Limit         int
	Cursor        string
}
