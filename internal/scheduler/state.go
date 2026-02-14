// Package scheduler defines types for OCEAN's scheduling subsystem, which
// orchestrates periodic evidence collection and control evaluation.
package scheduler

import (
	"time"
)

// Schedule represents a recurring job that collects evidence for one or more
// controls using the specified modules. Schedules are the mechanism for
// continuous monitoring and uptime calculation.
type Schedule struct {
	ID               string     `json:"id"`
	ControlID        string     `json:"control_id,omitempty"`
	CronExpr         string     `json:"cron_expr"`
	Modules          []string   `json:"modules"`
	MaxSafetyLevel   string     `json:"max_safety_level"`
	EnvironmentScope string     `json:"environment_scope"`
	Enabled          bool       `json:"enabled"`
	CatchUp          bool       `json:"catch_up"`
	LastRun          *time.Time `json:"last_run,omitempty"`
	NextRun          *time.Time `json:"next_run,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// Run status constants.
const (
	RunStatusSuccess        = "success"
	RunStatusPartialFailure = "partial_failure"
	RunStatusFailure        = "failure"
)

// Module run status constants.
const (
	ModuleStatusSuccess = "success"
	ModuleStatusFailure = "failure"
	ModuleStatusSkipped = "skipped"
)

// ScheduleRun records the outcome of a single execution of a schedule.
type ScheduleRun struct {
	ID            string            `json:"id"`
	ScheduleID    string            `json:"schedule_id"`
	StartedAt     time.Time         `json:"started_at"`
	CompletedAt   time.Time         `json:"completed_at"`
	Status        string            `json:"status"` // success, partial_failure, failure
	ModuleResults []ModuleRunResult `json:"module_results"`
	Error         string            `json:"error,omitempty"`
}

// ModuleRunResult records the outcome of executing a single module within a
// scheduled run.
type ModuleRunResult struct {
	ModuleID      string `json:"module_id"`
	Status        string `json:"status"` // success, failure, skipped
	EvidenceCount int    `json:"evidence_count"`
	Error         string `json:"error,omitempty"`
}
