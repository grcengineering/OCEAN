package testutil

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/grcengineering/ocean/internal/control"
	"github.com/grcengineering/ocean/internal/evidence"
	"github.com/grcengineering/ocean/internal/scheduler"
	"github.com/grcengineering/ocean/internal/storage"
)

// MemoryStore is a thread-safe in-memory implementation of storage.Store
// for use in tests. It provides full CRUD for evidence, control status,
// attestations, and schedules without touching disk.
type MemoryStore struct {
	mu              sync.RWMutex
	evidences       map[uuid.UUID]*evidence.Evidence
	controlStatuses map[string][]control.ControlStatus
	attestations    map[string][]byte
	schedules       map[string]*scheduler.Schedule
	scheduleRuns    map[string][]scheduler.ScheduleRun
	closed          bool
}

// Compile-time interface check.
var _ storage.Store = (*MemoryStore)(nil)

// NewMemoryStore creates a new empty in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		evidences:       make(map[uuid.UUID]*evidence.Evidence),
		controlStatuses: make(map[string][]control.ControlStatus),
		attestations:    make(map[string][]byte),
		schedules:       make(map[string]*scheduler.Schedule),
		scheduleRuns:    make(map[string][]scheduler.ScheduleRun),
	}
}

func (m *MemoryStore) StoreEvidence(_ context.Context, ev evidence.Evidence) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.evidences[ev.ID] = &ev
	return nil
}

func (m *MemoryStore) GetEvidence(_ context.Context, id uuid.UUID) (*evidence.Evidence, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ev, ok := m.evidences[id]
	if !ok {
		return nil, fmt.Errorf("evidence %s not found", id)
	}
	return ev, nil
}

func (m *MemoryStore) QueryEvidence(_ context.Context, query storage.EvidenceQuery) ([]evidence.Evidence, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var results []evidence.Evidence
	for _, ev := range m.evidences {
		if query.ControlID != "" && ev.ControlID != query.ControlID {
			continue
		}
		if query.Source != "" && ev.Metadata.Source.System != query.Source {
			continue
		}
		if query.FromTime != nil && ev.Time.Before(*query.FromTime) {
			continue
		}
		if query.ToTime != nil && ev.Time.After(*query.ToTime) {
			continue
		}
		if query.MinConfidence != nil && ev.ConfidenceLevel != *query.MinConfidence {
			continue
		}
		results = append(results, *ev)
		if query.Limit > 0 && len(results) >= query.Limit {
			break
		}
	}
	return results, nil
}

func (m *MemoryStore) StoreControlStatus(_ context.Context, status control.ControlStatus) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.controlStatuses[status.ControlID] = append(m.controlStatuses[status.ControlID], status)
	return nil
}

func (m *MemoryStore) GetControlStatus(_ context.Context, controlID string) (*control.ControlStatus, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	statuses, ok := m.controlStatuses[controlID]
	if !ok || len(statuses) == 0 {
		return nil, fmt.Errorf("control status for %q not found", controlID)
	}
	latest := statuses[len(statuses)-1]
	return &latest, nil
}

func (m *MemoryStore) QueryHistory(_ context.Context, controlID string, from, to time.Time) ([]control.ControlStatus, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var results []control.ControlStatus
	for _, cs := range m.controlStatuses[controlID] {
		if (cs.Timestamp.Equal(from) || cs.Timestamp.After(from)) &&
			(cs.Timestamp.Equal(to) || cs.Timestamp.Before(to)) {
			results = append(results, cs)
		}
	}
	return results, nil
}

func (m *MemoryStore) StoreAttestation(_ context.Context, ref string, envelope []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.attestations[ref] = envelope
	return nil
}

func (m *MemoryStore) GetAttestation(_ context.Context, ref string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	data, ok := m.attestations[ref]
	if !ok {
		return nil, fmt.Errorf("attestation %q not found", ref)
	}
	return data, nil
}

func (m *MemoryStore) StoreSchedule(_ context.Context, schedule scheduler.Schedule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.schedules[schedule.ID] = &schedule
	return nil
}

func (m *MemoryStore) GetSchedule(_ context.Context, id string) (*scheduler.Schedule, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.schedules[id]
	if !ok {
		return nil, fmt.Errorf("schedule %q not found", id)
	}
	return s, nil
}

func (m *MemoryStore) ListSchedules(_ context.Context) ([]scheduler.Schedule, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]scheduler.Schedule, 0, len(m.schedules))
	for _, s := range m.schedules {
		result = append(result, *s)
	}
	return result, nil
}

func (m *MemoryStore) DeleteSchedule(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.schedules, id)
	return nil
}

func (m *MemoryStore) StoreScheduleRun(_ context.Context, run scheduler.ScheduleRun) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.scheduleRuns[run.ScheduleID] = append(m.scheduleRuns[run.ScheduleID], run)
	return nil
}

func (m *MemoryStore) ListScheduleRuns(_ context.Context, scheduleID string, limit int) ([]scheduler.ScheduleRun, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	runs := m.scheduleRuns[scheduleID]
	if limit > 0 && len(runs) > limit {
		runs = runs[len(runs)-limit:]
	}
	return runs, nil
}

func (m *MemoryStore) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

// EvidenceCount returns the number of stored evidence records.
func (m *MemoryStore) EvidenceCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.evidences)
}
