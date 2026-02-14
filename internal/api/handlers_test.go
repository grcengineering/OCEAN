package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grcengineering/ocean/internal/control"
	"github.com/grcengineering/ocean/internal/evidence"
	"github.com/grcengineering/ocean/internal/module"
	"github.com/grcengineering/ocean/internal/scheduler"
	"github.com/grcengineering/ocean/internal/storage"
)

// --- mock store ---

type mockStore struct {
	evidences       map[uuid.UUID]*evidence.Evidence
	controlStatuses map[string][]control.ControlStatus
	attestations    map[string][]byte
	queryFunc       func(ctx context.Context, query storage.EvidenceQuery) ([]evidence.Evidence, error)
}

func newMockStore() *mockStore {
	return &mockStore{
		evidences:       make(map[uuid.UUID]*evidence.Evidence),
		controlStatuses: make(map[string][]control.ControlStatus),
		attestations:    make(map[string][]byte),
	}
}

func (m *mockStore) StoreEvidence(_ context.Context, ev evidence.Evidence) error {
	m.evidences[ev.ID] = &ev
	return nil
}

func (m *mockStore) GetEvidence(_ context.Context, id uuid.UUID) (*evidence.Evidence, error) {
	ev, ok := m.evidences[id]
	if !ok {
		return nil, fmt.Errorf("evidence not found")
	}
	return ev, nil
}

func (m *mockStore) QueryEvidence(ctx context.Context, query storage.EvidenceQuery) ([]evidence.Evidence, error) {
	if m.queryFunc != nil {
		return m.queryFunc(ctx, query)
	}
	var results []evidence.Evidence
	for _, ev := range m.evidences {
		if query.ControlID != "" && ev.ControlID != query.ControlID {
			continue
		}
		if query.Source != "" && ev.Metadata.Source.System != query.Source {
			continue
		}
		results = append(results, *ev)
	}
	limit := query.Limit
	if limit <= 0 {
		limit = 50
	}
	if len(results) > limit {
		results = results[:limit]
	}
	return results, nil
}

func (m *mockStore) StoreControlStatus(_ context.Context, status control.ControlStatus) error {
	m.controlStatuses[status.ControlID] = append(m.controlStatuses[status.ControlID], status)
	return nil
}

func (m *mockStore) GetControlStatus(_ context.Context, controlID string) (*control.ControlStatus, error) {
	statuses, ok := m.controlStatuses[controlID]
	if !ok || len(statuses) == 0 {
		return nil, fmt.Errorf("control status not found")
	}
	return &statuses[len(statuses)-1], nil
}

func (m *mockStore) QueryHistory(_ context.Context, controlID string, from, to time.Time) ([]control.ControlStatus, error) {
	statuses, ok := m.controlStatuses[controlID]
	if !ok {
		return nil, nil
	}
	var results []control.ControlStatus
	for _, s := range statuses {
		if (s.Timestamp.Equal(from) || s.Timestamp.After(from)) &&
			(s.Timestamp.Equal(to) || s.Timestamp.Before(to)) {
			results = append(results, s)
		}
	}
	return results, nil
}

func (m *mockStore) StoreAttestation(_ context.Context, ref string, envelope []byte) error {
	m.attestations[ref] = envelope
	return nil
}

func (m *mockStore) GetAttestation(_ context.Context, ref string) ([]byte, error) {
	env, ok := m.attestations[ref]
	if !ok {
		return nil, fmt.Errorf("attestation not found")
	}
	return env, nil
}

func (m *mockStore) StoreSchedule(_ context.Context, _ scheduler.Schedule) error   { return nil }
func (m *mockStore) GetSchedule(_ context.Context, _ string) (*scheduler.Schedule, error) {
	return nil, fmt.Errorf("not found")
}
func (m *mockStore) ListSchedules(_ context.Context) ([]scheduler.Schedule, error) { return nil, nil }
func (m *mockStore) DeleteSchedule(_ context.Context, _ string) error              { return nil }
func (m *mockStore) StoreScheduleRun(_ context.Context, _ scheduler.ScheduleRun) error {
	return nil
}
func (m *mockStore) ListScheduleRuns(_ context.Context, _ string, _ int) ([]scheduler.ScheduleRun, error) {
	return nil, nil
}
func (m *mockStore) Close() error { return nil }

// --- test helpers ---

func testServer(t *testing.T) (*Server, *mockStore) {
	t.Helper()
	store := newMockStore()
	reg := module.NewRegistry()
	srv := NewServer(store, reg, "test-token", 0)
	return srv, store
}

func doRequest(t *testing.T, handler http.Handler, method, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func sampleEvidence(id uuid.UUID, controlID string) evidence.Evidence {
	return evidence.Evidence{
		ID:              id,
		ControlID:       controlID,
		ClassUID:        6003,
		CategoryUID:     6,
		ActivityID:      1,
		Time:            time.Now().UTC(),
		ConfidenceLevel: evidence.PassiveObservation,
		Metadata: evidence.Metadata{
			Module: evidence.ModuleInfo{Name: "mock.test", Version: "0.1.0", Type: "collector"},
			Source: evidence.SourceInfo{System: "mock", APIVersion: "v1", Endpoint: "/mock"},
		},
		Observables: []evidence.Observable{{Type: "policy", Value: "mfa-enabled"}},
		StatusID:    evidence.StatusEffective,
		Status:      "effective",
		RawData:     json.RawMessage(`{"test": true}`),
		Findings:    []evidence.Finding{},
		Attestation: evidence.AttestationRef{
			Type:            "collection",
			DSSEEnvelopeRef: "attest-" + id.String(),
			Digest:          "sha256:abc123",
			Signer:          "ed25519:testkey",
		},
	}
}

// ============================================================
// T147: Error response helper tests
// ============================================================

func TestErrorResponse_NotFound(t *testing.T) {
	srv, _ := testServer(t)
	handler := srv.Handler()

	rec := doRequest(t, handler, "GET", "/api/v1/evidence/"+uuid.New().String(), "test-token")
	assert.Equal(t, http.StatusNotFound, rec.Code)

	var resp ErrorBody
	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "NOT_FOUND", resp.Error.Code)
	assert.NotEmpty(t, resp.Error.Message)
}

func TestErrorResponse_ContentType(t *testing.T) {
	srv, _ := testServer(t)
	handler := srv.Handler()

	rec := doRequest(t, handler, "GET", "/api/v1/evidence/"+uuid.New().String(), "test-token")
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
}

// ============================================================
// T145: Bearer token authentication middleware tests
// ============================================================

func TestAuthMiddleware_NoToken(t *testing.T) {
	srv, _ := testServer(t)
	handler := srv.Handler()

	rec := doRequest(t, handler, "GET", "/api/v1/evidence", "")
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	var resp ErrorBody
	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "UNAUTHORIZED", resp.Error.Code)
}

func TestAuthMiddleware_InvalidToken(t *testing.T) {
	srv, _ := testServer(t)
	handler := srv.Handler()

	rec := doRequest(t, handler, "GET", "/api/v1/evidence", "wrong-token")
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestAuthMiddleware_ValidToken(t *testing.T) {
	srv, _ := testServer(t)
	handler := srv.Handler()

	rec := doRequest(t, handler, "GET", "/api/v1/evidence", "test-token")
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestAuthMiddleware_HealthSkipsAuth(t *testing.T) {
	srv, _ := testServer(t)
	handler := srv.Handler()

	rec := doRequest(t, handler, "GET", "/api/v1/health", "")
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestAuthMiddleware_MalformedHeader(t *testing.T) {
	srv, _ := testServer(t)
	handler := srv.Handler()

	req := httptest.NewRequest("GET", "/api/v1/evidence", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// ============================================================
// T148: GET /api/v1/evidence - list evidence with query params
// ============================================================

func TestListEvidence_Empty(t *testing.T) {
	srv, _ := testServer(t)
	handler := srv.Handler()

	rec := doRequest(t, handler, "GET", "/api/v1/evidence", "test-token")
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp ListResponse
	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, 0, resp.dataLen(t))
	assert.False(t, resp.Meta.HasMore)
}

func TestListEvidence_WithData(t *testing.T) {
	srv, store := testServer(t)
	handler := srv.Handler()

	ev := sampleEvidence(uuid.New(), "CTRL-001")
	store.StoreEvidence(context.Background(), ev)

	rec := doRequest(t, handler, "GET", "/api/v1/evidence", "test-token")
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp ListResponse
	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, 1, resp.dataLen(t))
}

func TestListEvidence_FilterByControlID(t *testing.T) {
	srv, store := testServer(t)
	handler := srv.Handler()

	ev1 := sampleEvidence(uuid.New(), "CTRL-001")
	ev2 := sampleEvidence(uuid.New(), "CTRL-002")
	store.StoreEvidence(context.Background(), ev1)
	store.StoreEvidence(context.Background(), ev2)

	rec := doRequest(t, handler, "GET", "/api/v1/evidence?control_id=CTRL-001", "test-token")
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp ListResponse
	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, 1, resp.dataLen(t))
}

func TestListEvidence_FilterBySource(t *testing.T) {
	srv, store := testServer(t)
	handler := srv.Handler()

	ev := sampleEvidence(uuid.New(), "CTRL-001")
	store.StoreEvidence(context.Background(), ev)

	rec := doRequest(t, handler, "GET", "/api/v1/evidence?source=mock", "test-token")
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp ListResponse
	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, 1, resp.dataLen(t))
}

func TestListEvidence_LimitClamp(t *testing.T) {
	srv, store := testServer(t)
	handler := srv.Handler()

	// Store 3 records but request limit=2
	for i := 0; i < 3; i++ {
		ev := sampleEvidence(uuid.New(), "CTRL-001")
		store.StoreEvidence(context.Background(), ev)
	}

	// Use the queryFunc to properly respect limit
	store.queryFunc = func(_ context.Context, query storage.EvidenceQuery) ([]evidence.Evidence, error) {
		var results []evidence.Evidence
		for _, ev := range store.evidences {
			results = append(results, *ev)
		}
		limit := query.Limit
		if limit <= 0 {
			limit = 50
		}
		if len(results) > limit {
			results = results[:limit]
		}
		return results, nil
	}

	rec := doRequest(t, handler, "GET", "/api/v1/evidence?limit=2", "test-token")
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp ListResponse
	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, 2, resp.dataLen(t))
	assert.True(t, resp.Meta.HasMore)
}

func TestListEvidence_MaxLimit(t *testing.T) {
	srv, store := testServer(t)
	handler := srv.Handler()

	// A queryFunc that tracks the limit it received
	var capturedLimit int
	store.queryFunc = func(_ context.Context, query storage.EvidenceQuery) ([]evidence.Evidence, error) {
		capturedLimit = query.Limit
		return nil, nil
	}

	doRequest(t, handler, "GET", "/api/v1/evidence?limit=999", "test-token")
	// Max should be clamped to 200+1 for has_more detection
	assert.LessOrEqual(t, capturedLimit, 201)
}

func TestListEvidence_InvalidLimit(t *testing.T) {
	srv, _ := testServer(t)
	handler := srv.Handler()

	rec := doRequest(t, handler, "GET", "/api/v1/evidence?limit=abc", "test-token")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestListEvidence_TimeFilters(t *testing.T) {
	srv, store := testServer(t)
	handler := srv.Handler()

	var capturedQuery storage.EvidenceQuery
	store.queryFunc = func(_ context.Context, query storage.EvidenceQuery) ([]evidence.Evidence, error) {
		capturedQuery = query
		return nil, nil
	}

	from := "2024-01-01T00:00:00Z"
	to := "2024-12-31T23:59:59Z"
	doRequest(t, handler, "GET", "/api/v1/evidence?from_time="+from+"&to_time="+to, "test-token")

	require.NotNil(t, capturedQuery.FromTime)
	require.NotNil(t, capturedQuery.ToTime)
}

// ============================================================
// T149: GET /api/v1/evidence/{id} - single evidence
// ============================================================

func TestGetEvidence_Found(t *testing.T) {
	srv, store := testServer(t)
	handler := srv.Handler()

	id := uuid.New()
	ev := sampleEvidence(id, "CTRL-001")
	store.StoreEvidence(context.Background(), ev)

	rec := doRequest(t, handler, "GET", "/api/v1/evidence/"+id.String(), "test-token")
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp SingleResponse
	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.NotNil(t, resp.Data)
}

func TestGetEvidence_NotFound(t *testing.T) {
	srv, _ := testServer(t)
	handler := srv.Handler()

	rec := doRequest(t, handler, "GET", "/api/v1/evidence/"+uuid.New().String(), "test-token")
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestGetEvidence_InvalidUUID(t *testing.T) {
	srv, _ := testServer(t)
	handler := srv.Handler()

	rec := doRequest(t, handler, "GET", "/api/v1/evidence/not-a-uuid", "test-token")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ============================================================
// T150: GET /api/v1/evidence/{id}/provenance
// ============================================================

func TestGetProvenance_Found(t *testing.T) {
	srv, store := testServer(t)
	handler := srv.Handler()

	id := uuid.New()
	ev := sampleEvidence(id, "CTRL-001")
	store.StoreEvidence(context.Background(), ev)
	// Store the attestation
	store.StoreAttestation(context.Background(), ev.Attestation.DSSEEnvelopeRef, []byte(`{"payloadType":"test"}`))

	rec := doRequest(t, handler, "GET", "/api/v1/evidence/"+id.String()+"/provenance", "test-token")
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp SingleResponse
	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.NotNil(t, resp.Data)
}

func TestGetProvenance_EvidenceNotFound(t *testing.T) {
	srv, _ := testServer(t)
	handler := srv.Handler()

	rec := doRequest(t, handler, "GET", "/api/v1/evidence/"+uuid.New().String()+"/provenance", "test-token")
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ============================================================
// T151: GET /api/v1/controls - list controls
// ============================================================

func TestListControls_Empty(t *testing.T) {
	srv, _ := testServer(t)
	handler := srv.Handler()

	rec := doRequest(t, handler, "GET", "/api/v1/controls", "test-token")
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp ListResponse
	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, 0, resp.dataLen(t))
}

func TestListControls_WithControls(t *testing.T) {
	store := newMockStore()
	reg := module.NewRegistry()
	srv := NewServer(store, reg, "test-token", 0)
	srv.SetControls([]*control.Control{
		{ID: "CTRL-001", Name: "MFA Enforcement", Description: "Ensure MFA is enabled"},
		{ID: "CTRL-002", Name: "Password Policy", Description: "Enforce password complexity"},
	})
	handler := srv.Handler()

	rec := doRequest(t, handler, "GET", "/api/v1/controls", "test-token")
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp ListResponse
	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, 2, resp.dataLen(t))
}

// ============================================================
// T152: GET /api/v1/controls/{id} - single control
// ============================================================

func TestGetControl_Found(t *testing.T) {
	store := newMockStore()
	reg := module.NewRegistry()
	srv := NewServer(store, reg, "test-token", 0)
	srv.SetControls([]*control.Control{
		{ID: "CTRL-001", Name: "MFA Enforcement"},
	})
	handler := srv.Handler()

	rec := doRequest(t, handler, "GET", "/api/v1/controls/CTRL-001", "test-token")
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp SingleResponse
	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.NotNil(t, resp.Data)
}

func TestGetControl_NotFound(t *testing.T) {
	srv, _ := testServer(t)
	handler := srv.Handler()

	rec := doRequest(t, handler, "GET", "/api/v1/controls/NONEXISTENT", "test-token")
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ============================================================
// T153: GET /api/v1/controls/{id}/status
// ============================================================

func TestGetControlStatus_Found(t *testing.T) {
	srv, store := testServer(t)
	handler := srv.Handler()

	cs := control.ControlStatus{
		ID:          uuid.New(),
		ControlID:   "CTRL-001",
		Timestamp:   time.Now().UTC(),
		Status:      "effective",
		Confidence:  "high",
		EvidenceIDs: []uuid.UUID{uuid.New()},
	}
	store.StoreControlStatus(context.Background(), cs)

	rec := doRequest(t, handler, "GET", "/api/v1/controls/CTRL-001/status", "test-token")
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestGetControlStatus_NotFound(t *testing.T) {
	srv, _ := testServer(t)
	handler := srv.Handler()

	rec := doRequest(t, handler, "GET", "/api/v1/controls/NONEXISTENT/status", "test-token")
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ============================================================
// T154: GET /api/v1/controls/{id}/history
// ============================================================

func TestGetControlHistory_Found(t *testing.T) {
	srv, store := testServer(t)
	handler := srv.Handler()

	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		cs := control.ControlStatus{
			ID:          uuid.New(),
			ControlID:   "CTRL-001",
			Timestamp:   now.Add(time.Duration(i) * time.Hour),
			Status:      "effective",
			Confidence:  "high",
			EvidenceIDs: []uuid.UUID{uuid.New()},
		}
		store.StoreControlStatus(context.Background(), cs)
	}

	from := now.Add(-1 * time.Hour).Format(time.RFC3339)
	to := now.Add(5 * time.Hour).Format(time.RFC3339)
	rec := doRequest(t, handler, "GET", "/api/v1/controls/CTRL-001/history?from="+from+"&to="+to, "test-token")
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp, "data")
}

func TestGetControlHistory_MissingParams(t *testing.T) {
	srv, _ := testServer(t)
	handler := srv.Handler()

	rec := doRequest(t, handler, "GET", "/api/v1/controls/CTRL-001/history", "test-token")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ============================================================
// T155: GET /api/v1/attestations/{id}
// ============================================================

func TestGetAttestation_Found(t *testing.T) {
	srv, store := testServer(t)
	handler := srv.Handler()

	envelope := []byte(`{"payloadType":"application/vnd.in-toto+json","payload":"dGVzdA==","signatures":[]}`)
	store.StoreAttestation(context.Background(), "ref-123", envelope)

	rec := doRequest(t, handler, "GET", "/api/v1/attestations/ref-123", "test-token")
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestGetAttestation_NotFound(t *testing.T) {
	srv, _ := testServer(t)
	handler := srv.Handler()

	rec := doRequest(t, handler, "GET", "/api/v1/attestations/nonexistent", "test-token")
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ============================================================
// T156: GET /api/v1/modules
// ============================================================

func TestListModules_Empty(t *testing.T) {
	srv, _ := testServer(t)
	handler := srv.Handler()

	rec := doRequest(t, handler, "GET", "/api/v1/modules", "test-token")
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp ListResponse
	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, 0, resp.dataLen(t))
}

// ============================================================
// T157: GET /api/v1/health
// ============================================================

func TestHealth_OK(t *testing.T) {
	srv, _ := testServer(t)
	handler := srv.Handler()

	rec := doRequest(t, handler, "GET", "/api/v1/health", "")
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "ok", resp["status"])
	assert.NotEmpty(t, resp["version"])
}

// ============================================================
// T146: Request logging middleware tests
// ============================================================

func TestLoggingMiddleware_SetsContentType(t *testing.T) {
	srv, _ := testServer(t)
	handler := srv.Handler()

	rec := doRequest(t, handler, "GET", "/api/v1/health", "")
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
}

// ============================================================
// T144: Server setup tests
// ============================================================

func TestNewServer(t *testing.T) {
	store := newMockStore()
	reg := module.NewRegistry()
	srv := NewServer(store, reg, "tok", 9090)

	assert.NotNil(t, srv)
	assert.Equal(t, 9090, srv.Port)
	assert.Equal(t, "tok", srv.AuthToken)
}

func TestServerHandler_NotNil(t *testing.T) {
	srv, _ := testServer(t)
	assert.NotNil(t, srv.Handler())
}

// ============================================================
// Response types for test unmarshaling
// ============================================================

type ListResponse struct {
	Data json.RawMessage `json:"data"`
	Meta struct {
		Cursor  string `json:"cursor"`
		Limit   int    `json:"limit"`
		HasMore bool   `json:"has_more"`
	} `json:"meta"`
}

// dataLen returns the number of items in the Data array.
func (lr *ListResponse) dataLen(t *testing.T) int {
	t.Helper()
	var items []json.RawMessage
	err := json.Unmarshal(lr.Data, &items)
	require.NoError(t, err)
	return len(items)
}

type SingleResponse struct {
	Data json.RawMessage `json:"data"`
}

type ErrorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}
