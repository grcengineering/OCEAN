package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/grcengineering/ocean/internal/control"
	"github.com/grcengineering/ocean/internal/evidence"
	"github.com/grcengineering/ocean/internal/module"
	"github.com/grcengineering/ocean/internal/storage"
)

// --- JSON response types ---

// errorDetail is the inner object in an error response.
type errorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// errorResponse is the top-level JSON error envelope.
type errorResponse struct {
	Error errorDetail `json:"error"`
}

// listMeta holds pagination metadata for list endpoints.
type listMeta struct {
	Cursor  string `json:"cursor"`
	Limit   int    `json:"limit"`
	HasMore bool   `json:"has_more"`
}

// listEnvelope is the top-level JSON envelope for list endpoints.
type listEnvelope struct {
	Data interface{} `json:"data"`
	Meta listMeta    `json:"meta"`
}

// singleEnvelope is the top-level JSON envelope for single-resource endpoints.
type singleEnvelope struct {
	Data interface{} `json:"data"`
}

// provenanceChain represents the provenance chain for an evidence record,
// linking the evidence to its attestation envelope.
type provenanceChain struct {
	EvidenceID  string      `json:"evidence_id"`
	ControlID   string      `json:"control_id"`
	CollectedAt string      `json:"collected_at"`
	Attestation interface{} `json:"attestation"`
	Envelope    interface{} `json:"envelope,omitempty"`
}

// historyResponse wraps control history with uptime calculation.
type historyResponse struct {
	Statuses interface{} `json:"statuses"`
	Uptime   interface{} `json:"uptime"`
}

// healthResponse represents the health check payload.
type healthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version"`
	Time    string `json:"time"`
}

// --- error helper (T147) ---

// writeError writes a structured JSON error response.
func writeError(w http.ResponseWriter, httpStatus int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	json.NewEncoder(w).Encode(errorResponse{
		Error: errorDetail{Code: code, Message: message},
	})
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// --- pagination constants ---

const (
	defaultLimit = 50
	maxLimit     = 200
)

// --- Evidence handlers (T148-T150) ---

// handleListEvidence handles GET /api/v1/evidence with query parameters:
// control_id, source, from_time, to_time, min_confidence, cursor, limit.
// Returns cursor-based paginated results.
func (s *Server) handleListEvidence(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	// Parse limit.
	limit := defaultLimit
	if limitStr := q.Get("limit"); limitStr != "" {
		parsed, err := strconv.Atoi(limitStr)
		if err != nil {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid limit parameter")
			return
		}
		limit = parsed
	}
	if limit <= 0 {
		limit = defaultLimit
	}
	if limit > maxLimit {
		limit = maxLimit
	}

	// Build the storage query.
	query := storage.EvidenceQuery{
		ControlID: q.Get("control_id"),
		Source:    q.Get("source"),
		Cursor:   q.Get("cursor"),
		Limit:    limit + 1, // fetch one extra to detect has_more
	}

	// Parse time filters.
	if fromStr := q.Get("from_time"); fromStr != "" {
		t, err := time.Parse(time.RFC3339, fromStr)
		if err != nil {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid from_time format (use RFC3339)")
			return
		}
		query.FromTime = &t
	}
	if toStr := q.Get("to_time"); toStr != "" {
		t, err := time.Parse(time.RFC3339, toStr)
		if err != nil {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid to_time format (use RFC3339)")
			return
		}
		query.ToTime = &t
	}

	results, err := s.Store.QueryEvidence(r.Context(), query)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to query evidence")
		return
	}

	// Determine pagination.
	hasMore := len(results) > limit
	if hasMore {
		results = results[:limit]
	}

	var nextCursor string
	if hasMore && len(results) > 0 {
		nextCursor = results[len(results)-1].ID.String()
	}

	// Ensure data is always an array, never null.
	if results == nil {
		results = []evidence.Evidence{}
	}

	writeJSON(w, http.StatusOK, listEnvelope{
		Data: results,
		Meta: listMeta{
			Cursor:  nextCursor,
			Limit:   limit,
			HasMore: hasMore,
		},
	})
}

// handleGetEvidence handles GET /api/v1/evidence/{id}.
// Returns the full evidence record with attestation reference.
func (s *Server) handleGetEvidence(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid evidence ID format")
		return
	}

	ev, err := s.Store.GetEvidence(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "evidence not found")
		return
	}

	writeJSON(w, http.StatusOK, singleEnvelope{Data: ev})
}

// handleGetProvenance handles GET /api/v1/evidence/{id}/provenance.
// Returns the provenance chain: evidence metadata + attestation envelope.
func (s *Server) handleGetProvenance(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid evidence ID format")
		return
	}

	ev, err := s.Store.GetEvidence(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "evidence not found")
		return
	}

	chain := provenanceChain{
		EvidenceID:  ev.ID.String(),
		ControlID:   ev.ControlID,
		CollectedAt: ev.Time.Format(time.RFC3339Nano),
		Attestation: ev.Attestation,
	}

	// Attempt to fetch the DSSE envelope if a reference exists.
	if ev.Attestation.DSSEEnvelopeRef != "" {
		envelope, err := s.Store.GetAttestation(r.Context(), ev.Attestation.DSSEEnvelopeRef)
		if err == nil {
			var parsed interface{}
			if json.Unmarshal(envelope, &parsed) == nil {
				chain.Envelope = parsed
			} else {
				chain.Envelope = string(envelope)
			}
		}
	}

	writeJSON(w, http.StatusOK, singleEnvelope{Data: chain})
}

// --- Control handlers (T151-T154) ---

// handleListControls handles GET /api/v1/controls.
// Returns all loaded control definitions.
func (s *Server) handleListControls(w http.ResponseWriter, r *http.Request) {
	controls := s.controls
	if controls == nil {
		controls = []*control.Control{}
	}
	writeJSON(w, http.StatusOK, listEnvelope{
		Data: controls,
		Meta: listMeta{Limit: len(controls)},
	})
}

// handleGetControl handles GET /api/v1/controls/{id}.
// Returns a single control definition.
func (s *Server) handleGetControl(w http.ResponseWriter, r *http.Request) {
	controlID := r.PathValue("id")

	for _, ctrl := range s.controls {
		if ctrl.ID == controlID {
			writeJSON(w, http.StatusOK, singleEnvelope{Data: ctrl})
			return
		}
	}

	writeError(w, http.StatusNotFound, "NOT_FOUND", "control not found")
}

// handleGetControlStatus handles GET /api/v1/controls/{id}/status.
// Returns the latest ControlStatus with confidence.
func (s *Server) handleGetControlStatus(w http.ResponseWriter, r *http.Request) {
	controlID := r.PathValue("id")

	status, err := s.Store.GetControlStatus(r.Context(), controlID)
	if err != nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "control status not found")
		return
	}

	writeJSON(w, http.StatusOK, singleEnvelope{Data: status})
}

// handleGetControlHistory handles GET /api/v1/controls/{id}/history.
// Required query params: from, to (RFC3339).
// Returns time-series data with uptime percentage and bucketed data.
func (s *Server) handleGetControlHistory(w http.ResponseWriter, r *http.Request) {
	controlID := r.PathValue("id")
	q := r.URL.Query()

	fromStr := q.Get("from")
	toStr := q.Get("to")
	if fromStr == "" || toStr == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "from and to query parameters are required (RFC3339 format)")
		return
	}

	from, err := time.Parse(time.RFC3339, fromStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid from parameter (use RFC3339)")
		return
	}

	to, err := time.Parse(time.RFC3339, toStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid to parameter (use RFC3339)")
		return
	}

	statuses, err := s.Store.QueryHistory(r.Context(), controlID, from, to)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to query control history")
		return
	}
	if statuses == nil {
		statuses = []control.ControlStatus{}
	}

	// Calculate uptime using 24h buckets.
	uptime := control.CalculateUptime(statuses, from, to, 24*time.Hour)

	writeJSON(w, http.StatusOK, singleEnvelope{
		Data: historyResponse{
			Statuses: statuses,
			Uptime:   uptime,
		},
	})
}

// --- Attestation handler (T155) ---

// handleGetAttestation handles GET /api/v1/attestations/{id}.
// Returns the full DSSE envelope as JSON.
func (s *Server) handleGetAttestation(w http.ResponseWriter, r *http.Request) {
	ref := r.PathValue("id")

	envelope, err := s.Store.GetAttestation(r.Context(), ref)
	if err != nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "attestation not found")
		return
	}

	// Attempt to parse the envelope as JSON for clean output.
	var parsed interface{}
	if json.Unmarshal(envelope, &parsed) == nil {
		writeJSON(w, http.StatusOK, singleEnvelope{Data: parsed})
	} else {
		writeJSON(w, http.StatusOK, singleEnvelope{Data: string(envelope)})
	}
}

// --- Module handler (T156) ---

// handleListModules handles GET /api/v1/modules.
// Returns all registered modules with type and safety classification.
func (s *Server) handleListModules(w http.ResponseWriter, r *http.Request) {
	modules := s.Registry.ListModules()
	if modules == nil {
		modules = []module.ModuleInfo{}
	}
	writeJSON(w, http.StatusOK, listEnvelope{
		Data: modules,
		Meta: listMeta{Limit: len(modules)},
	})
}

// --- Health handler (T157) ---

// handleHealth handles GET /api/v1/health.
// Returns server status, version, and current time.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	resp := healthResponse{
		Status:  "ok",
		Version: s.Version,
		Time:    time.Now().UTC().Format(time.RFC3339),
	}

	writeJSON(w, http.StatusOK, resp)
}
