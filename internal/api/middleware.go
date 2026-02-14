package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// authMiddleware returns an http.Handler that validates Bearer token
// authentication on all requests except GET /api/v1/health. Requests
// without a valid token receive a 401 JSON error response.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Health endpoint is exempt from authentication (T145).
		if r.URL.Path == "/api/v1/health" {
			next.ServeHTTP(w, r)
			return
		}

		// Extract Bearer token from Authorization header.
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "missing Authorization header")
			return
		}

		if !strings.HasPrefix(authHeader, "Bearer ") {
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Authorization header must use Bearer scheme")
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token != s.AuthToken {
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid authentication token")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// responseCapture wraps http.ResponseWriter to capture the status code
// for logging purposes.
type responseCapture struct {
	http.ResponseWriter
	statusCode int
}

func (rc *responseCapture) WriteHeader(code int) {
	rc.statusCode = code
	rc.ResponseWriter.WriteHeader(code)
}

// loggingMiddleware returns an http.Handler that logs every request using
// zerolog, including method, path, status code, and duration. It also
// sets the Content-Type header to application/json for all API responses.
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// All API responses are JSON.
		w.Header().Set("Content-Type", "application/json")

		rc := &responseCapture{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rc, r)

		duration := time.Since(start)
		log.Info().
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Int("status", rc.statusCode).
			Dur("duration", duration).
			Msg("api request")
	})
}
