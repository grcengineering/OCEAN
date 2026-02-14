// Package api implements the OCEAN REST API server, providing HTTP endpoints
// for querying evidence, control status, attestations, and module metadata.
package api

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/grcengineering/ocean/internal/control"
	"github.com/grcengineering/ocean/internal/module"
	"github.com/grcengineering/ocean/internal/storage"
)

// Server is the OCEAN HTTP API server. It holds references to the storage
// backend, module registry, and server configuration.
type Server struct {
	Store     storage.Store
	Registry  *module.Registry
	AuthToken string
	Port      int
	Version   string

	controls []*control.Control
}

// NewServer creates a new Server with the given dependencies.
func NewServer(store storage.Store, registry *module.Registry, authToken string, port int) *Server {
	return &Server{
		Store:     store,
		Registry:  registry,
		AuthToken: authToken,
		Port:      port,
		Version:   "dev",
	}
}

// SetControls sets the loaded control definitions for the API to serve.
func (s *Server) SetControls(controls []*control.Control) {
	s.controls = controls
}

// Handler returns the fully wired http.Handler with all routes and middleware.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Evidence endpoints (T148-T150)
	mux.HandleFunc("GET /api/v1/evidence", s.handleListEvidence)
	mux.HandleFunc("GET /api/v1/evidence/{id}", s.handleGetEvidence)
	mux.HandleFunc("GET /api/v1/evidence/{id}/provenance", s.handleGetProvenance)

	// Control endpoints (T151-T154)
	mux.HandleFunc("GET /api/v1/controls", s.handleListControls)
	mux.HandleFunc("GET /api/v1/controls/{id}", s.handleGetControl)
	mux.HandleFunc("GET /api/v1/controls/{id}/status", s.handleGetControlStatus)
	mux.HandleFunc("GET /api/v1/controls/{id}/history", s.handleGetControlHistory)

	// Attestation endpoint (T155)
	mux.HandleFunc("GET /api/v1/attestations/{id}", s.handleGetAttestation)

	// Module endpoint (T156)
	mux.HandleFunc("GET /api/v1/modules", s.handleListModules)

	// Health endpoint (T157)
	mux.HandleFunc("GET /api/v1/health", s.handleHealth)

	// Apply middleware: logging wraps auth wraps routes.
	var handler http.Handler = mux
	handler = s.authMiddleware(handler)
	handler = s.loggingMiddleware(handler)

	return handler
}

// ListenAndServe starts the HTTP server on the configured port and blocks
// until the provided context is cancelled, at which point it gracefully
// shuts down with a 10-second deadline.
func (s *Server) ListenAndServe(ctx context.Context) error {
	addr := fmt.Sprintf(":%d", s.Port)

	httpServer := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		BaseContext: func(_ net.Listener) context.Context {
			return ctx
		},
	}

	// Start serving in a goroutine.
	errCh := make(chan error, 1)
	go func() {
		log.Info().Int("port", s.Port).Msg("OCEAN API server starting")
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	// Wait for context cancellation (graceful shutdown signal).
	select {
	case err := <-errCh:
		return fmt.Errorf("server error: %w", err)
	case <-ctx.Done():
		log.Info().Msg("shutting down OCEAN API server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown error: %w", err)
		}
		return nil
	}
}
