package testutil

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// MockAPIServer wraps httptest.Server with convenience methods for setting up
// expected request/response pairs. It uses t.Cleanup for proper lifecycle
// management.
//
// Usage:
//
//	srv := testutil.NewMockAPIServer(t)
//	srv.Handle("GET", "/api/v1/policies", http.StatusOK, `[{"id":"pol001"}]`)
//	config := map[string]string{"API_URL": srv.URL()}
type MockAPIServer struct {
	*httptest.Server
	mu      sync.Mutex
	routes  map[string]route
	calls   map[string]int
	t       *testing.T
}

type route struct {
	status int
	body   string
}

func routeKey(method, path string) string {
	return method + " " + path
}

// NewMockAPIServer creates a new mock HTTP server and registers cleanup.
func NewMockAPIServer(t *testing.T) *MockAPIServer {
	t.Helper()

	m := &MockAPIServer{
		routes: make(map[string]route),
		calls:  make(map[string]int),
		t:      t,
	}

	m.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		key := routeKey(r.Method, r.URL.Path)
		m.calls[key]++
		rt, ok := m.routes[key]
		m.mu.Unlock()

		if !ok {
			// Fallback: try path-only match with any method.
			m.mu.Lock()
			for k, v := range m.routes {
				if len(k) > len(r.URL.Path) && k[len(k)-len(r.URL.Path):] == r.URL.Path {
					rt = v
					ok = true
					break
				}
			}
			m.mu.Unlock()
		}

		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(rt.status)
		w.Write([]byte(rt.body))
	}))

	t.Cleanup(m.Server.Close)
	return m
}

// Handle registers a canned response for a method+path combination.
func (m *MockAPIServer) Handle(method, path string, status int, body string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.routes[routeKey(method, path)] = route{status: status, body: body}
}

// HandleFunc registers a custom handler for a method+path combination.
func (m *MockAPIServer) HandleFunc(method, path string, handler http.HandlerFunc) {
	// For HandleFunc, we wrap the existing server by adding routes that
	// store a special sentinel and dispatch to the handler.
	// Simpler approach: replace the route handler inline.
	m.mu.Lock()
	defer m.mu.Unlock()
	// Store a sentinel route that the main handler won't match.
	// Instead, override the server's handler to check funcs first.
	// For simplicity, we use the same route mechanism with a -1 status sentinel.
	m.routes[routeKey(method, path)] = route{status: -1, body: ""}

	// Re-wrap the server handler to support func routes.
	origHandler := m.Server.Config.Handler
	m.Server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := routeKey(r.Method, r.URL.Path)
		m.mu.Lock()
		rt, ok := m.routes[key]
		m.mu.Unlock()
		if ok && rt.status == -1 {
			m.mu.Lock()
			m.calls[key]++
			m.mu.Unlock()
			handler(w, r)
			return
		}
		origHandler.ServeHTTP(w, r)
	})
}

// Host returns the server's host:port without the scheme.
func (m *MockAPIServer) Host() string {
	// URL is like "http://127.0.0.1:PORT"
	u := m.Server.URL
	if len(u) > 7 {
		return u[7:] // strip "http://"
	}
	return u
}

// CallCount returns the number of times a method+path was called.
func (m *MockAPIServer) CallCount(method, path string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls[routeKey(method, path)]
}

// AssertCalled asserts that a method+path was called at least once.
func (m *MockAPIServer) AssertCalled(t *testing.T, method, path string) {
	t.Helper()
	if m.CallCount(method, path) == 0 {
		t.Errorf("expected %s %s to be called, but it was not", method, path)
	}
}
