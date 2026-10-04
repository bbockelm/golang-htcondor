package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/logging"
)

func warmTestServer(t *testing.T) *Server {
	t.Helper()
	logger, err := logging.New(&logging.Config{OutputPath: "stdout"})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	s, err := NewServer(Config{
		Logger:       logger,
		ScheddName:   "test-schedd",
		ScheddAddr:   "127.0.0.1:9618",
		OAuth2DBPath: t.TempDir() + "/oauth2.db",
	})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	return s
}

// Warming changes state on the server -- it opens a connection into
// somebody's job -- so it is a POST. A GET would also mean a link or a
// prefetch could open one.
func TestJobWarmRefusesGET(t *testing.T) {
	s := warmTestServer(t)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/jobs/1.0/warm", nil)
	req.Header.Set("Authorization", "Bearer "+createTestJWTToken(3600))
	w := httptest.NewRecorder()

	s.handleJobWarm(w, req, "1.0")

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status %d, want 405: %s", w.Code, w.Body.String())
	}
}

// Checked before anything is dialled: a bad id should cost nothing.
func TestJobWarmRejectsABadJobID(t *testing.T) {
	s := warmTestServer(t)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/jobs/nope/warm", nil)
	req.Header.Set("Authorization", "Bearer "+createTestJWTToken(3600))
	w := httptest.NewRecorder()

	s.handleJobWarm(w, req, "nope")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400: %s", w.Code, w.Body.String())
	}
}

// An unauthenticated caller does not get to open a connection into a
// job, and finds out before any work is done.
func TestJobWarmRequiresAuthentication(t *testing.T) {
	s := warmTestServer(t)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/jobs/1.0/warm", nil)
	w := httptest.NewRecorder()

	s.handleJobWarm(w, req, "1.0")

	if w.Code != http.StatusUnauthorized && w.Code != http.StatusFound {
		t.Fatalf("status %d, want 401 (or a redirect to login): %s", w.Code, w.Body.String())
	}
}

// The response has to carry the numbers a client needs: whether there
// was anything to do, and how long it has before the transport is
// reaped. Shape-checked here because the client reads these names.
func TestWarmResponseShape(t *testing.T) {
	encoded, err := json.Marshal(warmResponse{Ready: true, Reused: true, ElapsedMS: 12, IdleTimeoutSeconds: 600})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{`"ready":true`, `"reused":true`, `"elapsed_ms":12`, `"idle_timeout_seconds":600`} {
		if !strings.Contains(string(encoded), want) {
			t.Errorf("response is missing %s: %s", want, encoded)
		}
	}
}

// The endpoint has to be reachable through the mux, not just callable.
// Every test above invokes the handler directly, so a dispatcher that
// never routes to it would leave them all green and the endpoint dead.
func TestWarmIsRoutedThroughTheMux(t *testing.T) {
	s := warmTestServer(t)
	s.setupRoutes()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/jobs/1.0/warm", nil)
	req.Header.Set("Authorization", "Bearer "+createTestJWTToken(3600))
	w := httptest.NewRecorder()

	s.ServeHTTP(w, req)

	// A GET, so the answer from the handler is 405. Anything the
	// dispatcher does not know about answers 404, which is what this
	// is really distinguishing.
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status %d, want 405 (404 means nothing routes to it): %s", w.Code, w.Body.String())
	}
}
