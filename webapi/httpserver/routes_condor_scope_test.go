package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// Routes that reach HTCondor must be behind requireCondorScope, and the
// property is about the ROUTE TABLE rather than about the middleware, which
// has its own tests: the bug each of these fixes was a handler that reaches
// the schedd and a registration that forgot to wrap it.
//
// The probe is an API key scoped to metrics only -- the shape every key in
// existence has today. createAuthenticatedContext's API-key branch
// authenticates it happily and attaches no schedd credential, so a handler
// that runs anyway reaches GetSecurityConfigOrDefault with nothing, and the
// connection is built out of this daemon's own configuration. 403 here means
// the request stopped before any of that.
func TestRoutesReachingHTCondorAreScopeGated(t *testing.T) {
	gated := []struct {
		method string
		path   string
		why    string
	}{
		{http.MethodPost, "/api/v1/jupyter/start", "starts a Jupyter job"},
		{http.MethodGet, "/api/v1/jupyter/list", "queries the queue"},
		{http.MethodPost, "/api/v1/apps", "submits a job"},
		{http.MethodGet, "/api/v1/apps/", "queries the queue"},
		{http.MethodPost, "/api/v1/chat", "its tools query and act on the queue"},
		{http.MethodPost, "/api/v1/collector/advertise", "writes to the collector"},
		{http.MethodGet, "/api/v1/jobs", "control: a route that has always been gated"},
	}

	h := scopeGateRoutesServer(t)
	token := gateTestKey(t, h, []string{"metrics"})

	for _, tc := range gated {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, scopeGateRequest(t, tc.method, tc.path, token))
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403: this route %s, and a metrics-only API key "+
					"carries no schedd credential, so whatever it reached ran as this daemon",
					rec.Code, tc.why)
			}
		})
	}
}

// The control in the other direction: a metrics-only key is not simply
// refused everywhere. /api/v1/chat/info answers a feature probe and touches
// no HTCondor daemon, so gating it would be a functional regression with no
// security to show for it.
func TestFeatureProbeRoutesAreNotScopeGated(t *testing.T) {
	h := scopeGateRoutesServer(t)
	token := gateTestKey(t, h, []string{"metrics"})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, scopeGateRequest(t, http.MethodGet, "/api/v1/chat/info", token))
	if rec.Code == http.StatusForbidden {
		t.Fatal("/api/v1/chat/info is scope-gated; it reaches no HTCondor daemon")
	}
}

// POST /api/v1/collector/advertise used to discard the authentication error
// and advertise on the bare request context, i.e. as this daemon, with a
// command the caller chose.
func TestAdvertiseRefusesAnUnauthenticatedRequest(t *testing.T) {
	h := scopeGateRoutesServer(t)

	rec := httptest.NewRecorder()
	body := strings.NewReader(`{"ad":{"MyType":"Machine","Name":"slot1@evil.example.org"},` +
		`"command":"UPDATE_STARTD_AD"}`)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/api/v1/collector/advertise", body)
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401: an unauthenticated caller advertised to the collector "+
			"as this daemon", rec.Code)
	}
}

func scopeGateRoutesServer(t *testing.T) *Handler {
	t.Helper()
	s, err := NewServer(Config{
		Logger: testLogger(t),
		// A collector, because handleCollectorAdvertise answers 501
		// without one and this is about what an unauthenticated caller
		// may do to a configured collector.
		Collector:    htcondor.NewCollector("localhost:9618"),
		ScheddName:   "test-schedd",
		ScheddAddr:   "127.0.0.1:9618",
		OAuth2DBPath: t.TempDir() + "/oauth2.db",
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	// Start() would bind a listener and spawn background work; the routes
	// are all this needs.
	s.setupRoutes()
	if s.apiKeyStore == nil {
		t.Fatal("precondition: no API key store, so the gate cannot authenticate the probe")
	}
	return s.Handler
}

func scopeGateRequest(t *testing.T, method, path, token string) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader("{}"))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}
