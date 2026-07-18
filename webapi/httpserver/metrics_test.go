package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func TestClassifyRoute(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"/api/v1/jobs", "/api/v1/jobs"},
		{"/api/v1/jobs/3.0", "/api/v1/jobs/{id}"},
		{"/api/v1/jobs/3.0/stdout", "/api/v1/jobs/{id}/{action}"},
		{"/api/v1/jobs/3.0/log", "/api/v1/jobs/{id}/{action}"},
		{"/api/v1/jobs/3.0/output/share", "/api/v1/jobs/{id}/output/share"},
		{"/api/v1/jobs/3.0/files/output.txt", "/api/v1/jobs/{id}/files/{name}"},
		{"/api/v1/jobs/3.0/files/sub/dir/output.txt", "/api/v1/jobs/{id}/files/{name}"},
		{"/api/v1/jobs/3.0/input/multipart", "/api/v1/jobs/{id}/input/multipart"},
		{"/api/v1/jobs/archive", "/api/v1/jobs/archive"},
		{"/api/v1/jobs/hold", "/api/v1/jobs/hold"},
		{"/api/v1/jupyter/instances", "/api/v1/jupyter/instances"},
		{"/api/v1/jupyter/instances/abc123", "/api/v1/jupyter/instances/{id}"},
		{"/api/v1/jupyter/instances/abc123/proxy/", "/api/v1/jupyter/instances/{id}/proxy/*"},
		{"/api/v1/jupyter/instances/abc123/proxy/lab/tree", "/api/v1/jupyter/instances/{id}/proxy/*"},
		{"/api/v1/jupyter/instances/abc123/events", "/api/v1/jupyter/instances/{id}/{action}"},
		{"/api/v1/templates", "/api/v1/templates"},
		{"/api/v1/templates/hello-world", "/api/v1/templates/{id}"},
		{"/api/v1/dashboard", "/api/v1/dashboard"},
		{"/api/v1/auth/me", "/api/v1/auth/me"},
		{"/api/v1/admin/oauth2/clients", "/api/v1/admin/*"},
		{"/api/v1/admin/oauth2/tokens", "/api/v1/admin/*"},
		{"/healthz", "/healthz"},
		{"/readyz", "/readyz"},
		{"/metrics", "/metrics"},
		{"/some/random/path", "/<other>"},
		{"/api/v1/some-future-route", "/api/v1/<other>"},
	}
	for _, tc := range cases {
		if got := classifyRoute(tc.path); got != tc.want {
			t.Errorf("classifyRoute(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

// TestRecordingMiddleware verifies that requests funneled through the
// middleware bump the counter, observe the duration histogram, and
// surface the right (method, route, status_class) labels. Skipping
// /metrics so a Prometheus scrape doesn't self-instrument.
func TestRecordingMiddleware(t *testing.T) {
	m := newHTTPMetrics()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/dashboard", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/api/v1/jobs/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	srv := httptest.NewServer(m.middleware(mux))
	defer srv.Close()

	for _, path := range []string{
		"/api/v1/dashboard",
		"/api/v1/jobs/3.0",
	} {
		// Use NewRequestWithContext + DefaultClient.Do rather than
		// http.Get — the noctx linter flags context-less HTTP calls
		// because a misbehaving handler could hang the test forever.
		// The test's own deadline / `go test -timeout` is the real
		// bound, but explicitly threading a context makes that intent
		// visible and satisfies the linter.
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+path, nil)
		if err != nil {
			t.Fatalf("NewRequest %s: %v", path, err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_ = resp.Body.Close()
	}

	// Pull the prometheus text output and look for the counters we
	// just incremented. We assert on substrings so the test is robust
	// to label ordering / float formatting.
	rr := httptest.NewRecorder()
	// noctx-safe constructor; the recorded handler is in-process so a
	// background context is the right one to thread through.
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics", nil)
	mux2 := http.NewServeMux()
	mux2.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		// Use the metrics' own registry directly.
		h := promHandlerFor(t, m)
		h.ServeHTTP(w, r)
	})
	mux2.ServeHTTP(rr, r)

	body := rr.Body.String()
	for _, want := range []string{
		`htcondor_api_http_requests_total{`,
		`route="/api/v1/dashboard"`,
		`route="/api/v1/jobs/{id}"`,
		`status_class="2xx"`,
		`status_class="4xx"`,
		`htcondor_api_http_request_duration_seconds_bucket`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics output missing %q\n--- body ---\n%s", want, body)
		}
	}
}

// promHandlerFor returns the same promhttp.Handler the production
// /metrics endpoint uses, scoped to this test's registry.
func promHandlerFor(t *testing.T, m *httpMetrics) http.Handler {
	t.Helper()
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}
