package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/usagestats"
)

// restStatsHandler is statsHandler with REST counting switched on,
// which the plain one leaves off so that every other test in the
// package is unaffected by it.
func restStatsHandler(t *testing.T) *Handler {
	t.Helper()
	// Through the real constructor with the knob on, not by poking the
	// field: the thing most likely to be wrong is the wiring -- a
	// store built but never registered, never flushed, or never
	// reached by the middleware -- and a test that assembles it by
	// hand cannot see any of that.
	h := statsHandlerWith(t, filepath.Join(t.TempDir(), "app.db"), true)
	if h.restStats == nil {
		t.Fatal("RESTStatsEnabled did not produce a REST store")
	}
	h.webuiAdminGroups = newGroupSet("condor-admins")
	h.setupRoutes()
	t.Cleanup(func() { h.StopUsageStats() })
	return h
}

func TestRESTOutcomeSeparatesPolicyFromMalfunction(t *testing.T) {
	cases := []struct {
		status int
		want   string
	}{
		{http.StatusOK, usagestats.OutcomeOK},
		{http.StatusNoContent, usagestats.OutcomeOK},
		// A redirect is the sign-in flow working, not a failure.
		{http.StatusFound, usagestats.OutcomeOK},
		{http.StatusUnauthorized, usagestats.OutcomeDenied},
		{http.StatusForbidden, usagestats.OutcomeDenied},
		{http.StatusNotFound, usagestats.OutcomeNotFound},
		{http.StatusTooManyRequests, usagestats.OutcomeRateLimited},
		{http.StatusBadRequest, usagestats.OutcomeClientError},
		{http.StatusRequestEntityTooLarge, usagestats.OutcomeClientError},
		{http.StatusInternalServerError, usagestats.OutcomeError},
		{http.StatusBadGateway, usagestats.OutcomeError},
	}
	for _, c := range cases {
		if got := restOutcome(c.status); got != c.want {
			t.Errorf("restOutcome(%d) = %q, want %q", c.status, got, c.want)
		}
	}
}

// Every outcome restOutcome can produce has to be one the REST spec
// admits, or the store folds it into "error" and the page shows a
// column that never fills.
func TestRESTOutcomesAreAllInTheSpec(t *testing.T) {
	spec := usagestats.RESTSpec()
	admitted := map[string]bool{}
	for _, o := range spec.Outcomes {
		admitted[o] = true
	}
	for _, status := range []int{200, 302, 401, 403, 404, 429, 400, 500} {
		if o := restOutcome(status); !admitted[o] {
			t.Errorf("restOutcome(%d) = %q, which RESTSpec does not list", status, o)
		}
	}
}

func TestRESTUsageNameCountsTheAPIAndNothingElse(t *testing.T) {
	cases := []struct {
		method, path, want string
	}{
		// The method is part of the name: these are different
		// operations with different risk.
		{"GET", "/api/v1/jobs/42.0", "GET /api/v1/jobs/{id}"},
		{"DELETE", "/api/v1/jobs/42.0", "DELETE /api/v1/jobs/{id}"},
		{"GET", "/api/v1/jobs", "GET /api/v1/jobs"},
		// Not the REST API: health probes, the SPA's own assets, the
		// sign-in redirects, and MCP (counted in its own store, so
		// counting it here too would double it on one page).
		{"GET", "/healthz", ""},
		{"GET", "/metrics", ""},
		{"GET", "/", ""},
		{"GET", "/_next/static/chunk.js", ""},
		{"GET", "/login", ""},
	}
	for _, c := range cases {
		if got := restUsageName(c.method, c.path); got != c.want {
			t.Errorf("restUsageName(%q, %q) = %q, want %q", c.method, c.path, got, c.want)
		}
	}
	// The MCP endpoints by their route constants rather than by a
	// literal, so this follows the paths if they ever move -- and so
	// it is plainly not a file that posts to MCP.
	for _, path := range []string{mcpPath, mcpMessagePath} {
		if got := restUsageName(http.MethodPost, path); got != "" {
			t.Errorf("restUsageName(POST, %q) = %q; MCP has its own store, and "+
				"counting it here too would double it on one page", path, got)
		}
	}
}

// The job id must not reach the name: it is caller-chosen, and one
// series per job is exactly the unbounded growth the store is built
// to avoid.
func TestRESTUsageNameTemplatesTheJobID(t *testing.T) {
	first := restUsageName("GET", "/api/v1/jobs/1.0")
	second := restUsageName("GET", "/api/v1/jobs/99999.17")
	if first != second {
		t.Errorf("two job ids gave two names: %q and %q", first, second)
	}
}

func TestRESTClientFromUserAgentDropsTheVersion(t *testing.T) {
	cases := []struct{ ua, want string }{
		{"curl/8.4.0", "curl"},
		{"python-httpx/0.27.0", "python-httpx"},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", "Mozilla"},
		{"somethingplain", "somethingplain"},
		{"  curl/8.4.0  ", "curl"},
		{"", ""},
		{"/leadingslash", "/leadingslash"},
	}
	for _, c := range cases {
		if got := restClientFromUserAgent(c.ua); got != c.want {
			t.Errorf("restClientFromUserAgent(%q) = %q, want %q", c.ua, got, c.want)
		}
	}
	long := make([]byte, 400)
	for i := range long {
		long[i] = 'x'
	}
	if got := restClientFromUserAgent(string(long)); len(got) != maxClientLength {
		t.Errorf("a 400-byte product token was stored at %d bytes, want it clamped to %d",
			len(got), maxClientLength)
	}
}

// The whole path: a real request through ServeHTTP, counted with the
// identity its session carried and the outcome its status implies.
//
// Every other test here checks a piece. This one checks they are
// connected -- a recorder that was never installed would pass all of
// them and count nothing in production.
func TestARealRESTRequestIsCounted(t *testing.T) {
	h := restStatsHandler(t)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, usageRequest(t, h, "/api/v1/admin/usage", "root", []string{"condor-admins"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	snap := h.restStats.Snapshot()
	var found *usagestats.Key
	for k := range snap {
		if k.Name == "GET /api/v1/admin/*" {
			key := k
			found = &key
		}
	}
	if found == nil {
		t.Fatalf("the request was not counted; store holds %+v", snap)
	}
	if found.Outcome != usagestats.OutcomeOK {
		t.Errorf("outcome = %q, want %q", found.Outcome, usagestats.OutcomeOK)
	}
	if found.User != "root" {
		t.Errorf("user = %q, want root -- the session's identity never reached the recorder",
			found.User)
	}
	// Signed in with the session cookie means the single-page app.
	if found.Client != restClientWebUI {
		t.Errorf("client = %q, want %q", found.Client, restClientWebUI)
	}
}

// A refusal is the case this page most needs to show, and the gates
// that produce one run before any handler does.
func TestARefusedRESTRequestIsCountedAsDenied(t *testing.T) {
	h := restStatsHandler(t)

	rec := httptest.NewRecorder()
	// No credential at all: 401 from the admin gate.
	h.ServeHTTP(rec, httptest.NewRequestWithContext(
		context.Background(), http.MethodGet, "/api/v1/admin/usage", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}

	var denied uint64
	for k, e := range h.restStats.Snapshot() {
		if k.Outcome == usagestats.OutcomeDenied {
			denied += e.Calls
		}
	}
	if denied != 1 {
		t.Errorf("denied calls = %d, want 1; store holds %+v", denied, h.restStats.Snapshot())
	}
}

// A request that never authenticates still says something about
// itself, and "unknown" for both dimensions would lose it.
func TestAnUnauthenticatedRequestFallsBackToTheUserAgent(t *testing.T) {
	h := restStatsHandler(t)

	r := httptest.NewRequestWithContext(
		context.Background(), http.MethodGet, "/api/v1/admin/usage", nil)
	r.Header.Set("User-Agent", "curl/8.4.0")
	h.ServeHTTP(httptest.NewRecorder(), r)

	var seen bool
	for k := range h.restStats.Snapshot() {
		if k.Client == "curl" {
			seen = true
		}
	}
	if !seen {
		t.Errorf("no series recorded for curl; store holds %+v", h.restStats.Snapshot())
	}
}

// Off means off: no store, no rows, and no cost on the request path.
func TestRESTCountingCanBeTurnedOff(t *testing.T) {
	h := statsHandler(t)
	t.Cleanup(func() { h.StopUsageStats() })
	h.webuiAdminGroups = newGroupSet("condor-admins")
	h.setupRoutes()
	if h.restStats != nil {
		t.Fatal("statsHandler built a REST store; this test needs one without")
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, usageRequest(t, h, "/api/v1/admin/usage?kind=rest", "root", []string{"condor-admins"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); !strings.Contains(got, `"enabled":false`) {
		t.Errorf("body = %s, want enabled:false for a kind this server does not count", got)
	}
}

// The client cache turns an id into a name for display only. The
// recorded value has to survive, because it is what a filter sends
// back.
func TestClientNameCacheLabelsWithoutRewriting(t *testing.T) {
	h := restStatsHandler(t)
	ctx := context.Background()

	if _, err := h.db.ExecContext(ctx,
		`INSERT INTO oauth2_clients (id, client_name) VALUES (?, ?)`,
		"client_17", "OpenClaw MCP"); err != nil {
		t.Skipf("could not seed a client row: %v", err)
	}

	h.restStats.Record("GET /api/v1/jobs", "alice",
		restClientOAuthPrefix+"client_17", usagestats.OutcomeOK, time.Millisecond)
	h.restStats.Record("GET /api/v1/jobs", "alice", "curl", usagestats.OutcomeOK, time.Millisecond)

	summary := usagestats.Summarize(usagestats.RESTSpec(), h.restStats.Snapshot(), usagestats.Filter{})
	h.resolveUsageClientNames(ctx, &summary)

	var labelled, plain bool
	for _, row := range summary.ByClient {
		switch row.Name {
		case restClientOAuthPrefix + "client_17":
			if row.Label != "OpenClaw MCP" {
				t.Errorf("label = %q, want the client's name", row.Label)
			}
			labelled = true
		case "curl":
			if row.Label != "" {
				t.Errorf("a plain client string got a label: %q", row.Label)
			}
			plain = true
		}
	}
	if !labelled {
		t.Errorf("the oauth client kept no row under its recorded id: %+v", summary.ByClient)
	}
	if !plain {
		t.Errorf("the curl row went missing: %+v", summary.ByClient)
	}
	if summary.ClientLabels[restClientOAuthPrefix+"client_17"] != "OpenClaw MCP" {
		t.Errorf("client_labels = %+v, want the id mapped to the name", summary.ClientLabels)
	}
}

// An id with no client behind it reads as what it is, rather than
// being prettified into something that looks like a name.
func TestClientNameCacheLeavesAnUnknownIDAlone(t *testing.T) {
	h := restStatsHandler(t)
	raw := restClientOAuthPrefix + "client_gone"
	if got := h.restStatsClients.resolve(context.Background(), h.db, raw); got != raw {
		t.Errorf("resolve(%q) = %q, want it unchanged", raw, got)
	}
}

// The REST collector has to reach the registry that serves /metrics.
// A store that counts but was never registered passes every other
// test here and publishes nothing.
func TestRESTMetricsReachTheRegistry(t *testing.T) {
	h := restStatsHandler(t)
	h.restStats.Record("GET /api/v1/jobs", "alice", "curl", usagestats.OutcomeOK, time.Second)

	families, err := h.httpMetricsState.registry.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	seen := map[string]bool{}
	var names []string
	for _, f := range families {
		seen[f.GetName()] = true
		names = append(names, f.GetName())
	}
	for _, want := range []string{
		"htcondor_api_rest_endpoint_calls_total",
		"htcondor_api_rest_endpoint_users",
		"htcondor_api_rest_endpoint_last_call_timestamp_seconds",
	} {
		if !seen[want] {
			t.Errorf("%s is not on the registry that serves /metrics; got %v", want, names)
		}
	}
	// Deliberately absent: htcondor_api_http_request_duration_seconds
	// already publishes this server's latency by method and route, and
	// a second histogram over the same requests would add a bucket
	// series per (endpoint, client, outcome) to say the same thing.
	if seen["htcondor_api_rest_endpoint_duration_seconds"] {
		t.Error("the REST duration histogram was published; RESTSpec sets ExportDurations=false " +
			"because htcondor_api_http_request_duration_seconds already covers it")
	}
}

// MCP keeps its histogram: nothing else publishes how long a tool
// takes.
func TestMCPKeepsItsDurationHistogram(t *testing.T) {
	h := statsHandler(t)
	t.Cleanup(func() { h.StopUsageStats() })
	h.toolStats.Record("query_jobs", "alice", "claude-code", usagestats.OutcomeOK, time.Second)

	families, err := h.httpMetricsState.registry.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, f := range families {
		if f.GetName() == "htcondor_api_mcp_tool_duration_seconds" {
			return
		}
	}
	t.Error("htcondor_api_mcp_tool_duration_seconds went missing")
}

// A handler that panics must be counted, and counted as a failure.
//
// There is no panic-recovery middleware here, so the panic unwinds
// past the recorder to net/http, which closes the connection without
// ever setting a status. The recorder's default is 200, so the
// obvious implementation reports a crashing endpoint as a healthy
// one.
func TestAPanickingHandlerIsCountedAsAnError(t *testing.T) {
	h := restStatsHandler(t)
	h.mux.HandleFunc("/api/v1/jobs/boom", func(http.ResponseWriter, *http.Request) {
		panic("boom")
	})

	r := usageRequest(t, h, "/api/v1/jobs/boom", "root", []string{"condor-admins"})
	func() {
		// The panic has to reach the caller: counting it must not
		// swallow it, or net/http would never close the connection
		// and every panic would silently become a hung request.
		defer func() {
			if recover() == nil {
				t.Error("the panic did not propagate; recording must not swallow it")
			}
		}()
		h.ServeHTTP(httptest.NewRecorder(), r)
	}()

	var errors uint64
	for k, e := range h.restStats.Snapshot() {
		if k.Outcome == usagestats.OutcomeError {
			errors += e.Calls
		}
	}
	if errors != 1 {
		t.Errorf("error calls = %d, want 1; store holds %+v", errors, h.restStats.Snapshot())
	}
}
