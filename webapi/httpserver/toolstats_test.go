package httpserver

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/httpserver/appdb"
	"github.com/bbockelm/golang-htcondor/webapi/toolstats"
)

// statsHandler builds a real Handler against a real application
// database. The point of these tests is the WIRING -- a store that
// counts perfectly but was never handed to the MCP server, or a
// collector that was never registered, would pass every unit test in
// the toolstats package and ship a feature that does nothing.
func statsHandler(t *testing.T) *Handler {
	t.Helper()
	return statsHandlerAt(t, filepath.Join(t.TempDir(), "app.db"))
}

func statsHandlerAt(t *testing.T, dbPath string) *Handler {
	t.Helper()
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	h, err := NewHandler(HandlerConfig{
		ScheddName:   "test-schedd",
		ScheddAddr:   "127.0.0.1:9618",
		Logger:       logger,
		OAuth2DBPath: dbPath,
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return h
}

// TestARealMCPCallIsCounted drives the whole path: an HTTP tools/call
// into the routed server, out to the dispatcher, back through the
// recorder and onto the metrics registry.
//
// Everything else here tests a piece. This tests that the pieces are
// connected -- a store that was never handed to the MCP server would
// pass every other test in this file and count nothing in production.
func TestARealMCPCallIsCounted(t *testing.T) {
	s := newMCPTransportServer(t, false)
	t.Cleanup(func() { s.StopToolStats() })

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call",` +
		`"params":{"name":"definitely_not_a_tool","arguments":{}}}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+forwardedHTCondorToken(t))
	req.Header.Set("User-Agent", "integration-probe/1.0")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)

	snap := s.toolStats.Snapshot()
	var found bool
	for k, e := range snap {
		if k.Tool == "definitely_not_a_tool" && e.Calls > 0 {
			found = true
			// The harness identified itself only by User-Agent, which
			// is the fallback this call exercises.
			if k.Client != "integration-probe-1.0" {
				t.Errorf("client = %q, want integration-probe-1.0", k.Client)
			}
			if k.Outcome != toolstats.OutcomeUnknownTool {
				t.Errorf("outcome = %q, want %q", k.Outcome, toolstats.OutcomeUnknownTool)
			}
		}
	}
	if !found {
		t.Fatalf("an MCP tool call over HTTP was not counted (status %d): %+v", w.Code, snap)
	}
}

// The collector has to be registered, or /metrics never mentions it.
func TestToolCallsAppearOnTheMetricsRegistry(t *testing.T) {
	h := statsHandler(t)
	t.Cleanup(func() { h.StopToolStats() })

	h.toolStats.Record("query_jobs", "bbockelm", "claude-code/2.1", toolstats.OutcomeOK, 150*time.Millisecond)

	families, err := h.httpMetricsState.registry.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	var names []string
	seen := map[string]bool{}
	for _, f := range families {
		names = append(names, f.GetName())
		seen[f.GetName()] = true
	}
	for _, want := range []string{
		"htcondor_api_mcp_tool_calls_total",
		"htcondor_api_mcp_tool_duration_seconds",
		"htcondor_api_mcp_tool_users",
		"htcondor_api_mcp_tool_last_call_timestamp_seconds",
	} {
		if !seen[want] {
			t.Errorf("%s is not on the registry that serves /metrics; got %v", want, names)
		}
	}
}

// The names sit in the same namespace as the server's existing metrics,
// so one scrape config and one dashboard covers both.
func TestToolMetricNamesMatchTheServersNamespace(t *testing.T) {
	h := statsHandler(t)
	t.Cleanup(func() { h.StopToolStats() })
	h.toolStats.Record("t", "u", "c", toolstats.OutcomeOK, time.Second)

	families, err := h.httpMetricsState.registry.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, f := range families {
		if strings.Contains(f.GetName(), "_mcp_tool_") && !strings.HasPrefix(f.GetName(), metricsNamespace+"_") {
			t.Errorf("%s is outside the %s namespace", f.GetName(), metricsNamespace)
		}
	}
}

// The shutdown flush is the half of the requirement a timer cannot
// cover: a server stopped between ticks must still leave its counters
// behind.
func TestShutdownPersistsTheCounters(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "app.db")
	h := statsHandlerAt(t, dbPath)
	h.toolStats.Record("submit_job", "bbockelm", "claude-code/2.1", toolstats.OutcomeOK, time.Second)
	h.toolStats.Record("submit_job", "bbockelm", "claude-code/2.1", toolstats.OutcomeError, 2*time.Second)

	// Through the real lifecycle, not StopToolStats directly: the thing
	// at risk is that Stop forgets to flush, and a test calling the
	// flush itself could not see that. Stop needs the context Start
	// installs, so the handler is actually started -- on a throwaway
	// listener that nothing connects to.
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.Start(ctx, ln, "http"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Stop's own error is not the subject: it reports whether every
	// background goroutine drained in time, which is a different
	// question from whether the counters were written. Stop also
	// closes the database, so the check below reopens the file.
	_ = h.Stop(ctx)

	db, err := appdb.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = db.Close() }()

	var calls int
	err = db.QueryRowContext(context.Background(),
		`SELECT calls FROM mcp_tool_stats WHERE tool = 'submit_job' AND outcome = 'ok'`).Scan(&calls)
	if err != nil {
		t.Fatalf("the shutdown flush wrote nothing: %v", err)
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1", calls)
	}

	// And the identity is stored verbatim, which is what makes the
	// table answer "who uses this" directly.
	var actor, client string
	if err := db.QueryRowContext(context.Background(),
		`SELECT actor, client FROM mcp_tool_stats WHERE tool = 'submit_job' LIMIT 1`).
		Scan(&actor, &client); err != nil {
		t.Fatalf("query: %v", err)
	}
	if actor != "bbockelm" || client != "claude-code/2.1" {
		t.Errorf("stored actor/client = %q/%q, want bbockelm/claude-code/2.1", actor, client)
	}
}

// Shutdown can run from more than one signal path.
func TestStopToolStatsIsIdempotent(t *testing.T) {
	h := statsHandler(t)
	h.toolStats.Record("t", "u", "c", toolstats.OutcomeOK, time.Second)
	h.StopToolStats()
	h.StopToolStats() // must not panic on a closed channel
}

// A restart resumes: this is the whole point of persisting, so it is
// asserted against the real Handler and not only the store.
func TestANewHandlerResumesTheCountersFromDisk(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "app.db")
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	cfg := HandlerConfig{
		ScheddName:   "test-schedd",
		ScheddAddr:   "127.0.0.1:9618",
		Logger:       logger,
		OAuth2DBPath: dbPath,
	}

	first, err := NewHandler(cfg)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	for i := 0; i < 3; i++ {
		first.toolStats.Record("get_job", "bbockelm", "cc", toolstats.OutcomeOK, time.Second)
	}
	first.StopToolStats()
	if err := first.db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	second, err := NewHandler(cfg)
	if err != nil {
		t.Fatalf("NewHandler (restart): %v", err)
	}
	t.Cleanup(func() { second.StopToolStats() })

	got := second.toolStats.Snapshot()[toolstats.Key{
		Tool: "get_job", User: "bbockelm", Client: "cc", Outcome: toolstats.OutcomeOK,
	}]
	if got.Calls != 3 {
		t.Errorf("after restart calls = %d, want 3; the counters did not resume", got.Calls)
	}

	// And they keep counting from there rather than beside it.
	second.toolStats.Record("get_job", "bbockelm", "cc", toolstats.OutcomeOK, time.Second)
	got = second.toolStats.Snapshot()[toolstats.Key{
		Tool: "get_job", User: "bbockelm", Client: "cc", Outcome: toolstats.OutcomeOK,
	}]
	if got.Calls != 4 {
		t.Errorf("calls = %d, want 4", got.Calls)
	}
}

// Statistics must never be the reason a server will not boot.
func TestAServerStartsEvenWhenTheStatsTableIsUnusable(t *testing.T) {
	h := statsHandler(t)
	t.Cleanup(func() { h.StopToolStats() })

	if _, err := h.db.ExecContext(context.Background(), `DROP TABLE mcp_tool_stats`); err != nil {
		t.Fatalf("drop: %v", err)
	}
	// Loading and flushing against the missing table must both be
	// survivable, not fatal.
	if err := h.toolStats.LoadFrom(context.Background(), h.db); err != nil {
		t.Errorf("LoadFrom on a missing table = %v, want nil", err)
	}
	h.toolStats.Record("t", "u", "c", toolstats.OutcomeOK, time.Second)
	h.flushToolStatsOnce("test") // logs, does not panic or fail the test
}

// TestAFlushRetriesAReadThatFailedAtStartup covers the recovery half.
//
// The store refuses to flush after a failed load, which protects the
// stored record but would leave a process counting for days and
// persisting none of it. The flush path therefore re-reads first, and
// merges, so the calls counted in the meantime are added rather than
// discarded.
func TestAFlushRetriesAReadThatFailedAtStartup(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "app.db")

	// A deployment with history.
	seed := statsHandlerAt(t, dbPath)
	for i := 0; i < 40; i++ {
		seed.toolStats.Record("query_jobs", "alice", "cc", toolstats.OutcomeOK, time.Millisecond)
	}
	seed.StopToolStats()
	if err := seed.db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Restart, and break the read with the table still present.
	h := statsHandlerAt(t, dbPath)
	t.Cleanup(func() { h.StopToolStats() })
	if _, err := h.db.ExecContext(context.Background(),
		`ALTER TABLE mcp_tool_stats RENAME COLUMN calls TO calls_hidden`); err != nil {
		t.Fatalf("hide column: %v", err)
	}
	h.toolStats = toolstats.New()
	if err := h.toolStats.LoadFrom(context.Background(), h.db); err == nil {
		t.Fatal("LoadFrom succeeded against an unreadable table")
	}

	// Calls happen while the record cannot be read; the flush must not
	// write them over the history.
	h.toolStats.Record("query_jobs", "alice", "cc", toolstats.OutcomeOK, time.Millisecond)
	h.flushToolStatsOnce("while unreadable")

	if _, err := h.db.ExecContext(context.Background(),
		`ALTER TABLE mcp_tool_stats RENAME COLUMN calls_hidden TO calls`); err != nil {
		t.Fatalf("show column: %v", err)
	}

	// Now it can be read: the flush re-reads, merges and persists.
	h.flushToolStatsOnce("after recovery")

	var calls int
	if err := h.db.QueryRowContext(context.Background(),
		`SELECT calls FROM mcp_tool_stats WHERE tool = 'query_jobs'`).Scan(&calls); err != nil {
		t.Fatalf("query: %v", err)
	}
	if calls != 41 {
		t.Errorf("stored calls = %d, want 41 (40 persisted + 1 counted while unreadable)", calls)
	}
}
