package toolstats_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/httpserver/appdb"
	"github.com/bbockelm/golang-htcondor/webapi/toolstats"
)

// openDB builds the real application database, migrations and all.
//
// Deliberately not a hand-written CREATE TABLE: the point of these
// tests is that the code and the shipped migration agree, and a test
// that declared its own schema would pass on the day they stopped.
func openDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := appdb.Open(filepath.Join(t.TempDir(), "app.db"))
	if err != nil {
		t.Fatalf("appdb.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := appdb.Migrate(ctx, db); err != nil {
		t.Fatalf("appdb.Migrate: %v", err)
	}
	return db
}

// TestCountersSurviveARestart is the requirement: with no Prometheus
// scraping, the numbers must not vanish when the process does.
func TestCountersSurviveARestart(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()

	before := toolstats.New()
	before.Record("query_jobs", "bbockelm", "claude-code/2.1", toolstats.OutcomeOK, 250*time.Millisecond)
	before.Record("query_jobs", "bbockelm", "claude-code/2.1", toolstats.OutcomeOK, 2*time.Second)
	before.Record("submit_job", "alice", "cursor/0.4", toolstats.OutcomeError, 90*time.Millisecond)
	if err := before.Flush(ctx, db); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	// A new process, the same database.
	after := toolstats.New()
	if err := after.LoadFrom(ctx, db); err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}

	want := before.Snapshot()
	got := after.Snapshot()
	if len(got) != len(want) {
		t.Fatalf("restored %d series, want %d", len(got), len(want))
	}
	for k, w := range want {
		g, ok := got[k]
		if !ok {
			t.Errorf("series %+v did not survive", k)
			continue
		}
		if g.Calls != w.Calls {
			t.Errorf("%+v calls = %d, want %d", k, g.Calls, w.Calls)
		}
		if d := g.DurationSum - w.DurationSum; d > 0.001 || d < -0.001 {
			t.Errorf("%+v duration sum = %v, want %v", k, g.DurationSum, w.DurationSum)
		}
		// The distribution, not just the total: restoring the count
		// and losing the histogram would make every quantile wrong
		// for as long as the deployment lives.
		for i := range w.Buckets {
			if g.Buckets[i] != w.Buckets[i] {
				t.Errorf("%+v bucket %d = %d, want %d", k, i, g.Buckets[i], w.Buckets[i])
			}
		}
		if !g.LastCall.Equal(w.LastCall.Truncate(time.Second)) {
			t.Errorf("%+v last call = %v, want %v", k, g.LastCall, w.LastCall.Truncate(time.Second))
		}
	}
}

// Counting continues from the restored totals rather than restarting
// beside them.
func TestCountingResumesFromTheRestoredTotals(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()

	first := toolstats.New()
	for i := 0; i < 5; i++ {
		first.Record("get_job", "u", "c", toolstats.OutcomeOK, time.Second)
	}
	if err := first.Flush(ctx, db); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	second := toolstats.New()
	if err := second.LoadFrom(ctx, db); err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	second.Record("get_job", "u", "c", toolstats.OutcomeOK, time.Second)
	if err := second.Flush(ctx, db); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	third := toolstats.New()
	if err := third.LoadFrom(ctx, db); err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	if got := third.Snapshot()[toolstats.Key{Tool: "get_job", User: "u", Client: "c", Outcome: toolstats.OutcomeOK}].Calls; got != 6 {
		t.Errorf("calls after restart = %d, want 6", got)
	}
}

// A flush is an upsert of the whole total, not an increment. Flushing
// twice without recording anything new must not double the stored
// numbers -- which an INSERT ... DO UPDATE SET calls = calls + ? would.
func TestFlushingTwiceDoesNotDoubleTheTotals(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()

	s := toolstats.New()
	s.Record("t", "u", "c", toolstats.OutcomeOK, time.Second)
	if err := s.Flush(ctx, db); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	s.MarkDirty(s.Snapshot()) // force a second write of the same state
	if err := s.Flush(ctx, db); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	var calls int
	if err := db.QueryRowContext(ctx, `SELECT calls FROM mcp_tool_stats WHERE tool = 't'`).Scan(&calls); err != nil {
		t.Fatalf("query: %v", err)
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1", calls)
	}
}

// An idle server must not rewrite the same rows every interval.
func TestFlushWritesNothingWhenNothingWasRecorded(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()

	s := toolstats.New()
	s.Record("t", "u", "c", toolstats.OutcomeOK, time.Second)
	if err := s.Flush(ctx, db); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	// Corrupt the stored row behind the store's back. A second flush
	// that writes anything would restore it; one that correctly does
	// nothing leaves the sentinel in place.
	if _, err := db.ExecContext(ctx, `UPDATE mcp_tool_stats SET calls = 999 WHERE tool = 't'`); err != nil {
		t.Fatalf("update: %v", err)
	}
	if err := s.Flush(ctx, db); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	var calls int
	if err := db.QueryRowContext(ctx, `SELECT calls FROM mcp_tool_stats WHERE tool = 't'`).Scan(&calls); err != nil {
		t.Fatalf("query: %v", err)
	}
	if calls != 999 {
		t.Errorf("an idle flush rewrote the table (calls = %d); it should have done nothing", calls)
	}
}

// Loading what was just loaded must not mark the store dirty, or every
// restart of an idle server would write its whole table back.
func TestLoadDoesNotArmAFlush(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()

	seed := toolstats.New()
	seed.Record("t", "u", "c", toolstats.OutcomeOK, time.Second)
	if err := seed.Flush(ctx, db); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	fresh := toolstats.New()
	if err := fresh.LoadFrom(ctx, db); err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	// Corrupt the row AFTER the load, so the sentinel differs from what
	// the store holds. Corrupting it first would make "flushed the
	// loaded state back" and "did not flush" write the same value, and
	// the test could not tell them apart.
	if _, err := db.ExecContext(ctx, `UPDATE mcp_tool_stats SET calls = 999 WHERE tool = 't'`); err != nil {
		t.Fatalf("update: %v", err)
	}
	if err := fresh.Flush(ctx, db); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	var calls int
	if err := db.QueryRowContext(ctx, `SELECT calls FROM mcp_tool_stats WHERE tool = 't'`).Scan(&calls); err != nil {
		t.Fatalf("query: %v", err)
	}
	if calls != 999 {
		t.Errorf("a load armed a flush and rewrote the table (calls = %d)", calls)
	}
}

// A failed flush must re-arm, or everything counted since the last
// success is silently dropped.
func TestAFailedFlushIsRetriedOnTheNextTick(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()

	s := toolstats.New()
	s.Record("t", "u", "c", toolstats.OutcomeOK, time.Second)

	// Renamed rather than dropped, so the table comes back exactly as
	// the migration built it without having to unwind goose's record of
	// having run it.
	if _, err := db.ExecContext(ctx, `ALTER TABLE mcp_tool_stats RENAME TO mcp_tool_stats_hidden`); err != nil {
		t.Fatalf("rename away: %v", err)
	}
	if err := s.Flush(ctx, db); err == nil {
		t.Fatalf("Flush succeeded with no table to write to")
	}
	if _, err := db.ExecContext(ctx, `ALTER TABLE mcp_tool_stats_hidden RENAME TO mcp_tool_stats`); err != nil {
		t.Fatalf("rename back: %v", err)
	}
	if err := s.Flush(ctx, db); err != nil {
		t.Fatalf("retry Flush: %v", err)
	}
	var calls int
	if err := db.QueryRowContext(ctx, `SELECT calls FROM mcp_tool_stats WHERE tool = 't'`).Scan(&calls); err != nil {
		t.Fatalf("the retry wrote nothing: %v", err)
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1", calls)
	}
}

// A database that predates this feature must not stop the server.
func TestLoadFromATableThatDoesNotExistIsNotAnError(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `DROP TABLE mcp_tool_stats`); err != nil {
		t.Fatalf("drop: %v", err)
	}
	s := toolstats.New()
	if err := s.LoadFrom(ctx, db); err != nil {
		t.Errorf("LoadFrom on a missing table = %v, want nil", err)
	}
}

// Both calls must tolerate a server built without a database at all --
// the stdio MCP server has none.
func TestNilDatabaseIsAcceptedSilently(t *testing.T) {
	s := toolstats.New()
	s.Record("t", "u", "c", toolstats.OutcomeOK, time.Second)
	if err := s.LoadFrom(context.Background(), nil); err != nil {
		t.Errorf("LoadFrom(nil) = %v", err)
	}
	if err := s.Flush(context.Background(), nil); err != nil {
		t.Errorf("Flush(nil) = %v", err)
	}
}

// The stored user and client are the real ones, not the bounded label
// values: this table is the durable record and the one an operator
// queries by name.
func TestStoredRowsKeepTheVerbatimIdentity(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()

	s := toolstats.New()
	s.SetMaxLabelValues(1) // force the Prometheus label space to collapse
	s.Record("query_jobs", "alice", "cc", toolstats.OutcomeOK, time.Second)
	s.Record("query_jobs", "bob", "cc", toolstats.OutcomeOK, time.Second)
	s.Record("query_jobs", "carol", "cc", toolstats.OutcomeOK, time.Second)
	if err := s.Flush(ctx, db); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	rows, err := db.QueryContext(ctx, `SELECT actor FROM mcp_tool_stats ORDER BY actor`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var actors []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			t.Fatalf("scan: %v", err)
		}
		actors = append(actors, a)
	}
	want := []string{"alice", "bob", "carol"}
	if len(actors) != len(want) {
		t.Fatalf("stored actors = %v, want %v", actors, want)
	}
	for i := range want {
		if actors[i] != want[i] {
			t.Errorf("stored actor %d = %q, want %q (SQLite must keep the real name)",
				i, actors[i], want[i])
		}
	}
}

// TestAFlushWritesOnlyWhatChanged pins the narrowing.
//
// The flush used to rewrite the whole snapshot every time, costing
// O(all history) however little moved -- ~4s at 100k series, on the one
// connection every authenticated request also needs. Idleness alone
// does not test this: a flush that rewrites everything still writes
// nothing when nothing changed. So both stored rows are corrupted
// behind the store's back, one series is recorded, and the untouched
// row must still hold its sentinel.
func TestAFlushWritesOnlyWhatChanged(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()

	s := toolstats.New()
	s.Record("query_jobs", "alice", "cc", toolstats.OutcomeOK, time.Second)
	s.Record("submit_job", "alice", "cc", toolstats.OutcomeOK, time.Second)
	if err := s.Flush(ctx, db); err != nil {
		t.Fatalf("seed flush: %v", err)
	}

	if _, err := db.ExecContext(ctx, `UPDATE mcp_tool_stats SET calls = 999`); err != nil {
		t.Fatalf("corrupt: %v", err)
	}

	// Only one of the two series moves.
	s.Record("query_jobs", "alice", "cc", toolstats.OutcomeOK, time.Second)
	if err := s.Flush(ctx, db); err != nil {
		t.Fatalf("flush: %v", err)
	}

	var changed, untouched int
	if err := db.QueryRowContext(ctx,
		`SELECT calls FROM mcp_tool_stats WHERE tool = 'query_jobs'`).Scan(&changed); err != nil {
		t.Fatalf("query: %v", err)
	}
	if err := db.QueryRowContext(ctx,
		`SELECT calls FROM mcp_tool_stats WHERE tool = 'submit_job'`).Scan(&untouched); err != nil {
		t.Fatalf("query: %v", err)
	}
	if changed != 2 {
		t.Errorf("the changed series = %d, want 2", changed)
	}
	if untouched != 999 {
		t.Errorf("the unchanged series was rewritten (calls = %d); the flush is still O(all rows)",
			untouched)
	}
}
