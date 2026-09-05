package jobwatch

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/httpserver/appdb"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	db, err := appdb.Open(filepath.Join(t.TempDir(), "app.db"))
	if err != nil {
		t.Fatalf("appdb.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := appdb.Migrate(context.Background(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return NewStore(db)
}

func register(t *testing.T, s *Store, owner string, event Event, mode Mode) *Watch {
	t.Helper()
	w, err := New(owner, "test", "ClusterId == 42", event, "", mode)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got, err := s.Register(context.Background(), w, 0)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	return got
}

// TestWatchSurvivesARestart is why this is in SQL and not a map. The
// caller is an agent whose absence is the normal case; a watch that did
// not survive a daemon restart would fail silently, and only for the
// agents that waited longest.
func TestWatchSurvivesARestart(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	w := register(t, s, "alice", EventDone, ModeAll)

	// The tracked set is the part that must survive: a job that finishes
	// during an outage is neither still in the queue nor yet in history,
	// so without its memory the watch misses it permanently.
	if err := s.SaveProgress(ctx, w, Outcome{Tracked: []JobID{{42, 0}, {42, 1}}}); err != nil {
		t.Fatalf("SaveProgress: %v", err)
	}

	// A fresh Store over the same database is what a restart looks like.
	live, err := NewStore(s.db).Live(ctx)
	if err != nil {
		t.Fatalf("Live: %v", err)
	}
	if len(live) != 1 {
		t.Fatalf("got %d live watches, want 1", len(live))
	}
	if len(live[0].Tracked) != 2 {
		t.Errorf("tracked set lost across reload: %+v", live[0].Tracked)
	}
	if live[0].Event != EventDone || live[0].Mode != ModeAll {
		t.Errorf("the watch came back as a different question: event=%q mode=%q", live[0].Event, live[0].Mode)
	}
}

// TestReloadedWatchEvaluates: a stored watch is strings until it is
// compiled, and an uncompiled one silently matches nothing.
func TestReloadedWatchEvaluates(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	w := register(t, s, "alice", EventDone, ModeAll)
	if err := s.SaveProgress(ctx, w, Outcome{Tracked: []JobID{{42, 0}}}); err != nil {
		t.Fatal(err)
	}

	live, err := s.Live(ctx)
	if err != nil || len(live) != 1 {
		t.Fatalf("Live: %v (%d)", err, len(live))
	}
	// The tracked job is gone from the queue: done.
	if !live[0].Evaluate(Snapshot{}).Fires {
		t.Error("a reloaded watch must evaluate; an uncompiled one selects nothing and never fires")
	}
}

// TestForOwnerIsScoped is the leak this store exists to make
// impossible. The evaluator reads job ads as the daemon, so the owner
// column is the only thing confining a watch's results to whoever
// registered it.
func TestForOwnerIsScoped(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	register(t, s, "alice", EventDone, ModeAny)
	register(t, s, "bob", EventHeld, ModeAny)

	got, err := s.ForOwner(ctx, "alice", nil)
	if err != nil {
		t.Fatalf("ForOwner: %v", err)
	}
	if len(got) != 1 || got[0].Owner != "alice" {
		t.Fatalf("alice sees %d watches: %+v", len(got), got)
	}

	// An unidentified caller must not be answered with everyone's.
	if _, err := s.ForOwner(ctx, "", nil); err == nil {
		t.Error("an empty owner must be refused, not treated as a wildcard")
	}
	if ok, err := s.Cancel(ctx, "", "anything"); err == nil || ok {
		t.Error("Cancel with no owner must be refused")
	}
}

// TestCancelIsOwnerScoped: one caller must not be able to remove
// another's watch by guessing an id.
func TestCancelIsOwnerScoped(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	w := register(t, s, "alice", EventDone, ModeAny)

	if ok, err := s.Cancel(ctx, "bob", w.ID); err != nil || ok {
		t.Errorf("bob cancelled alice's watch (ok=%v err=%v)", ok, err)
	}
	if ok, err := s.Cancel(ctx, "alice", w.ID); err != nil || !ok {
		t.Errorf("alice could not cancel her own watch (ok=%v err=%v)", ok, err)
	}
}

// TestFireIsIdempotent: two evaluator passes, or a retry after a partial
// failure, must not move the moment something happened or replace the
// jobs that caused it. The first answer is the true one.
func TestFireIsIdempotent(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	w := register(t, s, "alice", EventDone, ModeAny)

	first := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	out := Outcome{Fires: true, Satisfied: 2, Matched: []JobRef{{JobID: JobID{42, 0}}}, Tracked: []JobID{{42, 0}}}
	if err := s.Fire(ctx, w.ID, out, first); err != nil {
		t.Fatalf("Fire: %v", err)
	}

	later := out
	later.Satisfied = 99
	later.Matched = []JobRef{{JobID: JobID{42, 7}}}
	if err := s.Fire(ctx, w.ID, later, first.Add(time.Hour)); err != nil {
		t.Fatalf("second Fire: %v", err)
	}

	got, err := s.ForOwner(ctx, "alice", nil)
	if err != nil || len(got) != 1 {
		t.Fatalf("ForOwner: %v", err)
	}
	if !got[0].FiredAt.Equal(first) {
		t.Errorf("FiredAt moved to %v; the first time it happened is the true one", got[0].FiredAt)
	}
	if got[0].MatchedTotal != 2 || len(got[0].Matched) != 1 || got[0].Matched[0].Proc != 0 {
		t.Errorf("the second fire overwrote what caused the first: %+v", got[0])
	}
}

// TestFiredWatchStaysReadable: reading an outcome must not consume it.
// An agent that loses its context, or a second session, has to be able
// to ask again -- that readback is the whole delivery mechanism.
func TestFiredWatchStaysReadable(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	w := register(t, s, "alice", EventDone, ModeAny)
	if err := s.Fire(ctx, w.ID, Outcome{Fires: true, Satisfied: 1}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkDelivered(ctx, "alice", []string{w.ID}); err != nil {
		t.Fatalf("MarkDelivered: %v", err)
	}

	yes := true
	got, err := s.ForOwner(ctx, "alice", &yes)
	if err != nil || len(got) != 1 {
		t.Fatalf("a delivered watch must still be readable: %v (%d)", err, len(got))
	}
	if got[0].DeliveredAt.IsZero() {
		t.Error("delivery should be recorded even though it does not consume the outcome")
	}
}

// TestFiredWatchLeavesTheEvaluator: once satisfied there is nothing left
// to evaluate, and continuing to would cost work per unread answer.
func TestFiredWatchLeavesTheEvaluator(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	w := register(t, s, "alice", EventDone, ModeAny)
	if err := s.Fire(ctx, w.ID, Outcome{Fires: true, Satisfied: 1}, time.Now()); err != nil {
		t.Fatal(err)
	}
	live, err := s.Live(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(live) != 0 {
		t.Errorf("a fired watch is still being evaluated: %+v", live)
	}
}

// TestExpiryStopsEvaluationAndPrunes. An agent that registers a watch
// and never returns is the common case; without expiry the evaluator's
// work grows without bound producing answers nobody reads.
func TestExpiryStopsEvaluationAndPrunes(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	register(t, s, "alice", EventDone, ModeAny)

	// Walk the clock past the TTL.
	s.now = func() time.Time { return time.Now().Add(DefaultTTL + time.Hour) }

	live, err := s.Live(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(live) != 0 {
		t.Errorf("an expired watch is still being evaluated: %+v", live)
	}
	got, err := s.ForOwner(ctx, "alice", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("an expired watch is still being reported: %+v", got)
	}
	n, err := s.Prune(ctx)
	if err != nil || n != 1 {
		t.Errorf("Prune removed %d rows (err=%v), want 1", n, err)
	}
}

// TestTTLIsClamped: a caller asking for "forever" wants the longest
// available, not an error.
func TestTTLIsClamped(t *testing.T) {
	s := testStore(t)
	w, err := New("alice", "l", "ClusterId == 1", EventDone, "", ModeAny)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Register(context.Background(), w, 100*365*24*time.Hour); err != nil {
		t.Fatalf("an over-long TTL should clamp, not fail: %v", err)
	}
}
