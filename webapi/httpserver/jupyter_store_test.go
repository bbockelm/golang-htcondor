package httpserver

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/httpserver/appdb"
)

func newJupyterTestStore(t *testing.T) *jupyterStore {
	t.Helper()
	db, err := appdb.Open(filepath.Join(t.TempDir(), "app.db"))
	if err != nil {
		t.Fatalf("appdb.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := appdb.Migrate(context.Background(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// No sealer: a deployment without HTTP_API_KEK_FILE still has to work,
	// and it is the shape most tests run in.
	return newJupyterStore(db, nil)
}

// The secret is the reason a session can outlive the process. Generated
// per process, every token minted before a restart stops verifying after
// it -- which is what killed every session.
func TestSigningSecretIsStableAcrossCalls(t *testing.T) {
	s := newJupyterTestStore(t)
	first, err := s.SigningSecret(context.Background())
	if err != nil {
		t.Fatalf("SigningSecret: %v", err)
	}
	if len(first) < 32 {
		t.Fatalf("secret is %d bytes, want at least 32", len(first))
	}
	second, err := s.SigningSecret(context.Background())
	if err != nil {
		t.Fatalf("SigningSecret (again): %v", err)
	}
	if string(first) != string(second) {
		t.Error("a second call minted a different secret; tokens would stop verifying")
	}
}

// Single-use, and durable: the swap only applies for the nonce the session
// is actually waiting for, so a replay of a spent token loses.
func TestRollNonceRefusesAReplay(t *testing.T) {
	s := newJupyterTestStore(t)
	ctx := context.Background()
	if err := s.Put(ctx, jupyterSessionRow{
		InstanceID: "abc", Owner: "alice", NextNonce: []byte("one"),
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	ok, err := s.RollNonce(ctx, "abc", []byte("one"), []byte("two"))
	if err != nil || !ok {
		t.Fatalf("first roll: ok=%v err=%v", ok, err)
	}
	// The same token again. This is the replay the in-memory burned set
	// could not catch after a restart, because it came back empty.
	ok, err = s.RollNonce(ctx, "abc", []byte("one"), []byte("three"))
	if err != nil {
		t.Fatalf("replay roll: %v", err)
	}
	if ok {
		t.Error("a spent nonce was accepted a second time")
	}

	row, err := s.Get(ctx, "abc")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(row.NextNonce) != "two" {
		t.Errorf("next nonce = %q, want the one from the winning roll", row.NextNonce)
	}
}

// Two helpers redialing at once must not both win, or two tunnels attach
// to one session.
func TestRollNonceHasOneWinner(t *testing.T) {
	s := newJupyterTestStore(t)
	ctx := context.Background()
	_ = s.Put(ctx, jupyterSessionRow{
		InstanceID: "abc", Owner: "alice", NextNonce: []byte("start"),
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	})

	first, _ := s.RollNonce(ctx, "abc", []byte("start"), []byte("a"))
	second, _ := s.RollNonce(ctx, "abc", []byte("start"), []byte("b"))
	if first == second {
		t.Errorf("both rolls returned %v; exactly one must win", first)
	}
}

// Rows are the credential store, so they must not accumulate.
func TestExpiredSessionsAreSwept(t *testing.T) {
	s := newJupyterTestStore(t)
	ctx := context.Background()
	now := time.Now()
	_ = s.Put(ctx, jupyterSessionRow{
		InstanceID: "old", Owner: "alice", NextNonce: []byte("n"),
		CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour),
	})
	_ = s.Put(ctx, jupyterSessionRow{
		InstanceID: "live", Owner: "alice", NextNonce: []byte("n"),
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	})

	n, err := s.DeleteExpired(ctx, now)
	if err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}
	if n != 1 {
		t.Errorf("swept %d rows, want 1", n)
	}
	if _, err := s.Get(ctx, "old"); !errors.Is(err, sql.ErrNoRows) {
		t.Error("the expired session survived the sweep")
	}
	if _, err := s.Get(ctx, "live"); err != nil {
		t.Errorf("the sweep took a live session: %v", err)
	}
}

// Only unexpired sessions are re-adopted: an expired one is a slot that
// should be let go, not put back.
func TestLiveExcludesExpired(t *testing.T) {
	s := newJupyterTestStore(t)
	ctx := context.Background()
	now := time.Now()
	_ = s.Put(ctx, jupyterSessionRow{InstanceID: "old", Owner: "a", NextNonce: []byte("n"),
		CreatedAt: now, ExpiresAt: now.Add(-time.Minute)})
	_ = s.Put(ctx, jupyterSessionRow{InstanceID: "new", Owner: "a", NextNonce: []byte("n"),
		CreatedAt: now, ExpiresAt: now.Add(time.Hour)})

	rows, err := s.Live(ctx, now)
	if err != nil {
		t.Fatalf("Live: %v", err)
	}
	if len(rows) != 1 || rows[0].InstanceID != "new" {
		t.Errorf("Live returned %+v, want only the unexpired session", rows)
	}
}
