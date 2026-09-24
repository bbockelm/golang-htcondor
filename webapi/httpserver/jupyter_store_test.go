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

// A lost delivery heals. The roll commits before the new token is handed
// over, so a helper can be left holding the one the session moved away
// from -- and without grace that session could never reconnect.
func TestPreviousNonceIsAcceptedOnce(t *testing.T) {
	s := newJupyterTestStore(t)
	ctx := context.Background()
	if err := s.Put(ctx, jupyterSessionRow{
		InstanceID: "abc", Owner: "alice", NextNonce: []byte("one"),
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// The server rolls one -> two, and the helper never receives "two".
	ok, err := s.RollNonce(ctx, "abc", []byte("one"), []byte("two"))
	if err != nil || !ok {
		t.Fatalf("first roll: ok=%v err=%v", ok, err)
	}

	// It redials with the token it still has.
	ok, err = s.RollNonce(ctx, "abc", []byte("one"), []byte("three"))
	if err != nil {
		t.Fatalf("grace roll: %v", err)
	}
	if !ok {
		t.Fatal("the previous nonce was refused; a lost delivery would end the session")
	}

	// And the grace is spent: a second consecutive miss is not tolerated,
	// because delivery failing twice running is not a blip.
	ok, err = s.RollNonce(ctx, "abc", []byte("one"), []byte("four"))
	if err != nil {
		t.Fatalf("second grace roll: %v", err)
	}
	if ok {
		t.Error("the same nonce was accepted twice on the grace path")
	}
}

// A successful round trip leaves no grace outstanding, so a token two
// generations old is refused.
func TestGraceIsClearedByASuccessfulRoll(t *testing.T) {
	s := newJupyterTestStore(t)
	ctx := context.Background()
	_ = s.Put(ctx, jupyterSessionRow{
		InstanceID: "abc", Owner: "alice", NextNonce: []byte("one"),
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	})

	// one -> two (prev = one), then two -> three (prev = two).
	if ok, _ := s.RollNonce(ctx, "abc", []byte("one"), []byte("two")); !ok {
		t.Fatal("first roll refused")
	}
	if ok, _ := s.RollNonce(ctx, "abc", []byte("two"), []byte("three")); !ok {
		t.Fatal("second roll refused")
	}
	// "one" is now two generations back and must be dead.
	if ok, _ := s.RollNonce(ctx, "abc", []byte("one"), []byte("four")); ok {
		t.Error("a nonce two generations old was accepted")
	}
}

// Two helpers redialing at once must not both win, or two tunnels attach
// to one session.
//
// The grace makes this subtler than it looks: both present the same
// nonce, so the second matches prev_nonce and the store alone would let
// it through. The registry is what serialises them -- it claims the
// session's one connection slot before any token is spent -- and this
// pins the store's half: the winner's roll must retire the nonce rather
// than leave it live.
func TestRollNonceHasOneWinner(t *testing.T) {
	s := newJupyterTestStore(t)
	ctx := context.Background()
	_ = s.Put(ctx, jupyterSessionRow{
		InstanceID: "abc", Owner: "alice", NextNonce: []byte("start"),
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	})

	if ok, _ := s.RollNonce(ctx, "abc", []byte("start"), []byte("a")); !ok {
		t.Fatal("the first roll was refused")
	}
	row, err := s.Get(ctx, "abc")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(row.NextNonce) != "a" {
		t.Errorf("next nonce = %q, want the winner's", row.NextNonce)
	}
	if string(row.PrevNonce) != "start" {
		t.Errorf("prev nonce = %q, want the retired one", row.PrevNonce)
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
