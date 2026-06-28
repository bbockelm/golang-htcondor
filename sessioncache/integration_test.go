package sessioncache_test

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/security"
	"github.com/bbockelm/golang-htcondor/sessioncache"
	"github.com/bbockelm/golang-htcondor/sessioncache/sqlite"
)

func signingKey(id string, b byte) sqlite.SigningKey {
	return sqlite.SigningKey{ID: id, Material: bytes.Repeat([]byte{b}, 24)}
}

func storeEntry(t *testing.T, cache *security.SessionCache, id string) {
	t.Helper()
	policy := classad.New()
	_ = policy.Set("User", "condor@pool.example")
	ki := &security.KeyInfo{Data: []byte("session-key-" + id), Protocol: "AESGCM"}
	e := security.NewSessionEntry(id, "<10.0.0.1:9618>", ki, policy,
		time.Now().Add(time.Hour), 30*time.Minute, "")
	cache.Store(e)
}

// snapshot persists the cache to a freshly opened store and closes it,
// mimicking a daemon snapshotting then shutting down.
func snapshot(t *testing.T, path string, keys []sqlite.SigningKey, cache *security.SessionCache) {
	t.Helper()
	store, err := sqlite.Open(path, keys, nil)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := store.Save(context.Background(), sessioncache.Snapshot(cache)); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// TestSessionCacheReloadAcrossRestart is the end-to-end persistence path: a
// session in the cedar cache is snapshotted to the encrypted SQLite store, the
// store is closed (shutdown), the in-memory session is dropped (restart), and a
// freshly reopened store restores it — proving the master-key derivation and
// envelope survive a restart and the session is resumable again.
func TestSessionCacheReloadAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.db")
	keys := []sqlite.SigningKey{signingKey("POOL", 7)}
	cache := security.GetSessionCache()
	id := "integ-reload-unique-1"

	storeEntry(t, cache, id)
	snapshot(t, path, keys, cache)

	// Simulate a restart losing the in-memory cache for this session.
	cache.Invalidate(id)
	if _, ok := cache.LookupNonExpired(id); ok {
		t.Fatal("precondition: session should be gone before restore")
	}

	// Reopen with the same signing key and restore.
	store2, err := sqlite.Open(path, keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store2.Close() }()
	n, err := sessioncache.Restore(context.Background(), store2, cache, nil)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if n < 1 {
		t.Fatalf("expected at least one restored session, got %d", n)
	}

	got, ok := cache.LookupNonExpired(id)
	if !ok {
		t.Fatal("session was not restored into the cache")
	}
	if got.KeyInfo() == nil || string(got.KeyInfo().Data) != "session-key-"+id {
		t.Errorf("restored session key mismatch: %+v", got.KeyInfo())
	}
	if u, ok := got.Policy().EvaluateAttrString("User"); !ok || u != "condor@pool.example" {
		t.Errorf("restored policy User mismatch: %q", u)
	}
}

// TestSessionCacheFlushesOnSigningKeyLoss verifies the advisory behavior: if the
// store is reopened with a signing key that cannot recover the master key, it
// flushes the cache and starts fresh (no error), so restore yields nothing and
// the daemon continues.
func TestSessionCacheFlushesOnSigningKeyLoss(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.db")
	cache := security.GetSessionCache()
	id := "integ-keyloss-unique-1"

	storeEntry(t, cache, id)
	snapshot(t, path, []sqlite.SigningKey{signingKey("POOL", 7)}, cache)
	cache.Invalidate(id)

	// Reopen with a different signing key: must NOT error, and must discard the
	// undecryptable cache.
	store2, err := sqlite.Open(path, []sqlite.SigningKey{signingKey("ROTATED", 200)}, nil)
	if err != nil {
		t.Fatalf("reopen with a new key should flush-and-continue, not error: %v", err)
	}
	defer func() { _ = store2.Close() }()
	recs, err := store2.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 0 {
		t.Errorf("expected an empty cache after signing-key loss, got %d records", len(recs))
	}
	// And the store is usable for fresh saves under the new key.
	storeEntry(t, cache, "integ-keyloss-fresh")
	if err := store2.Save(context.Background(), sessioncache.Snapshot(cache)); err != nil {
		t.Fatalf("save after re-init failed: %v", err)
	}
}
