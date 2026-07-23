package sqlite

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/sessioncache"
)

func sk(id string, b byte) SigningKey { return key(id, b) }

func sampleRecords() []sessioncache.SessionRecord {
	return []sessioncache.SessionRecord{
		{
			ID:          "sess-1",
			Addr:        "<10.0.0.1:9618>",
			KeyData:     []byte("super-secret-session-key"),
			KeyProtocol: "AESGCM",
			PolicyText:  "[ User = \"condor@pool\" ]",
			Expiration:  time.Now().Add(time.Hour).Truncate(time.Second),
			LeaseSecs:   1800,
			PeerVersion: "$CondorVersion: 25.12.0$",
		},
		{
			ID:         "sess-2",
			Addr:       "<10.0.0.2:9618>",
			KeyData:    []byte("another-key"),
			Expiration: time.Now().Add(2 * time.Hour).Truncate(time.Second),
		},
	}
}

func openStore(t *testing.T, path string, keys []SigningKey) *store {
	t.Helper()
	s, err := Open(path, keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s.(*store)
}

// totalChanges returns SQLite's cumulative INSERT/UPDATE/DELETE count for the
// connection, used to assert that an unchanged Save writes nothing.
func (s *store) totalChanges(t *testing.T) int64 {
	t.Helper()
	var n int64
	if err := s.db.QueryRowContext(context.Background(), `SELECT total_changes()`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestSessionStoreRoundTripAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.db")
	keys := []SigningKey{sk("POOL", 1)}

	st := openStore(t, path, keys)
	if err := st.Save(context.Background(), sampleRecords()); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()

	st2 := openStore(t, path, keys)
	defer func() { _ = st2.Close() }()
	got, err := st2.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 records, got %d", len(got))
	}
	byID := map[string]sessioncache.SessionRecord{}
	for _, r := range got {
		byID[r.ID] = r
	}
	if !bytes.Equal(byID["sess-1"].KeyData, []byte("super-secret-session-key")) {
		t.Errorf("sess-1 key not restored: %q", byID["sess-1"].KeyData)
	}
	if byID["sess-1"].PolicyText != "[ User = \"condor@pool\" ]" {
		t.Errorf("sess-1 policy not restored: %q", byID["sess-1"].PolicyText)
	}
}

func TestSessionStoreEncryptedAtRest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.db")
	st := openStore(t, path, []SigningKey{sk("POOL", 1)})
	secret := []byte("super-secret-session-key")
	if err := st.Save(context.Background(), sampleRecords()); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()

	raw, err := os.ReadFile(path) //nolint:gosec // test reads its own temp db file
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, secret) {
		t.Error("plaintext session key found in database file; at-rest encryption failed")
	}
}

func TestSessionStoreRequiresKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.db")
	if _, err := Open(path, nil, nil); err == nil {
		t.Error("expected error when no signing keys are available")
	}
}

func TestSessionStoreKeyRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.db")
	k1 := sk("POOL", 1)
	k2 := sk("POOL2", 9)

	st := openStore(t, path, []SigningKey{k1})
	if err := st.Save(context.Background(), sampleRecords()); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()

	st2 := openStore(t, path, []SigningKey{k1, k2}) // re-wrap for k2
	_ = st2.Close()

	st3 := openStore(t, path, []SigningKey{k2}) // only the new key
	defer func() { _ = st3.Close() }()
	got, err := st3.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 records after rotation, got %d", len(got))
	}
}

func TestSessionStoreKeyLossReinitializes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.db")
	st := openStore(t, path, []SigningKey{sk("POOL", 1)})
	if err := st.Save(context.Background(), sampleRecords()); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()

	st2 := openStore(t, path, []SigningKey{sk("DIFFERENT", 200)})
	defer func() { _ = st2.Close() }()
	got, err := st2.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty cache after key loss, got %d records", len(got))
	}
	if err := st2.Save(context.Background(), sampleRecords()); err != nil {
		t.Fatalf("save after re-init failed: %v", err)
	}
}

func TestSessionStoreSkipsExpired(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.db")
	st := openStore(t, path, []SigningKey{sk("POOL", 1)})
	defer func() { _ = st.Close() }()
	recs := []sessioncache.SessionRecord{
		{ID: "live", KeyData: []byte("k"), Expiration: time.Now().Add(time.Hour)},
		{ID: "dead", KeyData: []byte("k"), Expiration: time.Now().Add(-time.Hour)},
	}
	if err := st.Save(context.Background(), recs); err != nil {
		t.Fatal(err)
	}
	got, err := st.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "live" {
		t.Errorf("expected only the live session, got %+v", got)
	}
}

// TestSessionStoreDeltaWrites asserts the O(churn) behavior: an unchanged Save
// performs no database writes, and a changed/removed Save writes only the diff.
func TestSessionStoreDeltaWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.db")
	st := openStore(t, path, []SigningKey{sk("POOL", 1)})
	defer func() { _ = st.Close() }()
	ctx := context.Background()

	recs := sampleRecords()
	if err := st.Save(ctx, recs); err != nil {
		t.Fatal(err)
	}

	// An identical Save must write nothing.
	before := st.totalChanges(t)
	if err := st.Save(ctx, recs); err != nil {
		t.Fatal(err)
	}
	if after := st.totalChanges(t); after != before {
		t.Errorf("unchanged Save wrote %d rows, want 0", after-before)
	}

	// Change one record + drop another: exactly one upsert + one delete.
	recs[0].Expiration = recs[0].Expiration.Add(time.Hour) // lease renewal
	changed := recs[:1]
	before = st.totalChanges(t)
	if err := st.Save(ctx, changed); err != nil {
		t.Fatal(err)
	}
	if delta := st.totalChanges(t) - before; delta != 2 {
		t.Errorf("changed+removed Save wrote %d rows, want 2 (1 upsert + 1 delete)", delta)
	}

	got, err := st.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "sess-1" {
		t.Errorf("after delta, expected only sess-1, got %+v", got)
	}
}

// TestOpenRestrictsFileMode verifies the session database and its WAL/shared
// sidecars are created 0600 (not world/group readable), and that an existing
// looser file is tightened on reopen. Contents are encrypted, but the metadata
// should not be readable either.
func TestOpenRestrictsFileMode(t *testing.T) {
	// A permissive umask so the mode we assert is the store's doing, not the
	// environment's -- without the fix SQLite would create the file 0666&~umask.
	old := syscallUmask(0)
	defer syscallUmask(old)

	dir := t.TempDir()
	path := filepath.Join(dir, "sessions_test.db")

	st := openStore(t, path, []SigningKey{sk("POOL", 1)})
	// A write plus a checkpoint materializes the -wal and -shm sidecars.
	if err := st.Save(context.Background(), sampleRecords()); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(context.Background(), `PRAGMA wal_checkpoint(PASSIVE)`); err != nil {
		t.Fatal(err)
	}

	for _, suffix := range []string{"", "-wal", "-shm"} {
		p := path + suffix
		info, err := os.Stat(p)
		if err != nil {
			if suffix != "" {
				continue // sidecar may not exist on every platform/config
			}
			t.Fatalf("stat %s: %v", p, err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s mode = %o, want 600", p, perm)
		}
	}
	_ = st.Close()

	// A pre-existing looser file must be tightened on reopen.
	if err := os.Chmod(path, 0o644); err != nil { //nolint:gosec // G302: deliberately loosening to test tightening
		t.Fatal(err)
	}
	st2 := openStore(t, path, []SigningKey{sk("POOL", 1)})
	defer func() { _ = st2.Close() }()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("reopen did not tighten mode: %o, want 600", perm)
	}
}
