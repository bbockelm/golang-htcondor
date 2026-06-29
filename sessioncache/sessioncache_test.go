package sessioncache

import (
	"context"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/security"
)

func makeEntry(t *testing.T, id string) *security.SessionEntry {
	t.Helper()
	policy := classad.New()
	_ = policy.Set("User", "condor@pool.example")
	ki := &security.KeyInfo{Data: []byte("session-key-" + id), Protocol: "AESGCM"}
	e := security.NewSessionEntry(id, "<10.0.0.1:9618>", ki, policy,
		time.Now().Add(time.Hour), 30*time.Minute, "")
	e.SetLastPeerVersion("$CondorVersion: 25.12.0$")
	return e
}

func TestEntryRecordRoundTrip(t *testing.T) {
	orig := makeEntry(t, "conv-1")
	got, err := RecordToEntry(EntryToRecord(orig))
	if err != nil {
		t.Fatal(err)
	}
	if got.ID() != "conv-1" || got.Addr() != "<10.0.0.1:9618>" {
		t.Errorf("identity not preserved: id=%q addr=%q", got.ID(), got.Addr())
	}
	if got.KeyInfo() == nil || string(got.KeyInfo().Data) != "session-key-conv-1" {
		t.Errorf("key not preserved: %+v", got.KeyInfo())
	}
	if got.LastPeerVersion() != "$CondorVersion: 25.12.0$" {
		t.Errorf("peer version not preserved: %q", got.LastPeerVersion())
	}
	if u, ok := got.Policy().EvaluateAttrString("User"); !ok || u != "condor@pool.example" {
		t.Errorf("policy User not preserved: %q (ok=%v)", u, ok)
	}
}

// memStore is a trivial in-memory SessionStore for testing Restore.
type memStore struct{ recs []SessionRecord }

func (m *memStore) Load(context.Context) ([]SessionRecord, error)   { return m.recs, nil }
func (m *memStore) Save(_ context.Context, r []SessionRecord) error { m.recs = r; return nil }
func (m *memStore) Close() error                                    { return nil }

func TestSnapshotSkipsInheritedAndExpired(t *testing.T) {
	cache := security.GetSessionCache()

	keep := makeEntry(t, "keep-unique-xyz")
	cache.Store(keep)
	inh := makeEntry(t, "inherited-unique-xyz")
	inh.SetInherited(true)
	cache.Store(inh)

	recs := Snapshot(cache)
	ids := map[string]bool{}
	for _, r := range recs {
		ids[r.ID] = true
	}
	if !ids["keep-unique-xyz"] {
		t.Error("normal session should be snapshotted")
	}
	if ids["inherited-unique-xyz"] {
		t.Error("inherited session must not be snapshotted")
	}
}

func TestRestoreIntoCache(t *testing.T) {
	cache := security.GetSessionCache()
	id := "restore-unique-xyz"
	store := &memStore{recs: []SessionRecord{EntryToRecord(makeEntry(t, id))}}

	n, err := Restore(context.Background(), store, cache, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Fatalf("expected at least 1 restored, got %d", n)
	}
	got, ok := cache.LookupNonExpired(id)
	if !ok {
		t.Fatal("session not restored into cache")
	}
	if string(got.KeyInfo().Data) != "session-key-"+id {
		t.Errorf("restored key mismatch: %+v", got.KeyInfo())
	}
}
