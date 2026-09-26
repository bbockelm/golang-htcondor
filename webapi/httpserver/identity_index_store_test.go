// Copyright 2026 Morgridge Institute for Research
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package httpserver

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/idmap"
)

// The restart case this exists for. A container comes back with its SSSD
// sidecar cold, so the account database names only the container's own
// handful of accounts for the first minutes. Without a saved index every
// directory login in that window is refused; with one the daemon answers
// from what the previous run knew.
func TestTheIndexSurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	db := newTestDB(t, filepath.Join(dir, "app.db"))
	store := newIdentityIndexStore(db)

	// --- the run before the restart: the directory is readable ---
	full := filepath.Join(dir, "passwd-full")
	body := onePasswdEntry +
		"bbockelm:x:20014:20014:bockelman:/home/bbockelm:/bin/sh\n" +
		"tannenba:x:20013:20013:tatannen:/home/tannenba:/bin/sh\n"
	if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	before := identityOverFile(t, full, time.Hour)
	before.store = store
	warmUpForTest(t, before)
	if got, _, _ := before.resolver.Stats(); got != 3 {
		t.Fatalf("precondition: first run indexed %d accounts, want 3", got)
	}

	// --- the restart: the same database, an account source that cannot
	// be read yet. A file that is not there stands in for the directory
	// being unreachable, which is what a container's first seconds look
	// like; the SSSD-answers-with-nothing variant is covered in droppriv
	// and idmap, where the enumerator can be driven directly.
	cold := filepath.Join(dir, "not-readable-yet")

	after := identityOverFile(t, cold, time.Hour)
	after.store = store
	warmUpForTest(t, after)

	// The mapping the cold source cannot possibly know still resolves,
	// because the saved index proposed it and the verifier confirmed it.
	// Verification here reads the cold file, so the account has to be in
	// it for the mapping to stand -- which is exactly the guarantee: the
	// cache proposes, the live database disposes.
	accounts, _, builtAt := after.resolver.Stats()
	if accounts < 3 {
		t.Errorf("index holds %d accounts after restart; the saved one was not restored", accounts)
	}
	if time.Since(builtAt) > time.Hour {
		t.Errorf("builtAt = %v; the restored index should carry the previous run's build time", builtAt)
	}
}

// A degraded run must not overwrite the good index with its own partial
// view, or the next restart restores the bad one and the cache makes
// things worse rather than better.
func TestARestartDoesNotOverwriteTheSavedIndexWithAPartialOne(t *testing.T) {
	dir := t.TempDir()
	db := newTestDB(t, filepath.Join(dir, "app.db"))
	store := newIdentityIndexStore(db)

	full := filepath.Join(dir, "passwd")
	body := onePasswdEntry +
		"bbockelm:x:20014:20014:bockelman:/home/bbockelm:/bin/sh\n"
	if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	first := identityOverFile(t, full, time.Hour)
	first.store = store
	warmUpForTest(t, first)

	saved, ok, err := store.Load(context.Background())
	if err != nil || !ok {
		t.Fatalf("nothing was saved: ok=%v err=%v", ok, err)
	}
	if len(saved.ByGecos) != 2 {
		t.Fatalf("saved index holds %d entries, want 2", len(saved.ByGecos))
	}

	// A run whose account database has shrunk to nothing readable.
	missing := filepath.Join(dir, "gone")
	second := identityOverFile(t, missing, time.Hour)
	second.store = store
	warmUpForTest(t, second)

	again, ok, err := store.Load(context.Background())
	if err != nil || !ok {
		t.Fatalf("the saved index disappeared: ok=%v err=%v", ok, err)
	}
	if len(again.ByGecos) != len(saved.ByGecos) {
		t.Errorf("saved index went from %d entries to %d; a failed run overwrote it",
			len(saved.ByGecos), len(again.ByGecos))
	}
}

// An empty or corrupt row must not stop the daemon starting.
func TestAnUnreadableSavedIndexIsNotFatal(t *testing.T) {
	dir := t.TempDir()
	db := newTestDB(t, filepath.Join(dir, "app.db"))
	store := newIdentityIndexStore(db)

	if _, err := db.ExecContext(context.Background(),
		`INSERT INTO identity_index (id, snapshot, built_at, updated_at)
		 VALUES (1, 'not json', ?, ?)`, time.Now(), time.Now()); err != nil {
		t.Fatal(err)
	}

	if _, ok, err := store.Load(context.Background()); ok || err == nil {
		t.Errorf("a corrupt row loaded as usable: ok=%v err=%v", ok, err)
	}

	path := filepath.Join(dir, "passwd")
	if err := os.WriteFile(path, []byte(onePasswdEntry), 0o600); err != nil {
		t.Fatal(err)
	}
	li := identityOverFile(t, path, time.Hour)
	li.store = store
	warmUpForTest(t, li) // must not panic or hang
	if got, _, _ := li.resolver.Stats(); got != 1 {
		t.Errorf("index holds %d accounts; the corrupt cache disturbed a normal start", got)
	}
}

// Round-trip through the store, since a snapshot that does not survive
// encoding would fail silently: the daemon would simply never benefit.
func TestASnapshotRoundTripsThroughTheStore(t *testing.T) {
	db := newTestDB(t, filepath.Join(t.TempDir(), "app.db"))
	store := newIdentityIndexStore(db)

	built := time.Now().Add(-90 * time.Minute).UTC().Truncate(time.Second)
	want := idmap.Snapshot{
		ByGecos: map[string]string{"bockelman": "bbockelm"},
		Counts:  map[string]int{"bockelman": 1},
		Users:   []string{"bbockelm", "root"},
		BuiltAt: built,
		Count:   2,
	}
	if err := store.Save(context.Background(), want); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, ok, err := store.Load(context.Background())
	if err != nil || !ok {
		t.Fatalf("Load: ok=%v err=%v", ok, err)
	}
	if got.ByGecos["bockelman"] != "bbockelm" {
		t.Errorf("ByGecos = %v", got.ByGecos)
	}
	if got.Count != 2 || len(got.Users) != 2 {
		t.Errorf("Count = %d, Users = %v", got.Count, got.Users)
	}
	if !got.BuiltAt.Equal(built) {
		t.Errorf("BuiltAt = %v, want %v -- a restored index must age from its real build time", got.BuiltAt, built)
	}
}

// The freeze this nearly introduced. Protecting a restored index makes
// the startup build report an error -- correctly, since it refused to
// replace good knowledge with worse. If that error also skipped starting
// the background refresh, the daemon would hold the restored index for
// the rest of its life and never pick the directory up: a worse failure
// than the clobber it was meant to prevent.
func TestAProtectedStartupBuildStillStartsTheRefreshLoop(t *testing.T) {
	dir := t.TempDir()
	db := newTestDB(t, filepath.Join(dir, "app.db"))
	store := newIdentityIndexStore(db)

	// A previous run's index, saved.
	full := filepath.Join(dir, "passwd")
	body := onePasswdEntry +
		"bbockelm:x:20014:20014:bockelman:/home/bbockelm:/bin/sh\n"
	if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	first := identityOverFile(t, full, time.Hour)
	first.store = store
	warmUpForTest(t, first)
	if got, _, _ := first.resolver.Stats(); got != 2 {
		t.Fatalf("precondition: first run indexed %d accounts, want 2", got)
	}

	// The restart: the account database is unreadable at t=0, so the
	// startup build fails and the restored index is kept.
	missing := filepath.Join(dir, "appears-later")
	after := identityOverFile(t, missing, time.Hour)
	after.store = store
	after.refreshEvery = 5 * time.Millisecond
	warmUpForTest(t, after)

	if got, _, _ := after.resolver.Stats(); got != 2 {
		t.Fatalf("the restored index was lost: %d accounts", got)
	}

	// The database becomes readable, as a directory does once its sidecar
	// answers. Nothing calls Resolve: the daemon must notice by itself.
	grown := body + "tannenba:x:20013:20013:tatannen:/home/tannenba:/bin/sh\n"
	if err := os.WriteFile(missing, []byte(grown), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := waitForIndex(t, after, 3, 5*time.Second); got < 3 {
		t.Fatalf("index still holds %d accounts; the refresh loop never started after a protected build", got)
	}
}
