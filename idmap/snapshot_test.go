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

package idmap

import (
	"context"
	"testing"
	"time"
)

func completeIndex(t *testing.T) (*Resolver, *fakeEnum) {
	t.Helper()
	enum := &fakeEnum{accounts: []Account{
		{Username: "bbockelm", Gecos: "bockelman"},
		{Username: "tannenba", Gecos: "tatannen"},
	}}
	r := New(enum, &fakeVerifier{gecos: map[string]string{
		"bbockelm": "bockelman", "tannenba": "tatannen",
	}})
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatalf("building the initial index: %v", err)
	}
	return r, enum
}

// The case that makes a persisted index worth having -- and that would
// otherwise destroy it. A container restarts, the cached index is
// restored, and then the first rebuild runs while the directory is still
// unreadable. Installing that partial view would discard a complete index
// and start refusing logins that had been working.
func TestADegradedBuildDoesNotReplaceACompleteIndex(t *testing.T) {
	r, enum := completeIndex(t)

	enum.accounts = []Account{{Username: "root", Gecos: "root"}}
	enum.err = unreachableDirectory()
	if err := r.Refresh(context.Background()); err == nil {
		t.Fatal("a degraded rebuild reported success; the caller cannot tell it was refused")
	}

	if got, _, _ := r.Stats(); got != 2 {
		t.Errorf("index holds %d accounts, want the 2 from the complete build", got)
	}
	if r.Degraded() != nil {
		t.Errorf("the retained index is complete, but Degraded reports %v", r.Degraded())
	}
	account, err := r.Resolve(context.Background(), "bockelman")
	if err != nil || account != "bbockelm" {
		t.Errorf("Resolve = %q, %v; a working mapping was lost to a degraded rebuild", account, err)
	}
}

// ...but a degraded build IS installed when there is nothing to protect,
// which is what lets a cold start serve local accounts at all.
func TestADegradedBuildIsInstalledWhenThereIsNoIndexYet(t *testing.T) {
	enum := &fakeEnum{
		accounts: []Account{{Username: "root", Gecos: "root"}},
		err:      unreachableDirectory(),
	}
	r := New(enum, &fakeVerifier{gecos: map[string]string{"root": "root"}})

	if err := r.Refresh(context.Background()); err != nil {
		t.Fatalf("the first build refused to install anything: %v", err)
	}
	if got, _, _ := r.Stats(); got != 1 {
		t.Errorf("index holds %d accounts, want 1", got)
	}
	if r.Degraded() == nil {
		t.Error("a partial index must say so")
	}
}

// A complete build replaces a degraded one -- otherwise the first bad
// index would be permanent.
func TestACompleteBuildReplacesADegradedIndex(t *testing.T) {
	enum := &fakeEnum{
		accounts: []Account{{Username: "root", Gecos: "root"}},
		err:      unreachableDirectory(),
	}
	r := New(enum, &fakeVerifier{gecos: map[string]string{"root": "root", "bbockelm": "bockelman"}})
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	enum.accounts = []Account{
		{Username: "root", Gecos: "root"},
		{Username: "bbockelm", Gecos: "bockelman"},
	}
	enum.err = nil
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if got, _, _ := r.Stats(); got != 2 {
		t.Errorf("index holds %d accounts, want 2", got)
	}
	if r.Degraded() != nil {
		t.Errorf("Degraded = %v after a complete build", r.Degraded())
	}
}

// Only a complete index is worth saving. A degraded one is missing
// accounts by definition and its ambiguity counts are therefore
// unreliable, so persisting it would outlive the outage that caused it.
func TestOnlyACompleteIndexIsSnapshotted(t *testing.T) {
	r, _ := completeIndex(t)
	if _, ok := r.Snapshot(); !ok {
		t.Fatal("a complete index refused to snapshot")
	}

	// A PARTIAL index: accounts were readable, the directory was not. It
	// must be refused for a reason other than being empty, so it carries
	// entries.
	partial := New(&fakeEnum{
		accounts: []Account{{Username: "root", Gecos: "root"}},
		err:      unreachableDirectory(),
	}, &fakeVerifier{gecos: map[string]string{"root": "root"}})
	if err := partial.Refresh(context.Background()); err != nil {
		t.Fatalf("building the partial index: %v", err)
	}
	if n, _, _ := partial.Stats(); n == 0 {
		t.Fatal("precondition: the partial index must hold entries, or this tests only the empty case")
	}
	if partial.Degraded() == nil {
		t.Fatal("precondition: the index must be degraded")
	}
	if _, ok := partial.Snapshot(); ok {
		t.Error("a degraded index was offered for persisting")
	}
}

// A restored index answers immediately, which is the point: a process
// that has just started can map logins instead of refusing them until the
// directory becomes readable.
func TestARestoredIndexResolves(t *testing.T) {
	donor, _ := completeIndex(t)
	snap, ok := donor.Snapshot()
	if !ok {
		t.Fatal("no snapshot")
	}

	// A new process, whose account database cannot be enumerated at all.
	enum := &fakeEnum{err: unreachableDirectory()}
	r := New(enum, &fakeVerifier{gecos: map[string]string{"bbockelm": "bockelman"}})
	r.Restore(snap)

	account, err := r.Resolve(context.Background(), "bockelman")
	if err != nil || account != "bbockelm" {
		t.Errorf("Resolve = %q, %v; the restored index did not answer", account, err)
	}
	if enum.calls != 0 {
		t.Errorf("the enumerator was called %d times; a fresh restore is not stale", enum.calls)
	}
}

// The restored index must age from when it was BUILT, not from when it
// was loaded. Resetting the clock would make a cache from hours ago look
// freshly built and suppress the rebuild that should correct it.
func TestARestoredIndexKeepsItsOriginalAge(t *testing.T) {
	donor, _ := completeIndex(t)
	snap, _ := donor.Snapshot()
	snap.BuiltAt = time.Now().Add(-2 * time.Hour)

	r := New(&fakeEnum{}, &fakeVerifier{})
	r.Restore(snap)

	_, _, builtAt := r.Stats()
	if time.Since(builtAt) < time.Hour {
		t.Errorf("builtAt = %v; the restored index reports itself newer than it is", builtAt)
	}
}

// A restored index is a set of candidates, not an authority. An entry
// that no longer matches the live database must still be refused.
func TestARestoredEntryIsStillVerified(t *testing.T) {
	donor, _ := completeIndex(t)
	snap, _ := donor.Snapshot()

	// The live database has since renamed this account's GECOS.
	r := New(&fakeEnum{err: unreachableDirectory()},
		&fakeVerifier{gecos: map[string]string{"bbockelm": "somebody-else"}})
	r.Restore(snap)

	if account, err := r.Resolve(context.Background(), "bockelman"); err == nil {
		t.Errorf("Resolve = %q; a stale cache entry was believed without checking", account)
	}
}

// provenanceEnum reports whether a directory contributed, the way
// SystemAccounts does.
type provenanceEnum struct {
	accounts      []Account
	fromDirectory bool
	err           error
	calls         int
}

func (p *provenanceEnum) Name() string { return "provenance" }
func (p *provenanceEnum) Enumerate(context.Context) ([]Account, error) {
	p.calls++
	return p.accounts, p.err
}
func (p *provenanceEnum) EnumerateWithProvenance(context.Context) ([]Account, bool, error) {
	p.calls++
	return p.accounts, p.fromDirectory, p.err
}

// The exact sequence observed on a restarted pod:
//
//	Restored the account index saved by a previous run  accounts=4267
//	Indexed accounts by GECOS for identity mapping      accounts=18
//
// The restored index covered a directory; the startup rebuild ran before
// the SSSD sidecar's socket existed, so it saw only the container's own
// accounts and reported NO error -- "no directory here" is not a failure.
// It therefore looked like complete knowledge and replaced 4267 accounts
// with 18, which is precisely what persisting the index was meant to
// prevent.
func TestAColdStartDoesNotClobberARestoredDirectoryIndex(t *testing.T) {
	donor := New(&provenanceEnum{
		accounts:      []Account{{Username: "bbockelm", Gecos: "bockelman"}},
		fromDirectory: true,
	}, &fakeVerifier{gecos: map[string]string{"bbockelm": "bockelman"}})
	if err := donor.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	snap, ok := donor.Snapshot()
	if !ok {
		t.Fatal("no snapshot")
	}
	if !snap.FromDirectory {
		t.Fatal("the snapshot does not record that it covered a directory")
	}

	// The restarted process: cache restored, then a rebuild that reaches
	// no directory and says so by reporting no error.
	cold := &provenanceEnum{
		accounts:      []Account{{Username: "root", Gecos: "root"}},
		fromDirectory: false,
	}
	r := New(cold, &fakeVerifier{gecos: map[string]string{"bbockelm": "bockelman", "root": "root"}})
	r.Restore(snap)

	if err := r.Refresh(context.Background()); err == nil {
		t.Error("the cold rebuild reported success; the caller cannot tell the index was protected")
	}

	if got, _, _ := r.Stats(); got != 1 || !indexKnows(r, "bockelman") {
		t.Errorf("index holds %d accounts and lost the directory mapping; a cold start clobbered the cache", got)
	}
	account, err := r.Resolve(context.Background(), "bockelman")
	if err != nil || account != "bbockelm" {
		t.Errorf("Resolve = %q, %v; the restored directory mapping was lost", account, err)
	}
}

func indexKnows(r *Resolver, gecos string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.byGecos[gecos]
	return ok
}

// A directory-backed build must still replace a directory-backed index,
// or the first one would be permanent.
func TestADirectoryBuildStillReplacesADirectoryIndex(t *testing.T) {
	enum := &provenanceEnum{
		accounts:      []Account{{Username: "bbockelm", Gecos: "bockelman"}},
		fromDirectory: true,
	}
	r := New(enum, &fakeVerifier{gecos: map[string]string{
		"bbockelm": "bockelman", "tannenba": "tatannen",
	}})
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	enum.accounts = []Account{
		{Username: "bbockelm", Gecos: "bockelman"},
		{Username: "tannenba", Gecos: "tatannen"},
	}
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if got, _, _ := r.Stats(); got != 2 {
		t.Errorf("index holds %d accounts, want 2", got)
	}
}

// On a host that genuinely has no directory, nothing is protected and
// ordinary rebuilds must keep working -- otherwise the first index would
// freeze forever.
func TestWithoutADirectoryRebuildsAreUnaffected(t *testing.T) {
	enum := &provenanceEnum{
		accounts:      []Account{{Username: "root", Gecos: "root"}},
		fromDirectory: false,
	}
	r := New(enum, &fakeVerifier{gecos: map[string]string{"root": "root", "daemon": "daemon"}})
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	enum.accounts = []Account{
		{Username: "root", Gecos: "root"},
		{Username: "daemon", Gecos: "daemon"},
	}
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if got, _, _ := r.Stats(); got != 2 {
		t.Errorf("index holds %d accounts; a no-directory host cannot rebuild", got)
	}
}
