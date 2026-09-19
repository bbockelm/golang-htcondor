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
