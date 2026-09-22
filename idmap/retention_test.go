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
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"
)

// directory builds a plausible account list: every account's GECOS is its
// own name, which is the shape ~95% of the real directory has.
func directory(n int) []Account {
	out := make([]Account, 0, n)
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("user%03d", i)
		out = append(out, Account{Username: name, Gecos: name, UID: uint32(30000 + i)})
	}
	return out
}

// gecosOfAll answers by name for every account in a list, the way
// getpwnam does even while enumeration is cold.
func gecosOfAll(accounts []Account) *fakeVerifier {
	m := make(map[string]string, len(accounts))
	for _, a := range accounts {
		m[a.Username] = a.Gecos
	}
	return &fakeVerifier{gecos: m}
}

// The outage, in miniature. SSSD enumerated 4439 accounts one second and
// 17 the next; the rebuild that landed on 17 replaced the index and
// refused everybody else until the next good one.
//
// The ratio here is the measured one. What must survive is not "most" of
// the index but all of it: an enumeration is not a deletion notice.
func TestAnEnumerationThatComesBackShortEvictsNobody(t *testing.T) {
	full := directory(444)
	enum := &fakeEnum{accounts: full}
	r := New(enum, gecosOfAll(full))
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatalf("building the full index: %v", err)
	}
	if held, _, _ := r.Stats(); held != 444 {
		t.Fatalf("precondition: index holds %d accounts, want 444", held)
	}

	// The cold answer: the first handful of accounts and nobody else.
	enum.accounts = full[:2]
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatalf("the short rebuild failed outright: %v", err)
	}

	if held, _, _ := r.Stats(); held != 444 {
		t.Errorf("index holds %d accounts after a short enumeration, want all 444 kept", held)
	}
	// Spot-check accounts from the part of the directory the short
	// enumeration did not mention, including the last one.
	for _, subject := range []string{"user003", "user221", "user443"} {
		got, err := r.Resolve(context.Background(), subject)
		if err != nil || got != subject {
			t.Errorf("Resolve(%q) = %q, %v; a login was lost to one short enumeration", subject, got, err)
		}
	}
}

// Absence still means something -- it just has to be repeated. The count
// is written out step by step rather than looped to absenceLimit, so that
// changing the constant makes this test fail instead of following it.
func TestAnAccountIsForgottenOnlyAfterThreeConsecutiveAbsences(t *testing.T) {
	accounts := []Account{
		{Username: "staying", Gecos: "staying"},
		{Username: "leaving", Gecos: "leaving"},
	}
	enum := &fakeEnum{accounts: accounts}
	// The verifier does NOT know "leaving": the account is really gone,
	// so nothing can rescue the entry once the index drops it.
	r := New(enum, &fakeVerifier{gecos: map[string]string{"staying": "staying"}})
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	enum.accounts = accounts[:1]

	refresh := func(round int) {
		t.Helper()
		if err := r.Refresh(context.Background()); err != nil {
			t.Fatalf("refresh %d: %v", round, err)
		}
	}

	refresh(1)
	if !indexKnows(r, "leaving") {
		t.Fatal("one missed enumeration forgot the account; that is the outage")
	}
	refresh(2)
	if !indexKnows(r, "leaving") {
		t.Fatal("two missed enumerations forgot the account; absence must accumulate further than that")
	}
	refresh(3)
	if indexKnows(r, "leaving") {
		t.Error("the account was still indexed after three enumerations in a row missed it; " +
			"a real deletion must eventually take effect")
	}

	// And the account that kept being listed is untouched throughout.
	if got, err := r.Resolve(context.Background(), "staying"); err != nil || got != "staying" {
		t.Errorf("Resolve(staying) = %q, %v", got, err)
	}
}

// Only CONSECUTIVE absences count. A directory that answers intermittently
// -- which is what the measurements show -- must never accumulate its way
// to an eviction.
func TestOneSightingClearsTheAbsenceRecord(t *testing.T) {
	accounts := []Account{
		{Username: "steady", Gecos: "steady"},
		{Username: "flaky", Gecos: "flaky"},
	}
	enum := &fakeEnum{accounts: accounts}
	r := New(enum, gecosOfAll(accounts))
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Missing, missing, present, missing, missing: five rounds, never
	// three in a row.
	for _, listed := range []bool{false, false, true, false, false} {
		if listed {
			enum.accounts = accounts
		} else {
			enum.accounts = accounts[:1]
		}
		if err := r.Refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
	}

	if !indexKnows(r, "flaky") {
		t.Error("an account listed in the middle of the run was still evicted; " +
			"absences must be consecutive, not cumulative")
	}
}

// An account retained across an enumeration is a full member of the
// index, duplicate detection included. If it were not, an enumeration
// that happened to list only one of two accounts sharing a GECOS would
// resolve the subject to that one -- picking a victim, which is the thing
// this package refuses to do.
func TestARetainedAccountStillCausesAmbiguity(t *testing.T) {
	both := []Account{
		{Username: "twin-a", Gecos: "shared.identity"},
		{Username: "twin-b", Gecos: "shared.identity"},
	}
	enum := &fakeEnum{accounts: both}
	r := New(enum, gecosOfAll(both))
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	// The next enumeration mentions only one of the twins.
	enum.accounts = both[1:]
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	got, err := r.Resolve(context.Background(), "shared.identity")
	if !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("Resolve = %q, %v; the retained twin stopped counting as a claimant", got, err)
	}
	if amb := r.AmbiguousGecos(); len(amb) != 1 || amb[0] != "shared.identity" {
		t.Errorf("AmbiguousGecos() = %v, want the shared GECOS still reported", amb)
	}
	if _, ambCount, _ := r.Stats(); ambCount != 1 {
		t.Errorf("Stats reports %d ambiguous GECOS values, want 1", ambCount)
	}
}

// The live answer wins for the accounts it covers. Retaining an account
// the enumeration missed must not also retain a GECOS the enumeration
// contradicted, or a re-pointed account would keep answering for its old
// subject.
func TestAnEnumeratedAccountsGecosIsWrittenThrough(t *testing.T) {
	enum := &fakeEnum{accounts: []Account{{Username: "bbockelm", Gecos: "bockelman"}}}
	ver := &fakeVerifier{gecos: map[string]string{"bbockelm": "bockelman"}}
	r := New(enum, ver)
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	enum.accounts = []Account{{Username: "bbockelm", Gecos: "brian.bockelman"}}
	ver.gecos["bbockelm"] = "brian.bockelman"
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	if got, err := r.Resolve(context.Background(), "brian.bockelman"); err != nil || got != "bbockelm" {
		t.Errorf("Resolve(new GECOS) = %q, %v; the update did not take", got, err)
	}
	if got, err := r.Resolve(context.Background(), "bockelman"); err == nil {
		t.Errorf("Resolve(old GECOS) = %q; the superseded GECOS is still indexed", got)
	}
	if held, _, _ := r.Stats(); held != 1 {
		t.Errorf("index holds %d accounts, want 1: a renamed GECOS is not a second account", held)
	}
}

// The report is the only way a partial enumeration can be noticed from
// outside, so it has to name names rather than just count.
func TestLastBuildNamesWhatTheEnumerationMissed(t *testing.T) {
	accounts := []Account{
		{Username: "kept", Gecos: "kept"},
		{Username: "vanishing", Gecos: "vanishing"},
	}
	enum := &fakeEnum{accounts: accounts}
	r := New(enum, gecosOfAll(accounts))

	if _, ok := r.LastBuild(); ok {
		t.Error("a resolver that has never built reported a build")
	}
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	report, ok := r.LastBuild()
	if !ok {
		t.Fatal("no report after a build")
	}
	if report.Shrank() {
		t.Errorf("a complete enumeration reported a shrink: %+v", report)
	}
	if report.Enumerated != 2 || report.Held != 2 {
		t.Errorf("report = %d enumerated, %d held; want 2 and 2", report.Enumerated, report.Held)
	}

	enum.accounts = accounts[:1]
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	report, _ = r.LastBuild()
	if !report.Shrank() {
		t.Error("a short enumeration was not reported as one; this is the only trace it leaves")
	}
	if len(report.Retained) != 1 || report.Retained[0] != "vanishing" {
		t.Errorf("Retained = %v, want [vanishing] named", report.Retained)
	}
	if len(report.Evicted) != 0 {
		t.Errorf("Evicted = %v on the first miss; nothing should be dropped yet", report.Evicted)
	}
	if report.Enumerated != 1 || report.Held != 2 {
		t.Errorf("report = %d enumerated, %d held; want 1 enumerated and 2 still held",
			report.Enumerated, report.Held)
	}

	// Two more misses drop it, and the eviction is named too.
	for i := 0; i < 2; i++ {
		if err := r.Refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	report, _ = r.LastBuild()
	if len(report.Evicted) != 1 || report.Evicted[0] != "vanishing" {
		t.Errorf("Evicted = %v, want [vanishing] named when it is finally dropped", report.Evicted)
	}
	if report.Held != 1 {
		t.Errorf("report says %d held after the eviction, want 1", report.Held)
	}
}

// Persistence must carry every account, not just the ones that currently
// win a GECOS lookup: a snapshot that dropped the ambiguous ones would
// restore an index that has forgotten why it refuses them.
func TestSnapshotRoundTripsEveryAccountThroughJSON(t *testing.T) {
	accounts := []Account{
		{Username: "bbockelm", Gecos: "bockelman"},
		{Username: "twin-a", Gecos: "shared"},
		{Username: "twin-b", Gecos: "shared"},
		{Username: "blank", Gecos: ""},
	}
	r := New(&fakeEnum{accounts: accounts}, gecosOfAll(accounts))
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	snap, ok := r.Snapshot()
	if !ok {
		t.Fatal("no snapshot")
	}

	blob, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Snapshot
	if err := json.Unmarshal(blob, &decoded); err != nil {
		t.Fatal(err)
	}

	// A fresh process whose directory is unreadable, so only the restored
	// index can answer.
	restored := New(&fakeEnum{err: unreachableDirectory()}, gecosOfAll(accounts))
	restored.Restore(decoded)

	if held, amb, _ := restored.Stats(); held != 4 || amb != 1 {
		t.Errorf("restored index holds %d accounts with %d ambiguous, want 4 and 1", held, amb)
	}
	if got, err := restored.Resolve(context.Background(), "bockelman"); err != nil || got != "bbockelm" {
		t.Errorf("Resolve = %q, %v after a JSON round trip", got, err)
	}
	if got, err := restored.Resolve(context.Background(), "shared"); !errors.Is(err, ErrAmbiguous) {
		t.Errorf("Resolve(shared) = %q, %v; the restored index forgot the duplicate", got, err)
	}
}

// A row written before the index carried its accounts explicitly must
// still restore. A rollback or an old cache row should cost a worse
// index, not a daemon that cannot start.
func TestALegacySnapshotWithoutEntriesStillRestores(t *testing.T) {
	legacy := Snapshot{
		ByGecos:       map[string]string{"bockelman": "bbockelm"},
		Counts:        map[string]int{"bockelman": 1},
		Users:         []string{"bbockelm", "daemon"},
		Count:         2,
		BuiltAt:       time.Now(),
		FromDirectory: true,
	}
	r := New(&fakeEnum{err: unreachableDirectory()},
		&fakeVerifier{gecos: map[string]string{"bbockelm": "bockelman", "daemon": ""}})
	r.Restore(legacy)

	if got, err := r.Resolve(context.Background(), "bockelman"); err != nil || got != "bbockelm" {
		t.Errorf("Resolve = %q, %v; a pre-existing cache row stopped working", got, err)
	}
	if held, _, _ := r.Stats(); held != 2 {
		t.Errorf("restored %d accounts from a legacy row, want 2", held)
	}
}

// A restart is the WORST moment to be halfway to evicting somebody: the
// enumerations right after one are the least complete there are. So a
// restored entry starts over with its full budget, and the counters are
// not carried in the snapshot at all.
func TestARestoredEntryGetsAFullAbsenceBudgetAgain(t *testing.T) {
	accounts := []Account{
		{Username: "present", Gecos: "present"},
		{Username: "missing", Gecos: "missing"},
	}
	enum := &fakeEnum{accounts: accounts}
	r := New(enum, gecosOfAll(accounts))
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Two enumerations in a row miss it: one more would evict.
	enum.accounts = accounts[:1]
	for i := 0; i < 2; i++ {
		if err := r.Refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	snap, ok := r.Snapshot()
	if !ok {
		t.Fatal("no snapshot")
	}

	// The process restarts and restores that index, and its first
	// enumeration is another short one.
	next := &fakeEnum{accounts: accounts[:1]}
	restarted := New(next, gecosOfAll(accounts))
	restarted.Restore(snap)
	if err := restarted.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	if !indexKnows(restarted, "missing") {
		t.Error("the restored entry was evicted by a single short enumeration; " +
			"a restart must not inherit progress towards forgetting somebody")
	}
}
