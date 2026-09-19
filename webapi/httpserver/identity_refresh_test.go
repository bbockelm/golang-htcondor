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

// waitForIndex polls until the index holds at least n accounts.
func waitForIndex(t *testing.T, li *localIdentity, n int, within time.Duration) int {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		got, _, _ := li.resolver.Stats()
		if got >= n || time.Now().After(deadline) {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func identityOverFile(t *testing.T, path string, every time.Duration) *localIdentity {
	t.Helper()
	li := newLocalIdentity([]idmap.Strategy{idmap.StrategyGecos}, nil, path, time.Minute, false, testLogger(t))
	if li == nil {
		t.Fatal("no local identity was configured")
	}
	li.refreshEvery = every
	return li
}

const onePasswdEntry = "root:x:0:0:root:/root:/bin/sh\n" //nolint:gosec // a passwd(5) fixture line; the "x" means the hash lives in shadow(5)

// The index must come back on its own, not because somebody happened to
// log in after the TTL. In a container the first index is built before the
// SSSD sidecar answers, so the startup snapshot is normally the wrong one
// and nothing else would correct it.
func TestTheIndexRefreshesWithoutALogin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(path, []byte(onePasswdEntry), 0o600); err != nil {
		t.Fatal(err)
	}

	li := identityOverFile(t, path, 5*time.Millisecond)
	li.warmUp(context.Background())

	if got, _, _ := li.resolver.Stats(); got != 1 {
		t.Fatalf("precondition: index holds %d accounts, want the one in the file", got)
	}

	// The account database becomes readable, as SSSD does once its first
	// enumeration pass finishes.
	body := onePasswdEntry +
		"bbockelm:x:20014:20014:bockelman:/home/bbockelm:/bin/sh\n" +
		"tannenba:x:20013:20013:tatannen:/home/tannenba:/bin/sh\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	// Nothing calls Resolve: the daemon has to notice by itself.
	if got := waitForIndex(t, li, 3, 5*time.Second); got < 3 {
		t.Fatalf("index still holds %d accounts; it never refreshed", got)
	}

	account, err := li.resolver.Resolve(context.Background(), "bockelman")
	if err != nil || account != "bbockelm" {
		t.Errorf("Resolve(bockelman) = %q, %v; want bbockelm", account, err)
	}
}

// A refresh that fails must not empty the index. Serving a stale mapping
// beats refusing every login because the database was briefly unreadable.
func TestAFailedRefreshKeepsThePreviousIndex(t *testing.T) {
	path := filepath.Join(t.TempDir(), "passwd")
	body := onePasswdEntry + "bbockelm:x:20014:20014:bockelman:/home/bbockelm:/bin/sh\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	li := identityOverFile(t, path, 5*time.Millisecond)
	li.warmUp(context.Background())
	if got, _, _ := li.resolver.Stats(); got != 2 {
		t.Fatalf("precondition: index holds %d accounts, want 2", got)
	}

	// The database goes away entirely.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	// Give the loop several ticks to fail on it.
	time.Sleep(100 * time.Millisecond)

	if got, _, _ := li.resolver.Stats(); got != 2 {
		t.Errorf("index holds %d accounts after failed refreshes; the working one was discarded", got)
	}

	// Resolution is NOT asserted here. Every hit is forward-verified
	// against the live database before it is believed, so with that
	// database gone a mapping cannot be confirmed and is refused -- which
	// is the intended trade and not a consequence of the refresh failing.
	// What this test pins is that the refresh did not blank the index.
}

// A hint is confirmed, never trusted. One that does not check out must
// fall through to the ordinary resolution rather than being taken at its
// word -- this is the wiring that makes a forged cookie inert.
func TestAnUnconfirmableHintFallsBackToTheIndex(t *testing.T) {
	path := filepath.Join(t.TempDir(), "passwd")
	body := onePasswdEntry + "bbockelm:x:20014:20014:bockelman:/home/bbockelm:/bin/sh\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	li := identityOverFile(t, path, time.Hour)
	li.warmUp(context.Background())

	// "root" exists, but its GECOS is not this subject.
	account, _, hinted, err := li.resolveWithHint(context.Background(), "bockelman", nil, "root")
	if err != nil {
		t.Fatalf("resolveWithHint: %v", err)
	}
	if hinted {
		t.Error("an unconfirmable hint was reported as used")
	}
	if account != "bbockelm" {
		t.Errorf("account = %q, want bbockelm from the index", account)
	}
}

// And a hint that does check out is used, or the mechanism buys nothing.
func TestAConfirmedHintIsUsed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "passwd")
	body := onePasswdEntry + "bbockelm:x:20014:20014:bockelman:/home/bbockelm:/bin/sh\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	li := identityOverFile(t, path, time.Hour)
	li.warmUp(context.Background())

	account, _, hinted, err := li.resolveWithHint(context.Background(), "bockelman", nil, "bbockelm")
	if err != nil {
		t.Fatalf("resolveWithHint: %v", err)
	}
	if !hinted || account != "bbockelm" {
		t.Errorf("account = %q, hinted = %v; want the hint to have been used", account, hinted)
	}
}
