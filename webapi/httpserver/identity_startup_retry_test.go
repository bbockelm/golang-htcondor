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
		if got >= n {
			return got
		}
		if time.Now().After(deadline) {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The cold-start case, which is the normal case in a container: the
// daemon and its SSSD sidecar start together, so the first index is built
// against an account database that is not answering yet. Before this
// retry the daemon kept that first snapshot until the TTL expired AND
// somebody tried to log in -- so the people who arrived first were
// refused, and the log said only that the index was small.
func TestStartupIndexRetriesUntilTheAccountsAppear(t *testing.T) {
	path := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(path, []byte("root:x:0:0:root:/root:/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	li := newLocalIdentity([]idmap.Strategy{idmap.StrategyGecos}, false, path, time.Minute, false, testLogger(t))
	if li == nil {
		t.Fatal("no local identity was configured")
	}
	li.retryInterval = 5 * time.Millisecond
	li.retryWindow = 10 * time.Second
	li.warmUp(context.Background())

	if got, _, _ := li.resolver.Stats(); got != 1 {
		t.Fatalf("precondition: index holds %d accounts, want just the one in the file", got)
	}

	// The database "comes up" -- as SSSD does once its first enumeration
	// pass over the directory finishes.
	body := "root:x:0:0:root:/root:/bin/sh\n" +
		"bbockelm:x:20014:20014:bockelman:/home/bbockelm:/bin/sh\n" +
		"tannenba:x:20013:20013:tatannen:/home/tannenba:/bin/sh\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	// Nothing calls Resolve here: the point is that the daemon recovers on
	// its own, before the first login rather than because of it.
	if got := waitForIndex(t, li, 3, 5*time.Second); got < 3 {
		t.Fatalf("index still holds %d accounts; the startup retry never picked up the rest", got)
	}

	// And the recovered index is actually usable for a mapping.
	account, err := li.resolver.Resolve(context.Background(), "bockelman")
	if err != nil || account != "bbockelm" {
		t.Errorf("Resolve(bockelman) = %q, %v; want bbockelm", account, err)
	}
}

// The retry must not run forever: once the window closes the ordinary TTL
// takes over, so a long-lived process is not re-enumerating a large
// directory on a timer for the rest of its life.
func TestStartupIndexRetryStopsAtTheWindow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(path, []byte("root:x:0:0:root:/root:/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	li := newLocalIdentity([]idmap.Strategy{idmap.StrategyGecos}, false, path, time.Minute, false, testLogger(t))
	li.retryInterval = time.Millisecond
	li.retryWindow = 20 * time.Millisecond
	li.warmUp(context.Background())

	// Well after the window has closed, a database that grows is NOT
	// picked up any more -- the TTL owns refreshes from here.
	time.Sleep(200 * time.Millisecond)
	body := "root:x:0:0:root:/root:/bin/sh\n" +
		"bbockelm:x:20014:20014:bockelman:/home/bbockelm:/bin/sh\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := waitForIndex(t, li, 2, 100*time.Millisecond); got != 1 {
		t.Errorf("index grew to %d after the retry window closed; the loop is still running", got)
	}
}
