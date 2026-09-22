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
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/idmap"
	"github.com/bbockelm/golang-htcondor/logging"
)

// fileLogger writes to a file the test can read back, which is the only
// way to assert on a log line.
func fileLogger(t *testing.T) (*logging.Logger, func() string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "server.log")
	logger, err := logging.New(&logging.Config{
		OutputPath:        path,
		DefaultLevel:      logging.VerbosityInfo,
		SkipGlobalInstall: true,
	})
	if err != nil {
		t.Fatalf("creating the logger: %v", err)
	}
	return logger, func() string {
		body, err := os.ReadFile(path) //nolint:gosec // G304: a path this test just made
		if err != nil {
			t.Fatalf("reading the log: %v", err)
		}
		return string(body)
	}
}

// passwdWith writes a passwd file whose accounts all carry their own name
// as their GECOS, the shape the real directory mostly has.
func passwdWith(t *testing.T, path string, names []string) {
	t.Helper()
	var b strings.Builder
	for i, name := range names {
		fmt.Fprintf(&b, "%s:x:%d:%d:%s:/home/%s:/bin/bash\n", name, 30000+i, 30000+i, name, name)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A partial enumeration no longer evicts anybody, which makes it silent
// -- and a silent partial enumeration is how this took a day to diagnose.
// The names it did not list have to reach the log.
func TestAShortEnumerationIsReportedWithTheAccountsItMissed(t *testing.T) {
	logger, readLog := fileLogger(t)
	path := filepath.Join(t.TempDir(), "passwd")

	all := []string{"clock", "bbockelm", "tannenba", "matyas"}
	passwdWith(t, path, all)

	li := newLocalIdentity([]idmap.Strategy{idmap.StrategyGecos}, nil, path, time.Minute, false, logger)
	if err := li.resolver.Refresh(t.Context()); err != nil {
		t.Fatalf("building the index: %v", err)
	}

	// The directory answers short: only one account this time.
	passwdWith(t, path, all[:1])
	if err := li.resolver.Refresh(t.Context()); err != nil {
		t.Fatalf("the short rebuild failed: %v", err)
	}
	li.logRetention()

	log := readLog()
	for _, missing := range all[1:] {
		if !strings.Contains(log, missing) {
			t.Errorf("the log does not name %q, which the enumeration stopped listing:\n%s", missing, log)
		}
	}
	if !strings.Contains(log, "did not list accounts the index already held") {
		t.Errorf("no warning about the short enumeration:\n%s", log)
	}
	// The count, not only the names: an operator scanning the line needs
	// the magnitude before they need the identities.
	if !strings.Contains(log, "missing_now") {
		t.Errorf("the warning does not count what went missing:\n%s", log)
	}
}

// A complete enumeration is not news. This runs on the refresh cadence
// for the life of the process, so a line every time would bury the one
// that matters.
func TestACompleteEnumerationLogsNothing(t *testing.T) {
	logger, readLog := fileLogger(t)
	path := filepath.Join(t.TempDir(), "passwd")
	passwdWith(t, path, []string{"clock", "bbockelm"})

	li := newLocalIdentity([]idmap.Strategy{idmap.StrategyGecos}, nil, path, time.Minute, false, logger)
	for i := 0; i < 3; i++ {
		if err := li.resolver.Refresh(t.Context()); err != nil {
			t.Fatal(err)
		}
		li.logRetention()
	}

	if log := readLog(); strings.Contains(log, "did not list accounts") {
		t.Errorf("a steady index produced a retention warning:\n%s", log)
	}
}

// The list can be the whole directory. Naming 4000 accounts in one line
// means nobody reads any of them, so it is capped -- but the count is
// not, because the count is the part that says how bad it is.
func TestTheMissingAccountListIsCappedButTheCountIsNot(t *testing.T) {
	logger, readLog := fileLogger(t)
	path := filepath.Join(t.TempDir(), "passwd")

	names := make([]string, 0, 300)
	for i := 0; i < 300; i++ {
		names = append(names, fmt.Sprintf("user%03d", i))
	}
	passwdWith(t, path, names)

	li := newLocalIdentity([]idmap.Strategy{idmap.StrategyGecos}, nil, path, time.Minute, false, logger)
	if err := li.resolver.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	passwdWith(t, path, names[:1])
	if err := li.resolver.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	li.logRetention()

	log := readLog()
	named := 0
	for _, name := range names {
		if strings.Contains(log, name+"\"") || strings.Contains(log, name+",") {
			named++
		}
	}
	if named > 64 {
		t.Errorf("the log named %d accounts; the list must be capped", named)
	}
	if !strings.Contains(log, strconv.Itoa(len(names)-1)) {
		t.Errorf("the log does not report how many accounts went missing (%d):\n%s", len(names)-1, log)
	}
	if !strings.Contains(log, "and ") || !strings.Contains(log, "more") {
		t.Errorf("the truncated list does not say that it was truncated:\n%s", log)
	}
}
