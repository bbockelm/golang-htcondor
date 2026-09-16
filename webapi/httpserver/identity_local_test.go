package httpserver

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/idmap"
)

// The real shape of the problem: the account is "tannenba" and the token
// calls the same person "tatannen".
// conventional "x" placeholder meaning "see shadow(5)", not a secret.
//
//nolint:gosec // G101: passwd(5) fixtures. The second field is the
const testPasswd = `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1::/usr/sbin:/usr/sbin/nologin
tannenba:x:20013:20013:tatannen:/home/tannenba:/bin/bash
bbockelm:x:20014:20014:brian.bockelman.1:/home/bbockelm:/bin/bash
twin-a:x:20015:20015:shared.identity:/home/a:/bin/bash
twin-b:x:20016:20016:shared.identity:/home/b:/bin/bash
`

func writePasswd(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(path, []byte(testPasswd), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLocalIdentityResolvesSubjectToAccount(t *testing.T) {
	li := newLocalIdentity([]idmap.Strategy{idmap.StrategyGecos}, writePasswd(t), time.Minute, testLogger(t))
	// Groups come from the running system, which knows nothing about
	// these invented accounts, so exercise the resolver half directly.
	account, err := li.resolver.Resolve(t.Context(), "tatannen")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if account != "tannenba" {
		t.Errorf("resolved to %q, want tannenba", account)
	}
}

// The whole point of the feature: a caller whose token names them
// "tannenba" is NOT the tannenba account. Only the GECOS maps.
func TestLocalIdentityRejectsALoginNameAsSubject(t *testing.T) {
	li := newLocalIdentity([]idmap.Strategy{idmap.StrategyGecos}, writePasswd(t), time.Minute, testLogger(t))

	if _, err := li.resolver.Resolve(t.Context(), "tannenba"); err == nil {
		t.Fatal("a login name was accepted as a subject")
	}
}

func TestLocalIdentityRefusesAmbiguity(t *testing.T) {
	li := newLocalIdentity([]idmap.Strategy{idmap.StrategyGecos}, writePasswd(t), time.Minute, testLogger(t))

	_, err := li.resolver.Resolve(t.Context(), "shared.identity")
	if err == nil {
		t.Fatal("a subject claimed by two accounts resolved to one of them")
	}
	if msg := describeFailure(err); !strings.Contains(msg, "more than one") {
		t.Errorf("the user-facing message does not explain the ambiguity: %q", msg)
	}
}

// The messages a user sees must not enumerate the account database, and
// must distinguish "you are unknown here" from "we could not look".
func TestDescribeFailureSaysTheRightThing(t *testing.T) {
	if got := describeFailure(idmap.ErrNoMatch); !strings.Contains(got, "does not correspond") {
		t.Errorf("no-match message = %q", got)
	}
	if got := describeFailure(idmap.ErrAmbiguous); !strings.Contains(got, "more than one") {
		t.Errorf("ambiguous message = %q", got)
	}
	// Anything else is an outage, and should invite a retry rather than
	// telling the user they do not exist.
	other := describeFailure(context.DeadlineExceeded)
	if !strings.Contains(other, "try again") {
		t.Errorf("outage message = %q, want a retry hint", other)
	}
	for _, msg := range []string{
		describeFailure(idmap.ErrNoMatch),
		describeFailure(idmap.ErrAmbiguous),
		describeFailure(context.DeadlineExceeded),
	} {
		for _, leak := range []string{"tannenba", "bbockelm", "/etc/passwd", "getent"} {
			if strings.Contains(msg, leak) {
				t.Errorf("message %q leaks %q", msg, leak)
			}
		}
	}
}

// An unreadable account database must refuse logins, not admit everyone
// with an empty group list -- which would read as a permissions decision.
func TestLocalIdentityFailsClosedWhenTheDatabaseIsUnreadable(t *testing.T) {
	li := newLocalIdentity([]idmap.Strategy{idmap.StrategyGecos}, filepath.Join(t.TempDir(), "does-not-exist"), time.Minute, testLogger(t))

	account, groups, err := li.resolve(t.Context(), "tatannen")
	if err == nil {
		t.Fatalf("resolved %q with groups %v while the database was unreadable", account, groups)
	}
	if account != "" || groups != nil {
		t.Errorf("returned identity alongside the error: %q %v", account, groups)
	}
}

// warmUp must not panic on a broken database, and must leave the mapper
// refusing rather than permitting.
func TestWarmUpSurvivesAnUnreadableDatabase(t *testing.T) {
	li := newLocalIdentity([]idmap.Strategy{idmap.StrategyGecos}, filepath.Join(t.TempDir(), "nope"), time.Minute, testLogger(t))
	li.warmUp(t.Context())

	if _, _, err := li.resolve(t.Context(), "tatannen"); err == nil {
		t.Error("a mapper that failed to warm up is admitting callers")
	}
}

func TestWarmUpReportsAmbiguousAccounts(t *testing.T) {
	li := newLocalIdentity([]idmap.Strategy{idmap.StrategyGecos}, writePasswd(t), time.Minute, testLogger(t))
	li.warmUp(t.Context())

	amb := li.resolver.AmbiguousGecos()
	if len(amb) != 1 || amb[0] != "shared.identity" {
		t.Errorf("AmbiguousGecos() = %v, want [shared.identity] so an operator can fix it", amb)
	}
}

// The configuration this was built for: most accounts carry their own
// name in GECOS, a few do not, and one is a different string entirely.
func TestLocalIdentityGecosThenUsername(t *testing.T) {
	li := newLocalIdentity(
		[]idmap.Strategy{idmap.StrategyGecos, idmap.StrategyUsername},
		writePasswd(t), time.Minute, testLogger(t))

	for subject, want := range map[string]string{
		"tatannen":          "tannenba", // GECOS differs from the name
		"brian.bockelman.1": "bbockelm", // likewise
		"daemon":            "daemon",   // no GECOS, resolved by login name
	} {
		got, err := li.resolver.Resolve(t.Context(), subject)
		if err != nil {
			t.Errorf("Resolve(%q): %v", subject, err)
			continue
		}
		if got != want {
			t.Errorf("Resolve(%q) = %q, want %q", subject, got, want)
		}
	}

	// Ambiguity still refuses, rather than falling through to a login name.
	if _, err := li.resolver.Resolve(t.Context(), "shared.identity"); err == nil {
		t.Error("a contested GECOS fell through to the login-name strategy")
	}
}
