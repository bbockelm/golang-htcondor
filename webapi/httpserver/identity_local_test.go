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
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
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
	li := newLocalIdentity([]idmap.Strategy{idmap.StrategyGecos}, false, writePasswd(t), time.Minute, nil, testLogger(t))
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
	li := newLocalIdentity([]idmap.Strategy{idmap.StrategyGecos}, false, writePasswd(t), time.Minute, nil, testLogger(t))

	if _, err := li.resolver.Resolve(t.Context(), "tannenba"); err == nil {
		t.Fatal("a login name was accepted as a subject")
	}
}

func TestLocalIdentityRefusesAmbiguity(t *testing.T) {
	li := newLocalIdentity([]idmap.Strategy{idmap.StrategyGecos}, false, writePasswd(t), time.Minute, nil, testLogger(t))

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
	li := newLocalIdentity([]idmap.Strategy{idmap.StrategyGecos}, false, filepath.Join(t.TempDir(), "does-not-exist"), time.Minute, nil, testLogger(t))

	account, groups, err := li.resolve(t.Context(), "tatannen", nil)
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
	li := newLocalIdentity([]idmap.Strategy{idmap.StrategyGecos}, false, filepath.Join(t.TempDir(), "nope"), time.Minute, nil, testLogger(t))
	li.warmUp(t.Context())

	if _, _, err := li.resolve(t.Context(), "tatannen", nil); err == nil {
		t.Error("a mapper that failed to warm up is admitting callers")
	}
}

func TestWarmUpReportsAmbiguousAccounts(t *testing.T) {
	li := newLocalIdentity([]idmap.Strategy{idmap.StrategyGecos}, false, writePasswd(t), time.Minute, nil, testLogger(t))
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
		[]idmap.Strategy{idmap.StrategyGecos, idmap.StrategyUsername}, false,
		writePasswd(t), time.Minute, nil, testLogger(t))

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

// The two halves are independent. A container keeps the token's groups
// and does not translate the subject at all -- which must stay the
// default, since there is no account database in there to read.
func TestLocalIdentityHalvesAreIndependent(t *testing.T) {
	logger := testLogger(t)
	passwd := writePasswd(t)

	if li := newLocalIdentity(nil, false, passwd, time.Minute, nil, logger); li != nil {
		t.Error("neither half configured should yield no mapper at all")
	}

	// Subject mapping only: groups stay whatever the token said.
	mapOnly := newLocalIdentity([]idmap.Strategy{idmap.StrategyGecos}, false, passwd, time.Minute, nil, logger)
	if !mapOnly.mapsAccount() || mapOnly.sourcesGroups() {
		t.Fatalf("map-only: maps=%v groups=%v", mapOnly.mapsAccount(), mapOnly.sourcesGroups())
	}
	tokenGroups := []string{"from-the-token"}
	account, groups, err := mapOnly.resolve(t.Context(), "tatannen", tokenGroups)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if account != "tannenba" {
		t.Errorf("account = %q, want tannenba", account)
	}
	if !reflect.DeepEqual(groups, tokenGroups) {
		t.Errorf("groups = %v, want the token's claim %v untouched", groups, tokenGroups)
	}

	// Groups only: the subject is passed through unchanged, because it
	// is already expected to be a login name.
	groupsOnly := newLocalIdentity(nil, true, passwd, time.Minute, nil, logger)
	if groupsOnly.mapsAccount() || !groupsOnly.sourcesGroups() {
		t.Fatalf("groups-only: maps=%v groups=%v", groupsOnly.mapsAccount(), groupsOnly.sourcesGroups())
	}
	// warmUp must not touch an index that was never built.
	groupsOnly.warmUp(t.Context())
}

// With groups sourced from the system, a token claim must not leak
// through even when the lookup fails: that would be the weaker basis
// engaging exactly when the stronger one broke.
func TestSystemGroupsNeverFallBackToTheToken(t *testing.T) {
	li := newLocalIdentity(nil, true, writePasswd(t), time.Minute, nil, testLogger(t))

	_, groups, err := li.resolve(t.Context(), "no-such-account-anywhere", []string{"admin"})
	if err == nil {
		t.Fatalf("a failed system lookup returned groups %v", groups)
	}
	if groups != nil {
		t.Errorf("groups %v returned alongside the error", groups)
	}
}

// The SSO callback is not the only way an outside party names a user. A
// trusted proxy header and an RFC 8693 external subject token both do,
// and both must be mapped -- otherwise turning identity mapping on
// leaves a second, unmapped route to a session, which is the hole the
// feature exists to close.
func TestAssertedIdentitiesFromOtherPathsAreMappedToo(t *testing.T) {
	h := &Handler{
		localIdentity: newLocalIdentity(
			[]idmap.Strategy{idmap.StrategyGecos}, false,
			writePasswd(t), time.Minute, nil, testLogger(t)),
	}

	// The asserted name is a subject, and must come back as the account.
	got, _, err := h.mapAssertedIdentity(t.Context(), "tatannen", []string{"asserted-group"})
	if err != nil {
		t.Fatalf("mapAssertedIdentity: %v", err)
	}
	if got != "tannenba" {
		t.Errorf("asserted %q resolved to %q, want the local account tannenba", "tatannen", got)
	}

	// An assertion naming nobody local must not yield an identity at all.
	if got, _, err := h.mapAssertedIdentity(t.Context(), "nobody.local", nil); err == nil {
		t.Errorf("an unmappable assertion produced the identity %q", got)
	}

	// A login name is still not a subject under the gecos strategy.
	if got, _, err := h.mapAssertedIdentity(t.Context(), "tannenba", nil); err == nil {
		t.Errorf("a login name was accepted as an assertion, yielding %q", got)
	}
}

// With no local identity configured -- the default, and what a container
// runs -- assertions pass through untouched.
func TestAssertedIdentityIsUntouchedWhenMappingIsOff(t *testing.T) {
	h := &Handler{}
	groups := []string{"from-the-token"}

	got, gotGroups, err := h.mapAssertedIdentity(t.Context(), "someone", groups)
	if err != nil {
		t.Fatalf("mapAssertedIdentity: %v", err)
	}
	if got != "someone" || !reflect.DeepEqual(gotGroups, groups) {
		t.Errorf("mapping is off, so %q/%v should pass through; got %q/%v", "someone", groups, got, gotGroups)
	}
}

// recordingGroups remembers which account it was asked about.
type recordingGroups struct {
	mu     sync.Mutex
	asked  []string
	byUser map[string][]string
}

func (r *recordingGroups) Name() string { return "recording" }
func (r *recordingGroups) LookupGroups(_ context.Context, username string) ([]string, error) {
	r.mu.Lock()
	r.asked = append(r.asked, username)
	r.mu.Unlock()
	g, ok := r.byUser[username]
	if !ok {
		return nil, fmt.Errorf("no such user %q", username)
	}
	return g, nil
}

// Groups must be read for the MAPPED ACCOUNT, not for the subject the
// provider asserted and not for any other account.
//
// Nothing pinned this before: the e2e only checked that the required
// access group was satisfied, and the group it used happened to be one
// almost every account on the host belongs to -- so reading root's
// groups, or the raw subject's, passed just as well. That is the
// difference between "this caller is in the right groups" and "this
// caller's groups are the ones we read".
func TestGroupsAreReadForTheMappedAccountOnly(t *testing.T) {
	rec := &recordingGroups{byUser: map[string][]string{
		"tannenba": {"osg"},
		"root":     {"wheel"},
		"tatannen": {"decoy"},
	}}
	li := newLocalIdentity([]idmap.Strategy{idmap.StrategyGecos}, true,
		writePasswd(t), time.Minute, nil, testLogger(t))
	li.groups = rec // the resolver is real; only the group source is a stub

	account, groups, err := li.resolve(t.Context(), "tatannen", []string{"token-group"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if account != "tannenba" {
		t.Fatalf("account = %q, want tannenba", account)
	}

	rec.mu.Lock()
	asked := append([]string(nil), rec.asked...)
	rec.mu.Unlock()

	if len(asked) != 1 || asked[0] != "tannenba" {
		t.Errorf("groups were read for %v; they must be read for the mapped account %q alone",
			asked, "tannenba")
	}
	if !reflect.DeepEqual(groups, []string{"osg"}) {
		t.Errorf("groups = %v, want tannenba's [osg] -- not the subject's or root's", groups)
	}
	for _, wrong := range []string{"tatannen", "root"} {
		for _, a := range asked {
			if a == wrong {
				t.Errorf("groups were read for %q, which is not the mapped account", wrong)
			}
		}
	}
}
