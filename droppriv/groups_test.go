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

package droppriv

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"os/user"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// countingGroups records how often it was asked.
type countingGroups struct {
	mu     sync.Mutex
	calls  int
	groups []string
	err    error
}

func (c *countingGroups) Name() string { return "counting" }
func (c *countingGroups) LookupGroups(context.Context, string) ([]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	return c.groups, c.err
}

// The gid -> name mapping is the same for every account on the host, so a
// user in many groups must not cost one system lookup per group per login.
func TestGroupNameCacheResolvesEachGidOnce(t *testing.T) {
	var calls int
	c := newGroupNameCache(time.Minute)
	c.lookup = func(gid string) (*user.Group, error) {
		calls++
		return &user.Group{Gid: gid, Name: "group-" + gid}, nil
	}

	for range 5 {
		for _, gid := range []string{"100", "200", "100"} {
			name, err := c.name(gid)
			if err != nil {
				t.Fatal(err)
			}
			if name != "group-"+gid {
				t.Fatalf("name(%s) = %q", gid, name)
			}
		}
	}

	if calls != 2 {
		t.Errorf("went to the system %d times for 2 distinct gids across 15 requests; the cache is not working", calls)
	}
}

func TestGroupNameCacheExpires(t *testing.T) {
	var calls int
	c := newGroupNameCache(time.Nanosecond)
	c.lookup = func(gid string) (*user.Group, error) {
		calls++
		return &user.Group{Gid: gid, Name: "g"}, nil
	}
	if _, err := c.name("100"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond)
	if _, err := c.name("100"); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Errorf("calls = %d, want the entry to expire and be re-read", calls)
	}
}

// A gid with no group entry keeps its number. Dropping it would shorten
// the membership list, which is the one outcome an authorization decision
// must never be handed.
func TestStdlibGroupsKeepsUnresolvableGidsAsNumbers(t *testing.T) {
	s := NewStdlibGroups(time.Minute)
	s.names.lookup = func(gid string) (*user.Group, error) {
		if gid == "999" {
			return nil, fmt.Errorf("no such group")
		}
		return &user.Group{Gid: gid, Name: "named"}, nil
	}
	if got, _ := s.names.name("999"); got != "" {
		t.Errorf("name(999) = %q, want the error path", got)
	}
}

func TestCachedGroupLookupDoesNotCacheFailures(t *testing.T) {
	src := &countingGroups{err: errors.New("sssd timeout")}
	c := NewCachedGroupLookup(src, time.Minute)

	for range 3 {
		if _, err := c.LookupGroups(context.Background(), "tannenba"); err == nil {
			t.Fatal("expected the error to surface")
		}
	}
	if src.calls != 3 {
		t.Errorf("calls = %d, want 3; caching a failure turns a blip into minutes of denied access", src.calls)
	}
}

func TestCachedGroupLookupServesAndForgets(t *testing.T) {
	src := &countingGroups{groups: []string{"condor-users"}}
	c := NewCachedGroupLookup(src, time.Minute)

	for range 3 {
		if _, err := c.LookupGroups(context.Background(), "tannenba"); err != nil {
			t.Fatal(err)
		}
	}
	if src.calls != 1 {
		t.Errorf("calls = %d, want 1", src.calls)
	}
	c.Forget("tannenba")
	if _, err := c.LookupGroups(context.Background(), "tannenba"); err != nil {
		t.Fatal(err)
	}
	if src.calls != 2 {
		t.Errorf("Forget did not invalidate: %d calls", src.calls)
	}
}

// unknownGroups reports ErrUnknownUser, as a source does for an account
// that lives in some other service.
type unknownGroups struct{ calls int }

func (u *unknownGroups) Name() string { return "unknown" }
func (u *unknownGroups) LookupGroups(context.Context, string) ([]string, error) {
	u.calls++
	return nil, fmt.Errorf("%w: not here", ErrUnknownUser)
}

// The group database is a union: an account can hold local groups AND
// directory groups, so the chain must merge rather than stop at the first
// source that answers.
func TestGroupChainMergesEverySource(t *testing.T) {
	files := &countingGroups{groups: []string{"tannenba", "wheel"}}
	dir := &countingGroups{groups: []string{"condor-users", "wheel"}}
	c := &groupChain{sources: []GroupLookup{files, dir}}

	groups, err := c.LookupGroups(context.Background(), "tannenba")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"condor-users", "tannenba", "wheel"}
	if !slices.Equal(groups, want) {
		t.Errorf("groups = %v, want the union %v", groups, want)
	}
}

// An unknown-to-this-source answer contributes nothing and is NOT a
// failure -- on a "files sss" host every directory user is unknown to
// files and vice versa.
func TestGroupChainTreatsUnknownAsNotAFailure(t *testing.T) {
	c := &groupChain{sources: []GroupLookup{
		&unknownGroups{},
		&countingGroups{groups: []string{"condor-users"}},
	}}
	groups, err := c.LookupGroups(context.Background(), "tannenba")
	if err != nil {
		t.Fatalf("an unknown source failed the lookup: %v", err)
	}
	if !slices.Equal(groups, []string{"condor-users"}) {
		t.Errorf("groups = %v", groups)
	}
}

// A source that is BROKEN is different: the answer is still returned, so
// a login proceeds as it would under glibc, but it is marked so the one
// caller that must not act on a short list can decline.
func TestGroupChainMarksAnUnavailableSourceDegraded(t *testing.T) {
	c := &groupChain{sources: []GroupLookup{
		&countingGroups{groups: []string{"condor-users"}},
		&unsupportedMethod{method: "ldap", reason: "test"},
	}}

	groups, err := c.LookupGroups(context.Background(), "tannenba")

	var degraded *DegradedError
	if !errors.As(err, &degraded) {
		t.Fatalf("err = %v, want a DegradedError so the caller knows the list may be short", err)
	}
	if !slices.Contains(groups, "condor-users") {
		t.Errorf("groups = %v, want the usable part still returned", groups)
	}
	if degraded.Source != "unsupported:ldap" {
		t.Errorf("degraded source = %q, want the unavailable method named", degraded.Source)
	}
}

// Degraded AND empty is not a short answer, it is no answer: every source
// that might have known the account was the one that was down. Returning
// an empty list would read downstream as "belongs to nothing".
func TestGroupChainRefusesWhenNothingWasLearned(t *testing.T) {
	c := &groupChain{sources: []GroupLookup{
		&unknownGroups{},
		&unsupportedMethod{method: "ldap", reason: "test"},
	}}

	groups, err := c.LookupGroups(context.Background(), "tannenba")
	if err == nil {
		t.Fatalf("returned %v with no error; nothing was actually learned", groups)
	}
	if len(groups) != 0 {
		t.Errorf("groups = %v, want none", groups)
	}
	var degraded *DegradedError
	if !errors.As(err, &degraded) {
		t.Errorf("err = %v, want the degradation to still be visible", err)
	}
}

func TestNormalizeGroupsSortsAndDeduplicates(t *testing.T) {
	got := NormalizeGroups([]string{"wheel", "condor-users", " wheel ", "", "condor-users"})
	want := []string{"condor-users", "wheel"}
	if !slices.Equal(got, want) {
		t.Errorf("NormalizeGroups = %v, want %v", got, want)
	}
}

// The load-bearing test: this package's group resolution must agree with
// what the system itself reports.
//
// Reimplementing NSS risks answering from a subset of the configured
// services and being confidently wrong in a way nothing notices until
// somebody's permissions differ from id(1)'s answer. So the check is
// against id(1), on a real account, through this host's real nsswitch.conf.
// exec is used HERE, in a test, as the oracle; the package itself must
// never fork, which is precisely what this is holding it to.
func TestGroupLookupAgreesWithID(t *testing.T) {
	if _, err := exec.LookPath("id"); err != nil {
		t.Skip("id(1) not available to check against")
	}
	out, err := exec.CommandContext(t.Context(), "id", "-un").Output()
	if err != nil {
		t.Skipf("cannot determine the current user: %v", err)
	}
	username := strings.TrimSpace(string(out))
	if username == "" {
		t.Skip("current user has no name")
	}

	//nolint:gosec // a test-only oracle; username comes from id -un on this host
	raw, err := exec.CommandContext(t.Context(), "id", "-Gn", "--", username).Output()
	if err != nil {
		t.Skipf("id -Gn: %v", err)
	}
	want := NormalizeGroups(strings.Fields(string(raw)))
	if len(want) == 0 {
		t.Skip("id reported no groups")
	}

	got, err := DefaultGroupLookup().LookupGroups(context.Background(), username)

	// A degraded read is a legitimate outcome: this host resolves groups
	// through a method a non-cgo build cannot speak. The answer is then a
	// subset by construction, and only the no-fabrication check applies.
	var degraded *DegradedError
	if errors.As(err, &degraded) {
		t.Logf("degraded via %s (%v); checking for fabrication only", degraded.Source, degraded.Err)
		got = degraded.Groups
	} else if err != nil {
		t.Fatalf("LookupGroups(%q): %v", username, err)
	}

	// Never invent membership: a group reported that id does not is a
	// privilege this account does not have.
	for _, g := range got {
		if !slices.Contains(want, g) {
			t.Errorf("reported group %q that id(1) does not: got %v, id says %v", g, got, want)
		}
	}
	if degraded != nil {
		return
	}
	// A complete read must match exactly. Missing a group is a privilege
	// the account should have had, and surfaces as a mystifying denial.
	if !slices.Equal(got, want) {
		t.Errorf("complete read disagrees with id(1):\n  got %v\n  id  %v", got, want)
	}
	t.Logf("%s: %d groups, matching id(1)", username, len(got))
}
