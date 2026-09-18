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
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/droppriv"
	"github.com/bbockelm/golang-htcondor/idmap"
)

// stubGroups stands in for the account database.
type stubGroups struct {
	groups map[string][]string
	err    error
}

func (s *stubGroups) Name() string { return "stub" }
func (s *stubGroups) LookupGroups(_ context.Context, username string) ([]string, error) {
	if s.err != nil {
		return nil, s.err
	}
	g, ok := s.groups[username]
	if !ok {
		return nil, fmt.Errorf("no such user %q", username)
	}
	return g, nil
}

// testWriteGroup is the group this deployment's policy ties mcp:write
// to. It is a constant because nothing here needs it to vary; what the
// tests vary is a user's membership in it.
const testWriteGroup = "condor-writers"

func oracleFor(t *testing.T, src droppriv.GroupLookup, required string) *systemGroupOracle {
	t.Helper()
	return &systemGroupOracle{
		identity: &localIdentity{groups: src},
		validate: func(groups []string) error {
			if required == "" {
				return nil
			}
			for _, g := range groups {
				if g == required {
					return nil
				}
			}
			return errors.New("not a member of " + required)
		},
		scopesFor: func(groups, requested []string) []string {
			write := false
			for _, g := range groups {
				if g == testWriteGroup {
					write = true
				}
			}
			var out []string
			for _, s := range requested {
				if s == "mcp:write" && !write {
					continue
				}
				out = append(out, s)
			}
			return out
		},
		logger: testLogger(t),
	}
}

// The point of the whole exercise: membership removed after consent is
// noticed at refresh. The stored session still says otherwise.
func TestSystemGroupOracleRevokesOnLostMembership(t *testing.T) {
	src := &stubGroups{groups: map[string][]string{"tannenba": {"other"}}}
	o := oracleFor(t, src, "condor-users")

	got, err := o.Check(context.Background(), "tannenba", []string{"mcp:read"})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got.Status != UserStatusRevoked {
		t.Errorf("status = %v, want revoked once the group is gone", got.Status)
	}
	if got.Reason == "" {
		t.Error("a revocation must carry a reason for the operator log")
	}
}

// Losing write access narrows the grant rather than ending the session:
// the user keeps working read-only.
func TestSystemGroupOracleNarrowsRatherThanRevoking(t *testing.T) {
	src := &stubGroups{groups: map[string][]string{"tannenba": {"condor-users"}}}
	o := oracleFor(t, src, "condor-users")

	got, err := o.Check(context.Background(), "tannenba", []string{"mcp:read", "mcp:write"})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got.Status != UserStatusActive {
		t.Errorf("status = %v, want active", got.Status)
	}
	if !reflect.DeepEqual(got.DeniedScopes, []string{"mcp:write"}) {
		t.Errorf("denied = %v, want just mcp:write", got.DeniedScopes)
	}
}

// With no access group configured, membership cannot revoke -- there is
// no policy to fail. The oracle must still narrow scopes.
func TestSystemGroupOracleWithNoRequiredGroup(t *testing.T) {
	src := &stubGroups{groups: map[string][]string{"tannenba": {"unrelated"}}}
	o := oracleFor(t, src, "")

	got, err := o.Check(context.Background(), "tannenba", []string{"mcp:read", "mcp:write"})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got.Status != UserStatusActive {
		t.Errorf("status = %v; with no access group there is nothing to revoke on", got.Status)
	}
	if !reflect.DeepEqual(got.DeniedScopes, []string{"mcp:write"}) {
		t.Errorf("denied = %v, want mcp:write narrowed away", got.DeniedScopes)
	}
}

func TestSystemGroupOracleLeavesAnIntactGrantAlone(t *testing.T) {
	src := &stubGroups{groups: map[string][]string{
		"tannenba": {"condor-users", "condor-writers"},
	}}
	o := oracleFor(t, src, "condor-users")

	got, err := o.Check(context.Background(), "tannenba", []string{"mcp:read", "mcp:write"})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got.Status != UserStatusActive || len(got.DeniedScopes) != 0 {
		t.Errorf("an unchanged membership was disturbed: %+v", got)
	}
}

// The interface requires failing OPEN. An unreadable account database
// must read as "no opinion", never as a revocation -- otherwise an NSS
// hiccup logs out everyone whose token happens to refresh during it.
func TestSystemGroupOracleFailsOpen(t *testing.T) {
	src := &stubGroups{err: errors.New("sssd timeout")}
	o := oracleFor(t, src, "condor-users")

	got, err := o.Check(context.Background(), "tannenba", []string{"mcp:read"})
	if err == nil {
		t.Fatal("an unreadable database must surface as an error, which the caller treats as no opinion")
	}
	if got.Status == UserStatusRevoked {
		t.Errorf("status = revoked; a backend failure must never revoke")
	}
}

// An account that has vanished from the database entirely is the same
// case: an error, so the caller fails open and the lifetime cap bounds
// the exposure instead.
func TestSystemGroupOracleTreatsAMissingAccountAsNoOpinion(t *testing.T) {
	src := &stubGroups{groups: map[string][]string{}}
	o := oracleFor(t, src, "condor-users")

	got, err := o.Check(context.Background(), "ghost", []string{"mcp:read"})
	if err == nil {
		t.Fatal("a missing account should surface as an error")
	}
	if got.Status == UserStatusRevoked {
		t.Errorf("status = revoked; see the fail-open requirement")
	}
}

// The oracle must be registered when -- and only when -- groups come
// from the system.
//
// This is the whole membership-drift feature, and it had no coverage:
// setting the registration to `if false` (never register) and to
// `if true` (register even with token-sourced groups, where the oracle
// has no group source and nil-derefs on the first refresh) both passed.
// The tests constructed the oracle by hand and never built a Handler.
func TestSystemGroupOracleIsWiredExactlyWhenGroupsAreLocal(t *testing.T) {
	passwd := writePasswd(t)

	cases := []struct {
		name         string
		strategies   []idmap.Strategy
		systemGroups bool
		wantOracle   bool
	}{
		{"groups from the system", []idmap.Strategy{idmap.StrategyGecos}, true, true},
		{"groups from the system, no subject mapping", nil, true, true},
		{"subject mapped, groups from the token", []idmap.Strategy{idmap.StrategyGecos}, false, false},
		{"neither (the default, and what a container runs)", nil, false, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &Handler{logger: testLogger(t)}
			if li := newLocalIdentity(tc.strategies, tc.systemGroups, passwd, time.Minute, nil, h.logger); li != nil {
				h.localIdentity = li
			}
			h.registerSystemGroupOracle(h.logger)

			var found *systemGroupOracle
			for _, o := range h.revocationOracles {
				if sg, ok := o.(*systemGroupOracle); ok {
					found = sg
				}
			}
			if tc.wantOracle && found == nil {
				t.Fatal("membership is read locally, so refreshes must re-check it -- no oracle was registered")
			}
			if !tc.wantOracle && found != nil {
				t.Fatal("groups come from the token; there is nothing local to re-read, and the oracle would have no group source")
			}
			// A registered oracle must be usable: with no group source it
			// would nil-deref on the first refresh.
			if found != nil && found.identity.groups == nil {
				t.Error("the registered oracle has no group source and would panic on the first refresh")
			}
		})
	}
}

// degradedGroups answers, but reports that a source was unavailable.
type degradedGroups struct{ groups []string }

func (d *degradedGroups) Name() string { return "degraded" }
func (d *degradedGroups) LookupGroups(context.Context, string) ([]string, error) {
	return d.groups, &droppriv.DegradedError{
		Groups: d.groups, Source: "sssd", Err: errors.New("socket timeout"),
	}
}

// The destructive case. A degraded read is good enough to log somebody
// in -- it is what id(1) would say -- but acting on it HERE revokes a
// grant. An SSSD outage must not revoke everybody whose token happens to
// refresh during it, and a short list is indistinguishable from real
// lost membership.
func TestSystemGroupOracleWillNotRevokeOnADegradedRead(t *testing.T) {
	// The degraded list lacks the required group, so a naive reading
	// would revoke.
	o := oracleFor(t, &degradedGroups{groups: []string{"unrelated"}}, "condor-users")

	got, err := o.Check(context.Background(), "tannenba", []string{"mcp:read", "mcp:write"})
	if err == nil {
		t.Fatalf("a degraded read produced a verdict (%+v); it must be no opinion", got)
	}
	if got.Status == UserStatusRevoked {
		t.Error("REVOKED on a degraded read -- an outage would revoke every refreshing user")
	}
	if len(got.DeniedScopes) != 0 {
		t.Errorf("narrowed scopes %v on a degraded read", got.DeniedScopes)
	}
	if !strings.Contains(err.Error(), "outage") {
		t.Errorf("the error should say why it declined: %v", err)
	}
}

// A COMPLETE read that lacks the group still revokes -- otherwise the
// feature does nothing.
func TestSystemGroupOracleStillRevokesOnACompleteRead(t *testing.T) {
	o := oracleFor(t, &stubGroups{groups: map[string][]string{"tannenba": {"unrelated"}}}, "condor-users")

	got, err := o.Check(context.Background(), "tannenba", []string{"mcp:read"})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got.Status != UserStatusRevoked {
		t.Errorf("status = %v; a complete read showing lost membership must revoke", got.Status)
	}
}
