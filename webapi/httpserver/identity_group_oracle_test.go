package httpserver

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/bbockelm/golang-htcondor/idmap"
)

// stubGroups stands in for the account database.
type stubGroups struct {
	groups map[string][]string
	err    error
}

func (s *stubGroups) Name() string { return "stub" }
func (s *stubGroups) GroupsFor(_ context.Context, username string) ([]string, error) {
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

func oracleFor(t *testing.T, src idmap.GroupSource, required string) *systemGroupOracle {
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

// The oracle must only exist where there is something local to re-read.
func TestOracleRegisteredOnlyWithSystemGroups(t *testing.T) {
	logger := testLogger(t)
	passwd := writePasswd(t)

	tokenGroups := newLocalIdentity([]idmap.Strategy{idmap.StrategyGecos}, false, passwd, 0, logger)
	if tokenGroups.sourcesGroups() {
		t.Error("token-sourced groups must not report a system source")
	}
	systemGroups := newLocalIdentity(nil, true, passwd, 0, logger)
	if !systemGroups.sourcesGroups() {
		t.Error("system-sourced groups must report one")
	}
}
