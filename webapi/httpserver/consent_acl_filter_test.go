package httpserver

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/bbockelm/golang-htcondor/logging"
)

// fakeACLOracle stands in for the schedd probe.
type fakeACLOracle struct {
	denied []string
	err    error
	calls  int
}

func (f *fakeACLOracle) Name() string { return "fake-acl" }
func (f *fakeACLOracle) Check(context.Context, string, []string) (ReauthDecision, error) {
	f.calls++
	if f.err != nil {
		return ReauthDecision{}, f.err
	}
	return ReauthDecision{Status: UserStatusActive, DeniedScopes: f.denied}, nil
}

func aclTestHandler(t *testing.T, oracles ...RevocationOracle) *Handler {
	t.Helper()
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatal(err)
	}
	return &Handler{logger: logger, revocationOracles: oracles}
}

// The consistency this exists for: the refresh path already strips scopes
// the access point refuses, so the issuer must not hand them out in the
// first place. Without this a user denied WRITE could approve mcp:write,
// work until the first refresh, and silently lose it.
func TestConsentWithholdsScopesTheScheddRefuses(t *testing.T) {
	h := aclTestHandler(t)
	denier := &fakeACLOracle{denied: []string{"mcp:write", "condor:/WRITE"}}
	got := h.filterScopesByOracle(context.Background(), denier, "alice",
		[]string{"openid", "mcp:read", "mcp:write", "condor:/READ", "condor:/WRITE"})

	want := []string{"openid", "mcp:read", "condor:/READ"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("offered %v, want %v", got, want)
	}
	if denier.calls != 1 {
		t.Errorf("oracle consulted %d times, want 1", denier.calls)
	}
}

// Fails OPEN. A probe that errors must not strip anything: a schedd that
// is briefly unreachable would otherwise silently narrow what a person is
// offered, and they cannot tell that from "you may not have this".
func TestConsentOffersEverythingWhenTheProbeFails(t *testing.T) {
	h := aclTestHandler(t)
	broken := &fakeACLOracle{err: errors.New("schedd unreachable")}
	in := []string{"openid", "mcp:read", "mcp:write"}

	got := h.filterScopesByOracle(context.Background(), broken, "alice", in)
	if !reflect.DeepEqual(got, in) {
		t.Errorf("offered %v after a failed probe, want all of %v", got, in)
	}
}

// With no oracle configured the page must not probe at all: an operator
// who has not enabled it pays no schedd round trips, and refreshes do not
// strip these scopes either, so the two ends still agree.
func TestConsentDoesNotProbeWhenTheOracleIsOff(t *testing.T) {
	h := aclTestHandler(t)
	in := []string{"openid", "mcp:write"}
	if got := h.scopesAllowedByScheddACL(context.Background(), "alice", in); !reflect.DeepEqual(got, in) {
		t.Errorf("offered %v, want %v unchanged", got, in)
	}
	if h.scheddACLOracle() != nil {
		t.Error("found an ACL oracle where none was configured")
	}
}

// An empty username means the caller could not be identified; probing
// would ask about nobody, and the answer would be meaningless.
func TestConsentSkipsTheProbeWithoutAUsername(t *testing.T) {
	h := aclTestHandler(t)
	spy := &fakeACLOracle{denied: []string{"mcp:write"}}
	in := []string{"mcp:write"}
	if got := h.filterScopesByOracle(context.Background(), spy, "", in); !reflect.DeepEqual(got, in) {
		t.Errorf("offered %v, want %v", got, in)
	}
	if spy.calls != 0 {
		t.Errorf("probed %d times for an empty username, want 0", spy.calls)
	}
}
