package httpserver

import (
	"context"
	"errors"
	"net/http/httptest"
	"reflect"
	"strings"
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

// namedACLOracle answers to the configured name, so the handler's lookup
// finds it the way it finds the real one.
type namedACLOracle struct{ denied []string }

func (n *namedACLOracle) Name() string { return OracleScheddACL }
func (n *namedACLOracle) Check(context.Context, string, []string) (ReauthDecision, error) {
	return ReauthDecision{Status: UserStatusActive, DeniedScopes: n.denied}, nil
}

// The wiring, not the policy. The filter above can be perfect and still
// buy nothing if the consent page never calls it, which is exactly the
// shape of the bug this whole change is about -- a safeguard that exists
// and is not reached.
func TestConsentPageDoesNotRenderScopesTheScheddRefuses(t *testing.T) {
	h := aclTestHandler(t, &namedACLOracle{denied: []string{"mcp:write"}})
	rec := httptest.NewRecorder()

	h.renderConsentPage(context.Background(), rec, nil, consentPageParams{
		Title:           "Authorize Application",
		Username:        "alice",
		ClientID:        "c",
		RequestedScopes: []string{"openid", "mcp:read", "mcp:write"},
		FormAction:      "/mcp/oauth2/consent",
	})

	body := rec.Body.String()
	if strings.Contains(body, `value="mcp:write"`) {
		t.Error("the page offered mcp:write although the access point refuses it")
	}
	if !strings.Contains(body, `value="mcp:read"`) {
		t.Error("the page dropped mcp:read, which the access point allows")
	}
}

// And the same oracle must be found through the handler's own lookup,
// or the filter silently never runs in production.
func TestTheConfiguredACLOracleIsFound(t *testing.T) {
	h := aclTestHandler(t, &namedACLOracle{})
	if h.scheddACLOracle() == nil {
		t.Fatal("the configured schedd-acl oracle was not found")
	}
	real := &ScheddACLOracle{}
	if real.Name() != OracleScheddACL {
		t.Errorf("the real oracle calls itself %q; the lookup keys on %q", real.Name(), OracleScheddACL)
	}
}
