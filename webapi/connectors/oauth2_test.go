package connectors

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/bbockelm/golang-htcondor/webapi/connectors/mockgoogle"
)

const (
	testClientID     = "1234.apps.googleusercontent.com"
	testClientSecret = "s3cret"
	testRedirectURI  = "https://ap.example.org/api/v1/connect/builtin:gdrive/callback"
)

type harness struct {
	google *mockgoogle.Server
	flow   *Flow
	def    Definition
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	g := mockgoogle.New(t, mockgoogle.Config{
		ClientID:     testClientID,
		ClientSecret: testClientSecret,
		RedirectURI:  testRedirectURI,
	})
	return &harness{
		google: g,
		flow:   NewFlow(),
		def: Definition{
			ID:               MustParse("builtin:gdrive"),
			Kind:             KindOAuth2,
			ClientID:         testClientID,
			AuthorizationURL: g.AuthorizationURL(),
			TokenURL:         g.TokenURL(),
			Scopes:           []string{"https://www.googleapis.com/auth/drive.file"},
			Groups:           []string{"smith_lab"},
			Enabled:          true,
		},
	}
}

// browse follows an authorization URL as a browser would and returns
// the query the provider redirected back with.
func (h *harness) browse(t *testing.T, authURL string) url.Values {
	t.Helper()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, authURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("follow the authorization URL: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("no redirect from the authorization endpoint: %v (status %d)", err, resp.StatusCode)
	}
	return loc.Query()
}

// connect runs a whole flow for one user.
func (h *harness) connect(t *testing.T, subject string) Grant {
	t.Helper()
	authURL, err := h.flow.Begin(h.def, testClientSecret, subject, testRedirectURI)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	q := h.browse(t, authURL)
	g, err := h.flow.Complete(t.Context(), h.def, testClientSecret, subject,
		q.Get("state"), q.Get("code"), testRedirectURI)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	return g
}

// --- the happy path ---------------------------------------------------

func TestFlowProducesARefreshToken(t *testing.T) {
	h := newHarness(t)
	g := h.connect(t, "alice")

	if g.RefreshToken == "" {
		t.Error("no refresh token")
	}
	if g.AccessToken == "" {
		t.Error("no access token")
	}
	if len(g.GrantedScopes) == 0 {
		t.Error("no granted scopes recorded")
	}
	if !h.google.AccessTokenValid(g.AccessToken) {
		t.Error("the access token is not one the provider issued")
	}
}

// The authorization request has to ask for offline access AND force the
// prompt. Without the first there is no refresh token at all; without
// the second a user who has authorized before is approved silently and
// gets none either -- and the connector then works until the access
// token expires, which is a failure detached from its cause.
func TestAuthorizationAsksForOfflineAccessAndConsent(t *testing.T) {
	h := newHarness(t)
	authURL, err := h.flow.Begin(h.def, testClientSecret, "alice", testRedirectURI)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()

	if q.Get("access_type") != "offline" {
		t.Errorf("access_type = %q, want offline", q.Get("access_type"))
	}
	if q.Get("prompt") != "consent" {
		t.Errorf("prompt = %q, want consent", q.Get("prompt"))
	}
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		t.Errorf("PKCE missing: challenge=%q method=%q",
			q.Get("code_challenge"), q.Get("code_challenge_method"))
	}
	if q.Get("state") == "" {
		t.Error("no state")
	}
	if got := q.Get("scope"); !strings.Contains(got, "drive.file") {
		t.Errorf("scope = %q, want the connector's narrow default", got)
	}
}

// An exchange that returns no refresh token is refused outright. The
// alternative is a connector that works for an hour.
func TestExchangeWithoutARefreshTokenIsRefused(t *testing.T) {
	h := newHarness(t)

	// Begin builds the URL with access_type=offline; strip it, which is
	// what a provider that silently approves does to the outcome.
	authURL, err := h.flow.Begin(h.def, testClientSecret, "alice", testRedirectURI)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(authURL)
	q := u.Query()
	q.Del("access_type")
	u.RawQuery = q.Encode()

	cb := h.browse(t, u.String())
	_, err = h.flow.Complete(t.Context(), h.def, testClientSecret, "alice",
		cb.Get("state"), cb.Get("code"), testRedirectURI)

	if !errors.Is(err, ErrNoRefreshToken) {
		t.Fatalf("err = %v, want ErrNoRefreshToken", err)
	}
}

// Two users get separate grants. The design's sharpest rule about
// stored credentials is that one must never be usable for another
// user's request, and this is the first place that could go wrong: a
// Flow holds every pending authorization in one map.
func TestTwoUsersGetSeparateGrants(t *testing.T) {
	h := newHarness(t)

	alice := h.connect(t, "alice")
	bob := h.connect(t, "bob")

	if alice.RefreshToken == bob.RefreshToken {
		t.Fatal("two users were given the same refresh token")
	}
	if alice.AccessToken == bob.AccessToken {
		t.Fatal("two users were given the same access token")
	}
	// Revoking one leaves the other working.
	h.google.Revoke(alice.RefreshToken)
	if _, err := h.flow.Refresh(t.Context(), h.def, testClientSecret, bob.RefreshToken); err != nil {
		t.Errorf("revoking alice's grant broke bob's: %v", err)
	}
	if _, err := h.flow.Refresh(t.Context(), h.def, testClientSecret, alice.RefreshToken); err == nil {
		t.Error("alice's revoked grant still refreshed")
	}
}

// --- state: the part that is ours -------------------------------------

// A callback presented by a different session is refused. The state
// travels through a browser and a query string; binding it to the
// session that began the flow is what stops a stolen or planted one
// from attaching somebody else's provider account to this user.
func TestACallbackFromAnotherSessionIsRefused(t *testing.T) {
	h := newHarness(t)
	authURL, err := h.flow.Begin(h.def, testClientSecret, "alice", testRedirectURI)
	if err != nil {
		t.Fatal(err)
	}
	q := h.browse(t, authURL)

	_, err = h.flow.Complete(t.Context(), h.def, testClientSecret, "mallory",
		q.Get("state"), q.Get("code"), testRedirectURI)
	if err == nil {
		t.Fatal("another session completed alice's authorization")
	}
	if !strings.Contains(err.Error(), "not started by you") {
		t.Errorf("err = %v", err)
	}
}

func TestStateIsSingleUse(t *testing.T) {
	h := newHarness(t)
	authURL, _ := h.flow.Begin(h.def, testClientSecret, "alice", testRedirectURI)
	q := h.browse(t, authURL)

	if _, err := h.flow.Complete(t.Context(), h.def, testClientSecret, "alice",
		q.Get("state"), q.Get("code"), testRedirectURI); err != nil {
		t.Fatalf("first completion: %v", err)
	}
	_, err := h.flow.Complete(t.Context(), h.def, testClientSecret, "alice",
		q.Get("state"), q.Get("code"), testRedirectURI)
	if err == nil {
		t.Fatal("the same state was accepted twice")
	}
}

// A state is consumed even when the exchange fails, or a failed attempt
// would leave a replayable one behind.
func TestStateIsConsumedEvenWhenTheExchangeFails(t *testing.T) {
	h := newHarness(t)
	authURL, _ := h.flow.Begin(h.def, testClientSecret, "alice", testRedirectURI)
	q := h.browse(t, authURL)

	if _, err := h.flow.Complete(t.Context(), h.def, testClientSecret, "alice",
		q.Get("state"), "not-a-real-code", testRedirectURI); err == nil {
		t.Fatal("a bogus code was accepted")
	}
	if h.flow.Pending() != 0 {
		t.Error("the state survived a failed exchange and could be replayed")
	}
}

func TestAnUnknownStateIsRefused(t *testing.T) {
	h := newHarness(t)
	_, err := h.flow.Complete(t.Context(), h.def, testClientSecret, "alice",
		"never-issued", "code", testRedirectURI)
	if err == nil {
		t.Fatal("an unissued state was accepted")
	}
}

func TestStateExpires(t *testing.T) {
	h := newHarness(t)
	authURL, _ := h.flow.Begin(h.def, testClientSecret, "alice", testRedirectURI)
	q := h.browse(t, authURL)

	h.flow.now = func() time.Time { return time.Now().Add(FlowTTL + time.Minute) }

	_, err := h.flow.Complete(t.Context(), h.def, testClientSecret, "alice",
		q.Get("state"), q.Get("code"), testRedirectURI)
	if err == nil {
		t.Fatal("an expired authorization was completed")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("err = %v, want it to say the authorization expired", err)
	}
}

func TestStateIsUnguessable(t *testing.T) {
	h := newHarness(t)
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		authURL, err := h.flow.Begin(h.def, testClientSecret, "alice", testRedirectURI)
		if err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(authURL)
		state := u.Query().Get("state")
		if seen[state] {
			t.Fatal("a state value repeated")
		}
		seen[state] = true
		// 256 bits, base64url: 43 characters.
		if len(state) < 40 {
			t.Fatalf("state %q is only %d characters", state, len(state))
		}
	}
}

func TestBeginRefusesAnUnauthenticatedCaller(t *testing.T) {
	h := newHarness(t)
	if _, err := h.flow.Begin(h.def, testClientSecret, "", testRedirectURI); err == nil {
		t.Fatal("a flow was begun with no user to bind it to")
	}
}

// A state issued for one connector cannot complete another. Both are
// this user's, so the session check passes; the connector check is what
// stops a grant for a narrow connector being filed as one for a wide
// one.
func TestAStateCannotCrossConnectors(t *testing.T) {
	h := newHarness(t)
	authURL, _ := h.flow.Begin(h.def, testClientSecret, "alice", testRedirectURI)
	q := h.browse(t, authURL)

	other := h.def
	other.ID = MustParse("site:other")

	_, err := h.flow.Complete(t.Context(), other, testClientSecret, "alice",
		q.Get("state"), q.Get("code"), testRedirectURI)
	if err == nil {
		t.Fatal("a state issued for builtin:gdrive completed site:other")
	}
}

// --- refresh ----------------------------------------------------------

func TestRefreshMintsANewAccessToken(t *testing.T) {
	h := newHarness(t)
	g := h.connect(t, "alice")

	at, err := h.flow.Refresh(t.Context(), h.def, testClientSecret, g.RefreshToken)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if at.Token == "" || at.Token == g.AccessToken {
		t.Errorf("Refresh returned %q; want a new token", at.Token)
	}
	if !h.google.AccessTokenValid(at.Token) {
		t.Error("the refreshed token is not one the provider issued")
	}
}

// A revoked grant is ErrNeedsConsent, not a transient failure. Retrying
// it on a timer is how a server earns a rate limit from somebody else's
// identity provider.
func TestRevokedGrantNeedsConsent(t *testing.T) {
	h := newHarness(t)
	g := h.connect(t, "alice")
	h.google.Revoke(g.RefreshToken)

	_, err := h.flow.Refresh(t.Context(), h.def, testClientSecret, g.RefreshToken)
	if !errors.Is(err, ErrNeedsConsent) {
		t.Fatalf("err = %v, want ErrNeedsConsent", err)
	}
}

// A provider having a bad minute is NOT a revocation. Tearing a
// credential down over a 503 would turn one outage into every user
// having to consent again.
func TestATransientFailureIsNotARevocation(t *testing.T) {
	h := newHarness(t)
	h.def.AuthStyle = oauth2.AuthStyleInParams // as builtin:gdrive sets it
	g := h.connect(t, "alice")

	for _, status := range []int{
		http.StatusServiceUnavailable,
		http.StatusTooManyRequests,
		http.StatusInternalServerError,
	} {
		h.google.FailNext(status)
		_, err := h.flow.Refresh(t.Context(), h.def, testClientSecret, g.RefreshToken)
		if err == nil {
			t.Fatalf("status %d: the refresh reported success", status)
		}
		if errors.Is(err, ErrNeedsConsent) {
			t.Errorf("status %d was treated as a revocation", status)
		}
	}
}

// With no AuthStyle set, x/oauth2 probes: it sends the credentials in
// the Authorization header and on ANY error retries once with them in
// the body (internal/token.go:216-246). So one transient failure is
// absorbed invisibly -- until the style is cached, after which it is
// not.
//
// This test documents that behaviour rather than asserting it is
// desirable, which is why builtin:gdrive pins AuthStyleInParams: a
// failure that depends on how many requests have gone before is the
// hardest kind to reason about, and the secret should not go out in two
// forms on the first request.
func TestAnUnpinnedAuthStyleAbsorbsTheFirstFailure(t *testing.T) {
	h := newHarness(t)
	h.def.AuthStyle = 0 // probe, the zero value
	g := h.connect(t, "alice")

	h.google.FailNext(http.StatusServiceUnavailable)
	if _, err := h.flow.Refresh(t.Context(), h.def, testClientSecret, g.RefreshToken); err != nil {
		t.Fatalf("the probe did not absorb a single failure: %v", err)
	}

	// Two failures outlast the probe's one retry.
	h.google.FailNext(http.StatusServiceUnavailable, http.StatusServiceUnavailable)
	_, err := h.flow.Refresh(t.Context(), h.def, testClientSecret, g.RefreshToken)
	if err == nil {
		t.Fatal("two failures still reported success")
	}
	if errors.Is(err, ErrNeedsConsent) {
		t.Error("a transient failure was treated as a revocation")
	}
}

// builtin:gdrive pins the style, so its credentials go out one way and
// a failure is a failure.
func TestBuiltinGDrivePinsItsAuthStyle(t *testing.T) {
	def, ok := Lookup(MustParse("builtin:gdrive"))
	if !ok {
		t.Fatal("builtin:gdrive is not in the catalogue")
	}
	if def.AuthStyle != oauth2.AuthStyleInParams {
		t.Errorf("AuthStyle = %v, want AuthStyleInParams; the zero value makes "+
			"x/oauth2 probe, sending the secret in two forms and absorbing a failure",
			def.AuthStyle)
	}
}

func TestRefreshWithNoTokenNeedsConsent(t *testing.T) {
	h := newHarness(t)
	if _, err := h.flow.Refresh(t.Context(), h.def, testClientSecret, ""); !errors.Is(err, ErrNeedsConsent) {
		t.Errorf("err = %v, want ErrNeedsConsent", err)
	}
}

// --- the provider refusing --------------------------------------------

func TestUserCancellingIsNotAGrant(t *testing.T) {
	h := newHarness(t)
	h.google.DenyAuthorization(true)

	authURL, _ := h.flow.Begin(h.def, testClientSecret, "alice", testRedirectURI)
	q := h.browse(t, authURL)

	if q.Get("error") != "access_denied" {
		t.Fatalf("expected the provider to report access_denied, got %v", q)
	}
	// The caller sees no code, so Complete is reached only with an
	// empty one; it must not produce a grant.
	if _, err := h.flow.Complete(t.Context(), h.def, testClientSecret, "alice",
		q.Get("state"), q.Get("code"), testRedirectURI); err == nil {
		t.Fatal("a cancelled authorization produced a grant")
	}
}

func TestBeginRefusesAConnectorWithNoEndpointsOrClient(t *testing.T) {
	h := newHarness(t)

	noEndpoints := h.def
	noEndpoints.TokenURL = ""
	if _, err := h.flow.Begin(noEndpoints, testClientSecret, "alice", testRedirectURI); err == nil {
		t.Error("a connector with no token endpoint began a flow")
	}

	noClient := h.def
	noClient.ClientID = ""
	_, err := h.flow.Begin(noClient, testClientSecret, "alice", testRedirectURI)
	if err == nil {
		t.Fatal("a connector with no client id began a flow")
	}
	if !strings.Contains(err.Error(), "CLIENT_ID") {
		t.Errorf("err = %v, want it to name the parameter to set", err)
	}
}

// Abandoned flows do not accumulate.
func TestAbandonedFlowsAreSweptOut(t *testing.T) {
	h := newHarness(t)
	for i := 0; i < 5; i++ {
		if _, err := h.flow.Begin(h.def, testClientSecret, "alice", testRedirectURI); err != nil {
			t.Fatal(err)
		}
	}
	if h.flow.Pending() != 5 {
		t.Fatalf("Pending = %d, want 5", h.flow.Pending())
	}
	h.flow.now = func() time.Time { return time.Now().Add(FlowTTL + time.Minute) }
	if n := h.flow.Pending(); n != 0 {
		t.Errorf("Pending = %d after the TTL, want 0", n)
	}
}
