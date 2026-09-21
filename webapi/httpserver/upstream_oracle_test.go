package httpserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/bbockelm/golang-htcondor/logging"
)

const upstreamTestIssuer = "https://idp.example.org/token" //nolint:gosec // a public endpoint, not a credential

// upstreamOracleFor builds an oracle whose provider is whatever the test
// says it is.
func upstreamOracleFor(t *testing.T, refresh tokenRefresher, info userInfoFetcher, required string) *upstreamUserInfoOracle {
	t.Helper()
	logger, _ := logging.New(&logging.Config{OutputPath: "stderr"})
	store := upstreamStore(t, false)
	if err := store.Save(context.Background(), upstreamGrant{
		Subject:         "alice",
		ProviderSubject: "idp-sub-alice",
		Issuer:          upstreamTestIssuer,
		RefreshToken:    "stored-refresh",
		GrantedScopes:   []string{"openid", "offline_access"},
		ObtainedAt:      time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seeding the credential: %v", err)
	}
	return &upstreamUserInfoOracle{
		store:    store,
		issuer:   func() string { return upstreamTestIssuer },
		refresh:  refresh,
		userInfo: info,
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
			out := []string{}
			for _, s := range requested {
				if s == "mcp:write" && !write {
					continue
				}
				out = append(out, s)
			}
			return out
		},
		logger: logger,
		now:    time.Now,
	}
}

func okRefresh(_ context.Context, _ string) (*oauth2.Token, error) {
	return &oauth2.Token{AccessToken: "fresh-access"}, nil
}

func infoWith(subject string, groups ...string) userInfoFetcher {
	return func(_ context.Context, _ string) (*UserInfo, error) {
		return &UserInfo{Subject: subject, Groups: groups}, nil
	}
}

// TestUpstreamOracleOutageIsNotAVerdict is the one that decides whether this
// feature is safe to ship. The provider being unreachable says nothing about
// the user; reading it as a verdict revokes every grant that happens to
// refresh while the provider is down, which is every active session at once.
func TestUpstreamOracleOutageIsNotAVerdict(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"connection refused", errors.New("dial tcp: connection refused")},
		{"gateway error", &oauth2.RetrieveError{
			Response: &http.Response{StatusCode: http.StatusBadGateway},
		}},
		{"provider is confused about us", &oauth2.RetrieveError{
			Response:  &http.Response{StatusCode: http.StatusUnauthorized},
			ErrorCode: "invalid_client",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := upstreamOracleFor(t,
				func(context.Context, string) (*oauth2.Token, error) { return nil, tc.err },
				infoWith("idp-sub-alice"), "condor-users")

			got, err := o.Check(context.Background(), "alice", []string{"mcp:read"})
			if err == nil {
				t.Fatal("expected no opinion, reported as success")
			}
			if got.Status == UserStatusRevoked {
				t.Errorf("an unreachable provider revoked a grant: %v", tc.err)
			}
		})
	}
}

// invalid_grant is the provider disowning the credential -- the account is
// gone, or somebody revoked the authorization there. That IS about the user.
func TestUpstreamOracleRevokesOnDeadGrant(t *testing.T) {
	o := upstreamOracleFor(t,
		func(context.Context, string) (*oauth2.Token, error) {
			return nil, &oauth2.RetrieveError{
				Response:  &http.Response{StatusCode: http.StatusBadRequest},
				ErrorCode: "invalid_grant",
			}
		},
		infoWith("idp-sub-alice"), "condor-users")

	got, err := o.Check(context.Background(), "alice", []string{"mcp:read"})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got.Status != UserStatusRevoked {
		t.Errorf("status = %v, want revoked once the provider disowned the grant", got.Status)
	}

	// And the dead credential is forgotten rather than retried forever.
	if _, err := o.store.Load(context.Background(), "alice", upstreamTestIssuer); err == nil {
		t.Error("a credential the provider rejected was kept and will be retried on every refresh")
	}
}

// The claims that come back belong to whoever the credential names. If that
// is not the user this row was filed under, acting on them would apply one
// person's groups to another.
func TestUpstreamOracleRefusesAnswersAboutSomebodyElse(t *testing.T) {
	o := upstreamOracleFor(t, okRefresh, infoWith("idp-sub-BOB", "condor-users"), "condor-users")

	got, err := o.Check(context.Background(), "alice", []string{"mcp:read"})
	if err == nil {
		t.Fatal("an answer about another user was accepted")
	}
	if got.Status == UserStatusRevoked {
		t.Error("revoked on an answer that was about somebody else")
	}
}

// The point of the exercise: membership removed upstream after consent is
// noticed, which is what neither the frozen session nor a container without
// an account database can see.
func TestUpstreamOracleRevokesOnLostMembership(t *testing.T) {
	o := upstreamOracleFor(t, okRefresh, infoWith("idp-sub-alice", "some-other-group"), "condor-users")

	got, err := o.Check(context.Background(), "alice", []string{"mcp:read"})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got.Status != UserStatusRevoked {
		t.Errorf("status = %v, want revoked once the group is gone upstream", got.Status)
	}
}

// Losing write access narrows rather than ends the session.
func TestUpstreamOracleNarrowsRatherThanRevoking(t *testing.T) {
	o := upstreamOracleFor(t, okRefresh, infoWith("idp-sub-alice", "condor-users"), "condor-users")

	got, err := o.Check(context.Background(), "alice", []string{"mcp:read", "mcp:write"})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got.Status == UserStatusRevoked {
		t.Fatal("revoked a user who still has access, merely less of it")
	}
	if len(got.DeniedScopes) != 1 || got.DeniedScopes[0] != "mcp:write" {
		t.Errorf("denied = %v, want [mcp:write]", got.DeniedScopes)
	}
}

// TestUpstreamOracleRateLimitsPerUser: a client refreshes on its own timer,
// and the provider has no reason to hear about that. Without a floor one
// busy agent becomes steady load on somebody else's identity service.
func TestUpstreamOracleRateLimitsPerUser(t *testing.T) {
	calls := 0
	o := upstreamOracleFor(t,
		func(context.Context, string) (*oauth2.Token, error) {
			calls++
			return &oauth2.Token{AccessToken: "fresh"}, nil
		},
		infoWith("idp-sub-alice", "condor-users"), "condor-users")

	for i := 0; i < 3; i++ {
		if _, err := o.Check(context.Background(), "alice", []string{"mcp:read"}); err != nil {
			t.Fatalf("Check %d: %v", i, err)
		}
	}
	if calls != 1 {
		t.Errorf("asked the provider %d times for three refreshes in a row", calls)
	}

	// Past the interval it asks again: the limit is a floor, not a latch.
	o.now = func() time.Time { return time.Now().Add(2 * upstreamCheckInterval) }
	if _, err := o.Check(context.Background(), "alice", []string{"mcp:read"}); err != nil {
		t.Fatalf("Check after the interval: %v", err)
	}
	if calls != 2 {
		t.Errorf("the provider was asked %d times; the rate limit never lifts", calls)
	}
}

// A user with no stored credential is not an opinion. That is every user
// wherever the provider does not release offline_access, which is the case
// "auto" exists for.
func TestUpstreamOracleSaysNothingWithoutACredential(t *testing.T) {
	o := upstreamOracleFor(t, okRefresh, infoWith("idp-sub-bob"), "condor-users")

	got, err := o.Check(context.Background(), "nobody-here", []string{"mcp:read"})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got.Status == UserStatusRevoked {
		t.Error("revoked a user this server holds no credential for")
	}
}

func TestIsUpstreamGrantDead(t *testing.T) {
	cases := map[string]struct {
		err  error
		dead bool
	}{
		"invalid_grant":         {&oauth2.RetrieveError{ErrorCode: "invalid_grant"}, true},
		"bare 400":              {&oauth2.RetrieveError{Response: &http.Response{StatusCode: 400}}, true},
		"401 invalid_client":    {&oauth2.RetrieveError{Response: &http.Response{StatusCode: 401}, ErrorCode: "invalid_client"}, false},
		"503":                   {&oauth2.RetrieveError{Response: &http.Response{StatusCode: 503}}, false},
		"network":               {errors.New("connection refused"), false},
		"wrapped invalid_grant": {fmt.Errorf("refreshing: %w", &oauth2.RetrieveError{ErrorCode: "invalid_grant"}), true},
	}
	for name, tc := range cases {
		if got := isUpstreamGrantDead(tc.err); got != tc.dead {
			t.Errorf("%s: isUpstreamGrantDead = %v, want %v", name, got, tc.dead)
		}
	}
}

// registration is a decision, not plumbing: registering with no upstream
// provider is a nil dereference on the first refresh, and not registering
// when there is one silently disables the feature.
func TestUpstreamOracleIsWiredExactlyWhenThereIsAProvider(t *testing.T) {
	logger, _ := logging.New(&logging.Config{OutputPath: "stderr"})
	withProvider := func() *oauth2.Config {
		return &oauth2.Config{Endpoint: oauth2.Endpoint{TokenURL: upstreamTestIssuer}}
	}

	for _, tc := range []struct {
		name      string
		mode      UpstreamRefreshMode
		store     bool
		cfg       *oauth2.Config
		infoURL   string
		wantWired bool
	}{
		{"auto with a provider", UpstreamRefreshAuto, true, withProvider(), "https://idp/userinfo", true},
		{"on with a provider", UpstreamRefreshOn, true, withProvider(), "https://idp/userinfo", true},
		{"off", UpstreamRefreshOff, true, withProvider(), "https://idp/userinfo", false},
		{"no upstream provider", UpstreamRefreshAuto, true, nil, "", false},
		{"provider with no userinfo endpoint", UpstreamRefreshAuto, true, withProvider(), "", false},
		{"no store", UpstreamRefreshAuto, false, withProvider(), "https://idp/userinfo", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &Handler{
				logger:              logger,
				upstreamRefreshMode: tc.mode,
				oauth2Config:        tc.cfg,
				oauth2UserInfoURL:   tc.infoURL,
			}
			if tc.store {
				h.upstreamRefresh = upstreamStore(t, false)
			}
			h.registerUpstreamOracle(logger)

			wired := false
			for _, o := range h.revocationOracles {
				if o.Name() == "upstream-userinfo" {
					wired = true
				}
			}
			if wired != tc.wantWired {
				t.Errorf("wired = %v, want %v", wired, tc.wantWired)
			}
		})
	}
}

// A deployment with no group policy still benefits from the check: the
// provider disowning a credential is about the account existing at all,
// which is orthogonal to whether any group is required.
func TestUpstreamOracleWithNoRequiredGroup(t *testing.T) {
	o := upstreamOracleFor(t, okRefresh, infoWith("idp-sub-alice"), "")

	got, err := o.Check(context.Background(), "alice", []string{"mcp:read"})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got.Status == UserStatusRevoked {
		t.Error("revoked a user where no group is required at all")
	}
}
