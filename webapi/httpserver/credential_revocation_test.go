package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bbockelm/cedar/security"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/mcpserver"
)

// revokeAccessTokenGrant revokes the grant behind an access token, as the
// admin revoke endpoint and refresh-token reuse do.
func revokeAccessTokenGrant(t *testing.T, h *Handler, token string) {
	t.Helper()
	ar, err := h.oauth2Provider.IntrospectAccessToken(context.Background(), token)
	if err != nil {
		t.Fatalf("introspecting the token to revoke: %v", err)
	}
	h.revokeGrant(context.Background(), ar.GetID(), ar.GetSession().GetSubject(), "test revocation")
}

// renewsThenStops asserts that the credential on ctx renews while its source
// is good, and that after end() the next renewal is refused.
func renewsThenStops(ctx context.Context, t *testing.T, end func()) {
	t.Helper()
	cred, ok := htcondor.CallerCredentialFromContext(ctx)
	if !ok || !cred.Renewable() {
		t.Fatalf("credential on the context: present=%v renewable=%v, want both", ok, cred.Renewable())
	}
	if _, err := cred.Renew(context.Background()); err != nil {
		t.Fatalf("renewal with its source still good: %v", err)
	}
	end()
	if _, err := cred.Renew(context.Background()); err == nil {
		t.Error("the credential renewed after its source ended")
	}
}

// A renewal is a fresh mint, so it re-checks whatever authorized the
// caller: a revoked grant, a logged-out session or a finished request
// renews nothing.
func TestRenewalStopsWithItsSource(t *testing.T) {
	t.Run("REST OAuth2 grant", func(t *testing.T) {
		h := newRESTOAuth2Handler(t)
		opaque := mintRESTAccessToken(t, h, "alice", []string{"condor:/READ"})
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/jobs", nil)
		req.Header.Set("Authorization", "Bearer "+opaque)
		ctx, err := h.createAuthenticatedContext(req)
		if err != nil {
			t.Fatalf("createAuthenticatedContext: %v", err)
		}
		renewsThenStops(ctx, t, func() { revokeAccessTokenGrant(t, h, opaque) })
	})

	t.Run("MCP OAuth2 grant", func(t *testing.T) {
		s := newMCPScopeServer(t, false)
		tok := mintMCPAccessToken(t, s, []string{"mcp:read"})
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", nil)
		req.Header.Set("Accept", mcpserver.AcceptHeader)
		req.Header.Set("Authorization", "Bearer "+tok)
		ctx, _, ok := s.mcpAuthContext(httptest.NewRecorder(), req)
		if !ok {
			t.Fatal("mcpAuthContext refused a valid token")
		}
		renewsThenStops(ctx, t, func() { revokeAccessTokenGrant(t, s.Handler, tok) })
	})

	t.Run("session cookie", func(t *testing.T) {
		f := twoOwnerScheddServer(t)
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/jobs", nil)
		f.session(t, "alice")(req)
		ctx, err := f.s.createAuthenticatedContext(req)
		if err != nil {
			t.Fatalf("createAuthenticatedContext: %v", err)
		}
		sid, err := getSessionCookie(req)
		if err != nil {
			t.Fatal(err)
		}
		renewsThenStops(ctx, t, func() { f.s.sessionStore.Delete(sid) })
	})

	t.Run("user header", func(t *testing.T) {
		cfg := newTestConfig(t)
		cfg.UserHeader = "X-Test-User"
		cfg.UserHeaderTrustAnyUnsafe = true
		cfg.SigningKeyPath = writeTestSigningKey(t)
		cfg.TrustDomain = "test.domain"
		cfg.UIDDomain = "test.domain"
		s, err := NewServer(cfg)
		if err != nil {
			t.Fatalf("NewServer: %v", err)
		}
		reqCtx, cancel := context.WithCancel(context.Background())
		defer cancel()
		req := httptest.NewRequestWithContext(reqCtx, http.MethodGet, "/api/v1/jobs", nil)
		req.Header.Set("X-Test-User", "alice")
		ctx, err := s.createAuthenticatedContext(req)
		if err != nil {
			t.Fatalf("createAuthenticatedContext: %v", err)
		}
		renewsThenStops(ctx, t, cancel)
	})
}

// revokingOracle refuses every user once refuse is set, counting checks.
type revokingOracle struct {
	refuse atomic.Bool
	checks atomic.Int32
}

func (o *revokingOracle) Name() string { return "test oracle" }

func (o *revokingOracle) Check(context.Context, string, []string) (ReauthDecision, error) {
	o.checks.Add(1)
	if o.refuse.Load() {
		return ReauthDecision{Status: UserStatusRevoked, Reason: "disabled"}, nil
	}
	return ReauthDecision{Status: UserStatusActive}, nil
}

// Renewal re-runs the grant's authorization policy too, at most once per
// interval per grant: a user an oracle reports disabled loses the grant at
// the next due renewal, as they would at the next refresh.
func TestRenewalReauthorizesTheGrant(t *testing.T) {
	h := newRESTOAuth2Handler(t)
	oracle := &revokingOracle{}
	h.revocationOracles = []RevocationOracle{oracle}
	opaque := mintRESTAccessToken(t, h, "alice", []string{"condor:/READ"})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/jobs", nil)
	req.Header.Set("Authorization", "Bearer "+opaque)
	ctx, err := h.createAuthenticatedContext(req)
	if err != nil {
		t.Fatalf("createAuthenticatedContext: %v", err)
	}
	cred, _ := htcondor.CallerCredentialFromContext(ctx)

	for i := 0; i < 3; i++ {
		if _, err := cred.Renew(context.Background()); err != nil {
			t.Fatalf("renewal %d of an active grant: %v", i, err)
		}
	}
	if n := oracle.checks.Load(); n != 1 {
		t.Errorf("the oracle was consulted %d times over three renewals, want once per interval", n)
	}

	// Due again, and the oracle now says the user is disabled.
	oracle.refuse.Store(true)
	h.grantReauth = grantReauthLimiter{}
	if _, err := cred.Renew(context.Background()); err == nil {
		t.Fatal("a renewal succeeded for a user the oracle reports disabled")
	}
	if _, err := h.oauth2Provider.IntrospectAccessToken(context.Background(), opaque); err == nil {
		t.Error("the refused grant was left active")
	}
}

// What the holder sees: a job watch or lease carrying a renewable
// credential polls as the caller while the grant is good, and once it is
// revoked its next schedd call fails rather than running on.
func TestRevokedGrantStopsALongLivedHolder(t *testing.T) {
	pool := newTokenPool(t)
	schedd := htcondor.NewSchedd("fake", pool.serve(t, nil)).WithConfig(pool.cfg)
	h := newRESTOAuth2Handler(t)
	h.signingKeyPath = filepath.Join(pool.keyDir, "POOL")
	h.trustDomain, h.uidDomain = "pool.example", "pool.example"
	scopes := []string{"condor:/READ"}
	opaque := mintRESTAccessToken(t, h, "alice", scopes)

	// The request's credential, held past its expiry.
	held, err := configureSecurityForToken(pool.cfg, pool.mint(t, "alice@pool.example", -time.Second), security.NewSessionCache(), false)
	if err != nil {
		t.Fatal(err)
	}
	renew := renewWith(pool.cfg, held, h.grantReminter(opaque, "alice", scopes, time.Now().Add(time.Hour)))
	holder := htcondor.WithRenewableSecurityConfig(
		htcondor.WithUserRequest(context.Background(), "test holder"), held, renew)

	res, err := schedd.Ping(holder)
	if err != nil {
		t.Fatalf("polling on an active grant: %v", err)
	}
	if res.User != "alice@pool.example" {
		t.Errorf("polled as %q, want alice@pool.example", res.User)
	}

	revokeAccessTokenGrant(t, h, opaque)
	if res, err := schedd.Ping(holder); err == nil {
		t.Fatalf("polling after the grant was revoked succeeded as %q", res.User)
	}
}
