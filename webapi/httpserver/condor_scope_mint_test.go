package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/mcpserver"
)

// unmappableCondorGrants are grants whose condor:/* scopes all map to no
// authorization. mapCondorScopesToAuthz keeps only READ and WRITE, so each
// of these produced an empty limit list -- and an IDTOKEN with no scope
// claim, which HTCondor reads as every level the subject holds.
var unmappableCondorGrants = map[string][]string{
	"deprecated ADVERTISE_STARTD only": {"openid", "condor:/ADVERTISE_STARTD"},
	"ADMINISTRATOR only":               {"openid", "condor:/ADMINISTRATOR"},
	// Present condor:/* scopes select the condor mapping, so mcp:write
	// beside them does not reach the mcp:* mapping either.
	"ADVERTISE_STARTD with mcp:write": {"openid", "mcp:write", "condor:/ADVERTISE_STARTD"},
}

// condorTokenScope returns the scope claim of a minted IDTOKEN, and
// whether the claim is present at all.
func condorTokenScope(t *testing.T, token string) (string, bool) {
	t.Helper()
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser(jwt.WithoutClaimsValidation()).ParseUnverified(token, claims); err != nil {
		t.Fatalf("minted credential is not a JWT: %v", err)
	}
	raw, ok := claims["scope"]
	if !ok {
		return "", false
	}
	s, _ := raw.(string)
	return s, true
}

// A grant whose condor:/* scopes all map to nothing is refused a schedd
// credential on the REST surface: the request is rejected, no IDTOKEN
// reaches the context, and a second request with the same bearer is
// refused the same way rather than proceeding on the cache entry the first
// one left.
func TestRESTRefusesCredentialForUnmappableCondorScopes(t *testing.T) {
	for name, scopes := range unmappableCondorGrants {
		t.Run(name, func(t *testing.T) {
			h := newRESTOAuth2Handler(t)
			// Nothing listens here. A request that wrongly gets past
			// authentication fails at the dial, not on a nil schedd.
			h.schedd = htcondor.NewSchedd("test-schedd", "127.0.0.1:1")
			opaque := mintRESTAccessToken(t, h, "alice", scopes)

			// The handler first, then the context builder directly: if the
			// first refusal left a usable cache entry, the second request is
			// where it shows, and it shows here as a returned credential
			// rather than as a dial to a schedd this test does not have.
			for attempt := 1; attempt <= 2; attempt++ {
				req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/jobs", nil)
				req.Header.Set("Authorization", "Bearer "+opaque)
				rec := httptest.NewRecorder()
				h.handleListJobs(rec, req)
				if rec.Code != http.StatusUnauthorized {
					t.Fatalf("attempt %d: GET /api/v1/jobs = %d, want 401: %s", attempt, rec.Code, rec.Body.String())
				}

				req = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/jobs", nil)
				req.Header.Set("Authorization", "Bearer "+opaque)
				ctx, err := h.createAuthenticatedContext(req)
				if err == nil {
					sc, _ := htcondor.GetSecurityConfigFromContext(ctx)
					t.Fatalf("attempt %d: grant %v was given a schedd credential (token %q)", attempt, scopes, sc.Token)
				}
			}
		})
	}
}

// The same grants are refused on the MCP surface, before any tool runs.
func TestMCPRefusesCredentialForUnmappableCondorScopes(t *testing.T) {
	for name, scopes := range unmappableCondorGrants {
		t.Run(name, func(t *testing.T) {
			h := newRESTOAuth2Handler(t)
			// As above: a wrongly admitted caller fails at the dial.
			h.schedd = htcondor.NewSchedd("test-schedd", "127.0.0.1:1")
			opaque := mintRESTAccessToken(t, h, "alice", scopes)

			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", strings.NewReader("{}"))
			req.Header.Set("Authorization", "Bearer "+opaque)
			req.Header.Set("Accept", mcpserver.AcceptHeader)
			rec := httptest.NewRecorder()
			_, _, ok := h.mcpAuthContext(rec, req)
			if ok {
				t.Fatalf("grant %v was admitted to MCP with a minted schedd credential", scopes)
			}
			if rec.Code < 400 {
				t.Fatalf("refusal wrote status %d", rec.Code)
			}

			// The shared helper the SSH gateway also uses.
			if _, err := h.withCondorCredential(context.Background(), "alice", scopes); err == nil {
				t.Fatalf("withCondorCredential minted a credential for %v", scopes)
			}
		})
	}
}

// A recognised scope still mints, and the token is bounded by exactly what
// was granted: present (the grant's level) and absent (everything else).
func TestCondorScopesMintBoundedToken(t *testing.T) {
	for _, tc := range []struct {
		name   string
		scopes []string
		want   []string
	}{
		{"condor:/READ", []string{"openid", "condor:/READ"}, []string{"condor:/READ"}},
		{"condor:/READ beside a deprecated scope", []string{"condor:/READ", "condor:/ADVERTISE_STARTD"}, []string{"condor:/READ"}},
		{"legacy mcp:write", []string{"openid", "mcp:write"}, []string{"condor:/READ", "condor:/WRITE"}},
		{"legacy mcp:read", []string{"openid", "mcp:read"}, []string{"condor:/READ"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newRESTOAuth2Handler(t)
			opaque := mintRESTAccessToken(t, h, "bob", tc.scopes)

			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/jobs", nil)
			req.Header.Set("Authorization", "Bearer "+opaque)
			ctx, err := h.createAuthenticatedContext(req)
			if err != nil {
				t.Fatalf("createAuthenticatedContext: %v", err)
			}
			sc, ok := htcondor.GetSecurityConfigFromContext(ctx)
			if !ok || sc.Token == "" {
				t.Fatal("no minted credential in context")
			}
			scope, present := condorTokenScope(t, sc.Token)
			if !present {
				t.Fatal("minted token has no scope claim, so it is unrestricted")
			}
			got := strings.Fields(scope)
			slices.Sort(got)
			if !slices.Equal(got, tc.want) {
				t.Errorf("scope claim = %v, want %v", got, tc.want)
			}
		})
	}
}

// The minter itself never issues a token without limits, whichever caller
// reaches it.
func TestGenerateMCPAccessJWTRefusesEmptyLimits(t *testing.T) {
	keyPath := writeSigningKey(t)
	for _, limits := range [][]string{nil, {}} {
		token, err := generateMCPAccessJWT(
			filepath.Dir(keyPath), filepath.Base(keyPath),
			"alice@example.com", "pool.example.com", 1, 2, limits)
		if err == nil {
			t.Fatalf("minted %q with limits %#v; a token with no scope claim is unrestricted", token, limits)
		}
	}
}
