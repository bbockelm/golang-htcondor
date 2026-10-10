package httpserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// unsignedJWT builds a JWT nobody signed, with the given claims.
func unsignedJWT(t *testing.T, alg string, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]any{"alg": alg, "typ": "JWT", "kid": "POOL"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString([]byte("not-a-signature"))
}

// tenYearJWT is an unsigned token from iss, distinct per nonce, that
// claims to be good for ten years.
func tenYearJWT(t *testing.T, iss string, nonce int) string {
	t.Helper()
	now := time.Now()
	return unsignedJWT(t, "HS256", map[string]any{
		"sub": "x@test.domain",
		"iss": iss,
		"jti": fmt.Sprintf("nonce-%d", nonce),
		"iat": now.Unix(),
		"exp": now.AddDate(10, 0, 0).Unix(),
	})
}

// newRoutedServer is a server whose ServeHTTP reaches its routes.
func newRoutedServer(t *testing.T, cfg Config) *Server {
	t.Helper()
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	s.setupRoutes()
	return s
}

// fakeClock is a TokenCache clock that only moves when told to.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

// A bearer nobody verified must not buy a cache entry that lasts as
// long as the exp it claims, and enough of them must not grow the
// cache without limit: each one is free to make.
func TestTokenCacheBoundsUnvalidatedBearers(t *testing.T) {
	tc := NewTokenCache()
	clock := &fakeClock{t: time.Now()}
	tc.now = clock.now

	for i := 0; i < 10000; i++ {
		if _, err := tc.Add(tenYearJWT(t, "test.domain", i)); err != nil {
			t.Fatalf("Add #%d: %v", i, err)
		}
	}
	if got := tc.Size(); got > tokenCacheMaxEntries {
		t.Errorf("Size = %d after 10000 distinct bearers, want at most %d", got, tokenCacheMaxEntries)
	}
	if got := tc.Size(); got == 0 {
		t.Error("Size = 0: the cache kept nothing, so it is not caching at all")
	}

	clock.advance(tokenCacheUnvalidatedResidency + time.Second)
	if got := tc.Size(); got != 0 {
		t.Errorf("Size = %d once the unvalidated residency passed, want 0 whatever exp the tokens claim", got)
	}
}

// Eviction under that pressure takes unverified entries first, so a
// verified bearer keeps its entry -- and with it the sessions it has
// established.
func TestTokenCacheValidatedSurvivesEvictionPressure(t *testing.T) {
	tc := NewTokenCache()
	clock := &fakeClock{t: time.Now()}
	tc.now = clock.now

	const opaque = "ory_at_opaque-access-token"
	validated, err := tc.AddValidated(opaque, "alice@test.domain", clock.t.Add(30*time.Minute))
	if err != nil {
		t.Fatalf("AddValidated: %v", err)
	}
	for i := 0; i < 2*tokenCacheMaxEntries; i++ {
		if _, err := tc.Add(tenYearJWT(t, "test.domain", i)); err != nil {
			t.Fatalf("Add #%d: %v", i, err)
		}
	}

	got, ok := tc.Get(opaque)
	if !ok {
		t.Fatal("the verified entry was evicted by unverified ones")
	}
	if got != validated {
		t.Error("the verified entry was replaced, losing its session cache")
	}
	if user := tc.ValidatedUsername(opaque); user != "alice@test.domain" {
		t.Errorf("ValidatedUsername = %q, want alice@test.domain", user)
	}

	// And the cache is still bounded: the verified entry is one of the
	// cap, not in addition to it.
	if size := tc.Size(); size > tokenCacheMaxEntries {
		t.Errorf("Size = %d, want at most %d", size, tokenCacheMaxEntries)
	}
}

// A verified entry is not kept past its own residency either; it goes,
// and adding the bearer again (re-verifying it) gives a fresh one.
func TestTokenCacheValidatedResidency(t *testing.T) {
	tc := NewTokenCache()
	clock := &fakeClock{t: time.Now()}
	tc.now = clock.now

	const opaque = "ory_at_long-lived"
	if _, err := tc.AddValidated(opaque, "alice@test.domain", clock.t.AddDate(1, 0, 0)); err != nil {
		t.Fatalf("AddValidated: %v", err)
	}
	clock.advance(tokenCacheValidatedResidency + time.Second)
	if _, ok := tc.Get(opaque); ok {
		t.Error("a verified entry outlived tokenCacheValidatedResidency")
	}
	if _, err := tc.AddValidated(opaque, "alice@test.domain", clock.t.AddDate(1, 0, 0)); err != nil {
		t.Fatalf("re-adding: %v", err)
	}
	if user := tc.ValidatedUsername(opaque); user != "alice@test.domain" {
		t.Errorf("ValidatedUsername after re-adding = %q, want alice@test.domain", user)
	}
}

// The same bound through the request path: every unknown bearer
// reaches TokenCache.Add from createAuthenticatedContext.
func TestUnvalidatedBearersDoNotGrowTheTokenCache(t *testing.T) {
	s := newRoutedServer(t, newTestConfig(t))
	clock := &fakeClock{t: time.Now()}
	s.tokenCache.now = clock.now
	// A small cap so the request path can overrun it quickly.
	s.tokenCache.maxEntries = 16

	for i := 0; i < 100; i++ {
		req := httptest.NewRequestWithContext(context.Background(),
			http.MethodGet, "/api/v1/whoami", nil)
		req.Header.Set("Authorization", "Bearer "+tenYearJWT(t, "test.domain", i))
		s.ServeHTTP(httptest.NewRecorder(), req)
	}
	if got := s.tokenCache.Size(); got == 0 || got > 16 {
		t.Errorf("Size = %d after 100 distinct bearers, want 1..16", got)
	}
	clock.advance(tokenCacheUnvalidatedResidency + time.Second)
	if got := s.tokenCache.Size(); got != 0 {
		t.Errorf("Size = %d after the unvalidated residency, want 0", got)
	}
}

// A token issued outside this pool's trust domain can never
// authenticate here. It is refused before it is cached or handed to
// CEDAR; one from the trust domain is still accepted.
func TestTokenFromAnotherTrustDomainIsRefused(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.TrustDomain = "test.domain"
	s := newRoutedServer(t, cfg)

	serve := func(token string) int {
		req := httptest.NewRequestWithContext(context.Background(),
			http.MethodGet, "/api/v1/jobs", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, req)
		return w.Result().StatusCode
	}

	foreign := tenYearJWT(t, "not-this-pool", 1)
	if got := serve(foreign); got != http.StatusUnauthorized {
		t.Errorf("status = %d for a token from another trust domain, want 401", got)
	}
	if _, ok := s.tokenCache.Get(foreign); ok {
		t.Error("a token from another trust domain was cached")
	}

	// Without an iss at all it is no better.
	now := time.Now()
	noIssuer := unsignedJWT(t, "HS256", map[string]any{
		"sub": "x@test.domain", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	})
	serve(noIssuer)
	if _, ok := s.tokenCache.Get(noIssuer); ok {
		t.Error("a token with no issuer was cached")
	}

	// The other direction: a token from this trust domain gets past the
	// cache (whatever the schedd later makes of it).
	local := tenYearJWT(t, "test.domain", 2)
	serve(local)
	if _, ok := s.tokenCache.Get(local); !ok {
		t.Error("a token from this pool's trust domain was not cached")
	}

	// A SciToken's issuer is external by design; the schedd checks it
	// against its own SciTokens configuration, not TRUST_DOMAIN.
	sci := unsignedJWT(t, "RS256", map[string]any{
		"sub": "x", "iss": "https://issuer.example.org",
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	})
	serve(sci)
	if _, ok := s.tokenCache.Get(sci); !ok {
		t.Error("a SciToken was refused for its external issuer")
	}
}

// A 2xx response is not evidence that anything verified the bearer:
// these endpoints answer one without presenting it to a daemon. So
// however many of them a forged token collects, it stays nobody.
func TestForgedTokenIsNotValidatedBySuccessfulResponses(t *testing.T) {
	s := newRoutedServer(t, newTestConfig(t))
	forged := forgedToken(t, "admin@test.domain")

	for _, path := range []string{"/api/v1/whoami", "/api/v1/version", "/api/v1/templates"} {
		for i := 0; i < 3; i++ {
			req := httptest.NewRequestWithContext(context.Background(),
				http.MethodGet, path, nil)
			req.Header.Set("Authorization", "Bearer "+forged)
			w := httptest.NewRecorder()
			s.ServeHTTP(w, req)
			// whoami answers 200 whoever asks, which is what makes
			// this test mean something; the others may refuse.
			if path == "/api/v1/whoami" && w.Code != http.StatusOK {
				t.Fatalf("%s status = %d, want 200", path, w.Code)
			}
			if got := s.tokenCache.ValidatedUsername(forged); got != "" {
				t.Fatalf("after a %d from %s the forged token is validated as %q", w.Code, path, got)
			}
		}
	}
}

// Session-cookie mode mints a new token for every request. Those must
// not each become a cache entry; the user's sessions are kept under
// the user this server authenticated, as in user-header mode.
func TestSessionCookieRequestsDoNotAddTokenCacheEntries(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.SigningKeyPath = writeTestSigningKey(t)
	cfg.TrustDomain = "test.domain"
	cfg.UIDDomain = "test.domain"
	s := newRoutedServer(t, cfg)
	sid, _, err := s.sessionStore.Create("alice")
	if err != nil {
		t.Fatalf("creating a session: %v", err)
	}
	newRequest := func() *http.Request {
		req := httptest.NewRequestWithContext(context.Background(),
			http.MethodGet, "/api/v1/whoami", nil)
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid}) //nolint:gosec // test cookie
		return req
	}

	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		s.ServeHTTP(w, newRequest())
		if w.Code != http.StatusOK {
			t.Fatalf("whoami status = %d", w.Code)
		}
	}
	if got := s.tokenCache.Size(); got != 0 {
		t.Errorf("Size = %d after session-cookie requests, want 0", got)
	}

	ctx, err := s.createAuthenticatedContext(newRequest())
	if err != nil {
		t.Fatalf("createAuthenticatedContext: %v", err)
	}
	secConfig, ok := htcondor.GetSecurityConfigFromContext(ctx)
	if !ok {
		t.Fatal("no security config on the request context")
	}
	if secConfig.SecurityTag != "session:alice" {
		t.Errorf("SecurityTag = %q, want session:alice", secConfig.SecurityTag)
	}
	if secConfig.SessionCache != nil {
		t.Error("a per-request session cache was attached; nothing could ever resume from it")
	}
}
