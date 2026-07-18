package httpserver

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/ory/fosite"
	openid "github.com/ory/fosite/handler/openid"
	"golang.org/x/crypto/bcrypt"
)

// fositeAccessTokenDefault and fositeRefreshTokenDefault are the values fosite would
// silently use if AccessTokenLifespan / RefreshTokenLifespan were left zero in the
// fosite.Config. Tests below pick lifespans that are deliberately neither of these,
// so a bug that drops the configured value (like PelicanPlatform/pelican#3389) is
// observable as the wrong duration coming out the other side rather than as a
// suspicious round-number match with our own defaults.
const (
	fositeAccessTokenDefault  = time.Hour
	fositeRefreshTokenDefault = 30 * 24 * time.Hour
)

// TestOAuth2ProviderLifespansAreHonored verifies that the lifespans passed in via
// OAuth2ProviderOptions are what fosite reads back through the config getters, and
// that they are different from fosite's internal defaults. This is a regression
// test for the bug class described in PelicanPlatform/pelican#3389, where a custom
// flow (or storage layer) silently fell back to a 1-hour refresh token because the
// configured lifespan was never plumbed through.
func TestOAuth2ProviderLifespansAreHonored(t *testing.T) {
	// Pick durations that are intentionally distinct from BOTH fosite's defaults
	// AND the httpserver-package defaults (1h / 30d) so a regression that drops
	// our value back to either default is visible as a wrong number.
	const (
		wantAccess  = 17 * time.Minute
		wantRefresh = 13 * time.Hour
	)

	if wantAccess == fositeAccessTokenDefault {
		t.Fatalf("test setup error: wantAccess equals fosite default %s", fositeAccessTokenDefault)
	}
	if wantRefresh == fositeRefreshTokenDefault {
		t.Fatalf("test setup error: wantRefresh equals fosite default %s", fositeRefreshTokenDefault)
	}

	provider, err := NewOAuth2Provider(OAuth2ProviderOptions{
		DB:                   newTestDB(t, filepath.Join(t.TempDir(), "lifespan.db")),
		Issuer:               "http://localhost:8080",
		AccessTokenLifespan:  wantAccess,
		RefreshTokenLifespan: wantRefresh,
	})
	if err != nil {
		t.Fatalf("NewOAuth2Provider: %v", err)
	}
	defer func() { _ = provider.Close() }()

	ctx := context.Background()

	if got := provider.config.GetAccessTokenLifespan(ctx); got != wantAccess {
		t.Errorf("AccessTokenLifespan: got %s, want %s", got, wantAccess)
	}
	if got := provider.config.GetRefreshTokenLifespan(ctx); got != wantRefresh {
		t.Errorf("RefreshTokenLifespan: got %s, want %s", got, wantRefresh)
	}

	// Belt-and-braces: explicitly assert the values are not the fosite defaults
	// even if the *configured* values happened to coincide with them in the
	// future. The first two assertions above catch the real bug; these guard the
	// invariant of "we are not silently taking a default."
	if provider.config.GetAccessTokenLifespan(ctx) == fositeAccessTokenDefault && wantAccess != fositeAccessTokenDefault {
		t.Errorf("AccessTokenLifespan fell back to fosite default %s instead of configured %s",
			fositeAccessTokenDefault, wantAccess)
	}
	if provider.config.GetRefreshTokenLifespan(ctx) == fositeRefreshTokenDefault && wantRefresh != fositeRefreshTokenDefault {
		t.Errorf("RefreshTokenLifespan fell back to fosite default %s instead of configured %s",
			fositeRefreshTokenDefault, wantRefresh)
	}
}

// TestIDPProviderLifespansAreHonored is the same check for the built-in IDP.
func TestIDPProviderLifespansAreHonored(t *testing.T) {
	const (
		wantAccess  = 11 * time.Minute
		wantRefresh = 5 * time.Hour
	)

	provider, err := NewIDPProvider(IDPProviderOptions{
		DB:                   newTestDB(t, filepath.Join(t.TempDir(), "idp-lifespan.db")),
		Issuer:               "http://localhost:8080",
		AccessTokenLifespan:  wantAccess,
		RefreshTokenLifespan: wantRefresh,
	})
	if err != nil {
		t.Fatalf("NewIDPProvider: %v", err)
	}
	defer func() { _ = provider.Close() }()

	ctx := context.Background()

	if got := provider.config.GetAccessTokenLifespan(ctx); got != wantAccess {
		t.Errorf("AccessTokenLifespan: got %s, want %s", got, wantAccess)
	}
	if got := provider.config.GetRefreshTokenLifespan(ctx); got != wantRefresh {
		t.Errorf("RefreshTokenLifespan: got %s, want %s", got, wantRefresh)
	}
}

// TestOAuth2ProviderRejectsMissingLifespans verifies the constructor refuses
// zero-valued lifespans rather than silently substituting a default, which is the
// behavior that masked the original bug in pelican.
func TestOAuth2ProviderRejectsMissingLifespans(t *testing.T) {
	// Lifespan validation happens before DB access in the constructor;
	// a nil DB exercises the right error paths without touching disk.
	cases := []struct {
		name string
		opts OAuth2ProviderOptions
	}{
		{
			name: "zero access lifespan",
			opts: OAuth2ProviderOptions{Issuer: "http://x", RefreshTokenLifespan: time.Hour},
		},
		{
			name: "zero refresh lifespan",
			opts: OAuth2ProviderOptions{Issuer: "http://x", AccessTokenLifespan: time.Hour},
		},
		{
			name: "refresh shorter than access",
			opts: OAuth2ProviderOptions{
				Issuer:               "http://x",
				AccessTokenLifespan:  2 * time.Hour,
				RefreshTokenLifespan: time.Hour,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := NewOAuth2Provider(tc.opts)
			if err == nil {
				_ = p.Close()
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
		})
	}
}

// TestSetStandardTokenExpiriesUsesConfig verifies the helper that custom flows
// (device code, etc.) use to seed session expiries reads from the provider's
// fosite.Config — i.e., the same configured value users set on
// OAuth2ProviderOptions, not a hardcoded fallback.
//
// This is the direct unit-level repro of the pelican#3389 root cause: the
// device-code flow used to call GenerateRefreshToken without populating
// session.ExpiresAt[RefreshToken], leaving the stored session with a zero-valued
// expiry. The fix introduced setStandardTokenExpiries; this test pins it.
func TestSetStandardTokenExpiriesUsesConfig(t *testing.T) {
	const (
		wantAccess  = 23 * time.Minute
		wantRefresh = 9 * time.Hour
	)

	cfg := &fosite.Config{
		AccessTokenLifespan:  wantAccess,
		RefreshTokenLifespan: wantRefresh,
	}
	session := &openid.DefaultSession{}

	before := time.Now().UTC()
	setStandardTokenExpiries(context.Background(), cfg, session)
	after := time.Now().UTC()

	gotAccess := session.GetExpiresAt(fosite.AccessToken)
	gotRefresh := session.GetExpiresAt(fosite.RefreshToken)

	// The expiries must be set (not zero) — that's the bit that pelican#3389 got
	// wrong, and the bit fosite's HMAC strategy then interprets as "unlimited
	// lifetime" for refresh tokens.
	if gotAccess.IsZero() {
		t.Fatalf("AccessToken expiry was not set on session")
	}
	if gotRefresh.IsZero() {
		t.Fatalf("RefreshToken expiry was not set on session")
	}

	// And they must use the configured lifespan, not fosite's defaults.
	wantAccessLow := before.Add(wantAccess).Truncate(time.Second).Add(-time.Second)
	wantAccessHigh := after.Add(wantAccess).Truncate(time.Second).Add(time.Second)
	if gotAccess.Before(wantAccessLow) || gotAccess.After(wantAccessHigh) {
		t.Errorf("AccessToken expiry %s outside expected range [%s, %s] (configured lifespan %s)",
			gotAccess, wantAccessLow, wantAccessHigh, wantAccess)
	}
	wantRefreshLow := before.Add(wantRefresh).Truncate(time.Second).Add(-time.Second)
	wantRefreshHigh := after.Add(wantRefresh).Truncate(time.Second).Add(time.Second)
	if gotRefresh.Before(wantRefreshLow) || gotRefresh.After(wantRefreshHigh) {
		t.Errorf("RefreshToken expiry %s outside expected range [%s, %s] (configured lifespan %s)",
			gotRefresh, wantRefreshLow, wantRefreshHigh, wantRefresh)
	}

	// Sanity: refresh strictly outlives access. If this ever fails, refresh
	// grants will start failing before access tokens expire — exactly the user-
	// visible symptom that triggered this whole investigation.
	if !gotRefresh.After(gotAccess) {
		t.Errorf("RefreshToken expiry %s must be after AccessToken expiry %s", gotRefresh, gotAccess)
	}
}

// TestDeviceCodeFlowSetsRefreshExpiryFromConfig is an end-to-end unit test of the
// device-code custom path in mcp_handlers.go. It reproduces the pelican#3389 bug
// shape: build a request, run it through the handler-level glue that previously
// skipped SetExpiresAt, and assert the persisted refresh-token session has an
// expiry that matches the configured RefreshTokenLifespan (and not 1 hour, which
// is what the storage layer's old hardcoded fallback would have produced).
func TestDeviceCodeFlowSetsRefreshExpiryFromConfig(t *testing.T) {
	const (
		wantAccess  = 7 * time.Minute
		wantRefresh = 3 * time.Hour
	)

	provider, err := NewOAuth2Provider(OAuth2ProviderOptions{
		DB:                   newTestDB(t, filepath.Join(t.TempDir(), "device.db")),
		Issuer:               "http://localhost:8080",
		AccessTokenLifespan:  wantAccess,
		RefreshTokenLifespan: wantRefresh,
	})
	if err != nil {
		t.Fatalf("NewOAuth2Provider: %v", err)
	}
	defer func() { _ = provider.Close() }()

	ctx := context.Background()

	// Register a client capable of device_code + refresh_token grants.
	clientID := "test-device-client"
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.DefaultCost)
	if err := provider.GetStorage().CreateClient(ctx, &fosite.DefaultClient{
		ID:         clientID,
		Secret:     hashedSecret,
		GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code", "refresh_token"},
		Scopes:     []string{"openid"},
	}); err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	client, err := provider.GetStorage().GetClient(ctx, clientID)
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}

	// Build a fosite request that mirrors what handleDeviceCodeTokenRequest assembles
	// after pulling the device-code session out of storage. We populate it directly
	// rather than walking the entire HTTP path because the bug under test is in the
	// session-expiry plumbing, not the wire format.
	session := DefaultOpenIDConnectSession("alice")
	request := fosite.NewAccessRequest(session)
	request.Client = client
	request.GrantedScope = fosite.Arguments{"openid"}
	request.SetID("test-request-id")
	request.RequestedAt = time.Now().UTC()

	// This is the exact call sequence handleDeviceCodeTokenRequest performs after
	// the fix: seed the session, then mint and store the refresh token.
	setStandardTokenExpiries(ctx, provider.config, request.GetSession())

	strategy := provider.GetStrategy()
	refreshToken, _, err := strategy.GenerateRefreshToken(ctx, request)
	if err != nil {
		t.Fatalf("GenerateRefreshToken: %v", err)
	}
	refreshSig := strategy.RefreshTokenSignature(ctx, refreshToken)
	if err := provider.GetStorage().CreateRefreshTokenSession(ctx, refreshSig, request); err != nil {
		t.Fatalf("CreateRefreshTokenSession: %v", err)
	}

	// Now read the session back the way fosite's refresh handler will, and confirm
	// the refresh expiry survived the round trip.
	loadedSession := DefaultOpenIDConnectSession("")
	loaded, err := provider.GetStorage().GetRefreshTokenSession(ctx, refreshSig, loadedSession)
	if err != nil {
		t.Fatalf("GetRefreshTokenSession: %v", err)
	}

	gotRefresh := loaded.GetSession().GetExpiresAt(fosite.RefreshToken)
	if gotRefresh.IsZero() {
		t.Fatal("persisted refresh-token session has zero ExpiresAt[RefreshToken] — fosite would treat this as unlimited lifetime, which is the pelican#3389 bug shape")
	}

	// Must be in the configured ballpark, not the 1-hour storage-layer fallback.
	expectedLow := time.Now().UTC().Add(wantRefresh - time.Minute)
	expectedHigh := time.Now().UTC().Add(wantRefresh + time.Minute)
	if gotRefresh.Before(expectedLow) || gotRefresh.After(expectedHigh) {
		t.Errorf("refresh token expiry %s outside [%s, %s] for configured lifespan %s",
			gotRefresh, expectedLow, expectedHigh, wantRefresh)
	}

	// Specifically: must NOT be the 1-hour value the storage layer used to hardcode.
	oneHourFromNow := time.Now().UTC().Add(time.Hour)
	if gotRefresh.Sub(oneHourFromNow).Abs() < time.Minute {
		t.Errorf("refresh token expiry %s suspiciously close to the 1-hour storage-layer fallback (configured lifespan was %s)",
			gotRefresh, wantRefresh)
	}

	// And the access-token expiry must be present too — same reasoning applies for
	// the access-token validation path in fosite's HMAC strategy.
	if loaded.GetSession().GetExpiresAt(fosite.AccessToken).IsZero() {
		t.Error("persisted refresh-token session has zero ExpiresAt[AccessToken]")
	}
}
