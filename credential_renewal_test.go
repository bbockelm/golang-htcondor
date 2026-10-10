package htcondor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/security"
)

// newRenewalPool is a token pool with a daemon token in the system token
// directory, as on an access point running under condor_master.
func newRenewalPool(t *testing.T) (keyDir string, mint func(sub string, ttl time.Duration) string, cfgText string) {
	t.Helper()
	keyDir = t.TempDir()
	if err := os.WriteFile(filepath.Join(keyDir, "POOL"), []byte("credential-renewal-test-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	mint = func(sub string, ttl time.Duration) string {
		t.Helper()
		now := time.Now()
		tok, err := security.GenerateJWT(keyDir, "POOL", sub, "pool.example", now.Add(-2*time.Hour).Unix(), now.Add(ttl).Unix(), nil)
		if err != nil {
			t.Fatalf("GenerateJWT: %v", err)
		}
		return tok
	}
	sysDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(sysDir, "condor"), []byte(mint("condor@pool.example", time.Hour)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return keyDir, mint, fmt.Sprintf(`
SEC_CLIENT_AUTHENTICATION_METHODS = IDTOKENS
SEC_CLIENT_CRYPTO_METHODS = AES
SEC_TOKEN_SYSTEM_DIRECTORY = %s
`, sysDir)
}

// A caller's token that has expired fails the connection: it does not
// authenticate as this daemon, whose own token is right there. With a
// renewer bound to it the token is minted again and the connection
// authenticates as the caller; a renewer that refuses fails it.
func TestExpiredCallerCredentialIsRenewedOrRefused(t *testing.T) {
	forceDaemon(t)
	keyDir, mint, cfgText := newRenewalPool(t)
	cfg := mustConfig(t, cfgText)

	ping := func(ctx context.Context) (*PingResult, error) {
		t.Helper()
		// A daemon per ping, so nothing is resumed from an earlier one.
		addr := newTokenDaemon(t, keyDir)
		return NewSchedd("fake", addr).WithConfig(cfg).Ping(ctx)
	}
	callerConfig := func(token string) *security.SecurityConfig {
		t.Helper()
		sc, err := NewClientSecurityConfigWithConfig(context.Background(), cfg, token, "", int(commands.DC_NOP), "CLIENT", nil)
		if err != nil {
			t.Fatal(err)
		}
		return sc
	}
	caller := WithUserRequest(context.Background(), "test request")
	expired := callerConfig(mint("alice@pool.example", -time.Second))

	res, err := ping(WithSecurityConfig(caller, expired))
	if err == nil {
		t.Fatalf("an expired caller token authenticated as %q", res.User)
	}

	renewals := 0
	renew := func(context.Context) (*security.SecurityConfig, error) {
		renewals++
		return callerConfig(mint("alice@pool.example", time.Minute)), nil
	}
	res, err = ping(WithRenewableSecurityConfig(caller, expired, renew))
	if err != nil {
		t.Fatalf("a renewable expired caller token: %v", err)
	}
	if res.User != "alice@pool.example" || renewals != 1 {
		t.Errorf("renewable expired token authenticated as %q after %d renewal(s), want alice@pool.example after 1", res.User, renewals)
	}

	refuse := func(context.Context) (*security.SecurityConfig, error) { return nil, errors.New("grant over") }
	if res, err := ping(WithRenewableSecurityConfig(caller, expired, refuse)); err == nil {
		t.Fatalf("a refused renewal authenticated as %q", res.User)
	}
}

// A renewer renews only the config it was attached with, only when that
// config's token is about to expire, and goes with the credential when it
// is detached from the request.
func TestRenewerIsBoundToItsConfig(t *testing.T) {
	_, mint, _ := newRenewalPool(t)
	fresh := mint("alice@pool.example", time.Hour)
	renewals := 0
	renew := func(context.Context) (*security.SecurityConfig, error) {
		renewals++
		return &security.SecurityConfig{Token: fresh}, nil
	}
	tokenOf := func(ctx context.Context) string {
		t.Helper()
		sc, err := GetSecurityConfigOrDefault(ctx, nil, int(commands.DC_NOP), "CLIENT", "<127.0.0.1:1>")
		if err != nil {
			t.Fatalf("GetSecurityConfigOrDefault: %v", err)
		}
		return sc.Token
	}
	base := WithUserRequest(context.Background(), "test request")

	expiring := mint("alice@pool.example", 10*time.Second)
	ctx := WithRenewableSecurityConfig(base, &security.SecurityConfig{Token: expiring}, renew)
	if got := tokenOf(ctx); got != fresh {
		t.Error("a token within the renewal margin of expiry was presented, not renewed")
	}

	lasting := mint("alice@pool.example", time.Hour)
	renewals = 0
	if got := tokenOf(WithRenewableSecurityConfig(base, &security.SecurityConfig{Token: lasting}, renew)); got != lasting || renewals != 0 {
		t.Errorf("a token an hour from expiry was renewed (%d renewal(s))", renewals)
	}

	// Replaced by some other config -- impersonation, say -- the
	// caller's renewer must not swap the caller back in.
	other := mint("bob@pool.example", 10*time.Second)
	if got := tokenOf(WithSecurityConfig(ctx, &security.SecurityConfig{Token: other})); got != other {
		t.Error("a renewer replaced a config it was not attached with")
	}

	// Detached from the request and attached to background work.
	cred, ok := CallerCredentialFromContext(ctx)
	if !ok || !cred.Renewable() {
		t.Fatalf("detached credential: ok=%v renewable=%v, want both", ok, cred.Renewable())
	}
	if got := tokenOf(cred.Attach(WithUserRequest(context.Background(), "background"))); got != fresh {
		t.Error("a detached credential lost its renewer")
	}
	plain, _ := CallerCredentialFromContext(WithSecurityConfig(base, &security.SecurityConfig{Token: expiring}))
	if plain.Renewable() {
		t.Error("a credential attached without a renewer reports itself renewable")
	}
}

func TestTokenExpiresWithin(t *testing.T) {
	_, mint, _ := newRenewalPool(t)
	now := time.Now()
	for _, tc := range []struct {
		name  string
		token string
		want  bool
	}{
		{"expired", mint("a@pool.example", -time.Second), true},
		{"inside the margin", mint("a@pool.example", 10*time.Second), true},
		{"outside the margin", mint("a@pool.example", time.Hour), false},
		{"not a JWT", "opaque-token", false},
	} {
		if got := tokenExpiresWithin(tc.token, credentialRenewMargin, now); got != tc.want {
			t.Errorf("%s: tokenExpiresWithin = %v, want %v", tc.name, got, tc.want)
		}
	}
}
