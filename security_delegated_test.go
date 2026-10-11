package htcondor

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
	"github.com/bbockelm/golang-htcondor/config"
)

// TestDelegatedSecurityConfigNeverOffersFS is the unit-level guard for
// the fail-open reported against query_jobs.
//
// A token passed to NewClientSecurityConfig means "act as whoever holds
// this token". FS cannot do that: it identifies the connection by the OS
// process, which for a service is the service account. Cedar negotiates
// in the SERVER's preference order, so leaving FS in the offered list
// lets an ordinary access-point schedd — SEC_DEFAULT_AUTHENTICATION_
// METHODS = FS,TOKEN — pick FS and map the connection to that account
// while the forwarded token goes unused.
//
// Downstream that is not a subtle degradation. Anything asking the
// schedd "who is this connection?" gets the service account, and on an
// access point that account is a queue superuser, for which the schedd
// drops owner filtering entirely: a "my jobs" query returns every user's
// jobs. Ordering alone does not prevent it — only removing FS does.
func TestDelegatedSecurityConfigNeverOffersFS(t *testing.T) {
	cfg, err := NewClientSecurityConfig(context.Background(), "a.token.value", "", 0, "CLIENT", nil)
	if err != nil {
		t.Fatalf("NewClientSecurityConfig: %v", err)
	}

	for _, m := range cfg.AuthMethods {
		if m == security.AuthFS {
			t.Errorf("a delegated config must not offer FS; got %v", cfg.AuthMethods)
		}
	}
	if len(cfg.AuthMethods) == 0 || cfg.AuthMethods[0] != security.AuthToken {
		t.Errorf("TOKEN must be offered first so the caller's credential is what identifies the connection; got %v", cfg.AuthMethods)
	}
	if cfg.Token != "a.token.value" {
		t.Errorf("the supplied token did not reach the config: %q", cfg.Token)
	}
}

// TestUndelegatedSecurityConfigKeepsConfiguredMethods: with no token
// there is nobody to act for, so the connection is the daemon's own and
// the configured methods stand. Stripping FS there would break every
// local same-host call that legitimately authenticates as the process.
func TestUndelegatedSecurityConfigKeepsConfiguredMethods(t *testing.T) {
	cfg, err := NewClientSecurityConfig(context.Background(), "", "", 0, "CLIENT", nil)
	if err != nil {
		t.Fatalf("NewClientSecurityConfig: %v", err)
	}
	var sawFS bool
	for _, m := range cfg.AuthMethods {
		if m == security.AuthFS {
			sawFS = true
		}
	}
	if !sawFS {
		t.Errorf("without a token the daemon's own methods should be intact, including FS; got %v", cfg.AuthMethods)
	}
}

// delegatedTestConfig is a daemon's client configuration that carries a
// credential of its own for every method that can have one, at the
// configured default authentication level of OPTIONAL.
func delegatedTestConfig(t *testing.T, sysDir string) *config.Config {
	t.Helper()
	return mustConfig(t, fmt.Sprintf(`
SEC_CLIENT_AUTHENTICATION = OPTIONAL
SEC_CLIENT_AUTHENTICATION_METHODS = FS,IDTOKENS,PASSWORD,KERBEROS,SCITOKENS,SSL,ANONYMOUS
SEC_TOKEN_SYSTEM_DIRECTORY = %s
AUTH_SSL_CLIENT_CERTFILE = /etc/condor/hostcert.pem
AUTH_SSL_CLIENT_KEYFILE = /etc/condor/hostkey.pem
AUTH_SSL_CLIENT_CAFILE = /etc/condor/ca.pem
`, sysDir))
}

// forceDaemon makes runningAsDaemon report true for the rest of the test,
// as it does for any process started by condor_master.
func forceDaemon(t *testing.T) {
	t.Helper()
	restore := runningAsDaemon
	t.Cleanup(func() { runningAsDaemon = restore })
	runningAsDaemon = func() bool { return true }
}

// TestDelegatedSecurityConfigCarriesOnlyTheToken: a config built for a
// caller's token must not carry any of the daemon's own credentials. Cedar
// treats Token as the first candidate rather than the only one -- an
// incompatible or expired Token sends it on to TokenFile and TokenDir --
// and the SSL handshake presents CertFile/KeyFile, so any of those left set
// lets the connection authenticate as this process instead of the caller.
//
// The other direction is asserted too: with no token the connection is the
// daemon's own and keeps every configured credential.
func TestDelegatedSecurityConfigCarriesOnlyTheToken(t *testing.T) {
	forceDaemon(t)
	sysDir := t.TempDir()
	cfg := delegatedTestConfig(t, sysDir)

	got, err := NewClientSecurityConfigWithConfig(t.Context(), cfg, "a.token.value", "<127.0.0.1:9618>", 0, "CLIENT", nil)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if got.Token != "a.token.value" {
		t.Errorf("Token = %q, want the caller's", got.Token)
	}
	if got.TokenDir != "" || got.TokenFile != "" {
		t.Errorf("TokenDir = %q, TokenFile = %q; a delegated config must not carry the daemon's token store", got.TokenDir, got.TokenFile)
	}
	if got.CertFile != "" || got.KeyFile != "" {
		t.Errorf("CertFile = %q, KeyFile = %q; a delegated config must not present the daemon's certificate", got.CertFile, got.KeyFile)
	}
	if got.CAFile != "/etc/condor/ca.pem" {
		t.Errorf("CAFile = %q; the server's certificate should still be verified", got.CAFile)
	}
	if want := []security.AuthMethod{security.AuthToken, security.AuthSciTokens, security.AuthSSL}; !slices.Equal(got.AuthMethods, want) {
		t.Errorf("AuthMethods = %v, want %v", got.AuthMethods, want)
	}
	if got.Authentication != security.SecurityRequired {
		t.Errorf("Authentication = %q, want REQUIRED", got.Authentication)
	}

	// The daemon's own path, same configuration.
	daemon, err := NewClientSecurityConfigWithConfig(WithDaemonCredential(t.Context(), "test"), cfg, "", "<127.0.0.1:9618>", 0, "CLIENT", nil)
	if err != nil {
		t.Fatalf("no token: %v", err)
	}
	if daemon.TokenDir != sysDir {
		t.Errorf("daemon TokenDir = %q, want %q", daemon.TokenDir, sysDir)
	}
	if daemon.CertFile != "/etc/condor/hostcert.pem" || daemon.KeyFile != "/etc/condor/hostkey.pem" {
		t.Errorf("daemon CertFile = %q, KeyFile = %q, want the configured pair", daemon.CertFile, daemon.KeyFile)
	}
	if !slices.Contains(daemon.AuthMethods, security.AuthFS) || !slices.Contains(daemon.AuthMethods, security.AuthNone) {
		t.Errorf("daemon AuthMethods = %v, want the configured list", daemon.AuthMethods)
	}
	if daemon.Authentication != security.SecurityOptional {
		t.Errorf("daemon Authentication = %q, want the configured OPTIONAL", daemon.Authentication)
	}
}

// newTokenDaemon starts a CEDAR server for trust domain "pool.example" that
// accepts only TOKEN, verified with the pool signing key in keyDir, and
// answers DC_NOP.
func newTokenDaemon(t *testing.T, keyDir string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // test-only loopback listener
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := cedarserver.New(&security.SecurityConfig{
		AuthMethods:             []security.AuthMethod{security.AuthToken},
		Authentication:          security.SecurityRequired,
		CryptoMethods:           []security.CryptoMethod{security.CryptoAES},
		Encryption:              security.SecurityOptional,
		Integrity:               security.SecurityOptional,
		TrustDomain:             "pool.example",
		TokenPoolSigningKeyFile: filepath.Join(keyDir, "POOL"),
		SessionCache:            security.NewSessionCache(),
	})
	srv.Handle(int(commands.DC_NOP), func(context.Context, *cedarserver.Conn) error { return nil }, "READ")
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx, ln) }()
	t.Cleanup(func() { cancel(); _ = ln.Close() })
	return fmt.Sprintf("<%s>", ln.Addr().String())
}

// TestDelegatedTokenDoesNotFallBackToDaemonTokens runs the handshake. The
// daemon's system token directory holds a token the server accepts; the
// caller's token comes from another issuer, so cedar finds it incompatible.
// That must fail the connection, not authenticate it as the daemon. A
// caller token the server does accept authenticates as the caller, and the
// daemon's own path still authenticates with the directory's token.
func TestDelegatedTokenDoesNotFallBackToDaemonTokens(t *testing.T) {
	forceDaemon(t)
	keyDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(keyDir, "POOL"), []byte("delegated-token-fallback-test-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	mint := func(sub, iss string) string {
		t.Helper()
		now := time.Now().Unix()
		tok, err := security.GenerateJWT(keyDir, "POOL", sub, iss, now, now+3600, nil)
		if err != nil {
			t.Fatalf("GenerateJWT: %v", err)
		}
		return tok
	}
	sysDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(sysDir, "condor"), []byte(mint("condor@pool.example", "pool.example")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := mustConfig(t, fmt.Sprintf(`
SEC_CLIENT_AUTHENTICATION_METHODS = IDTOKENS
SEC_CLIENT_CRYPTO_METHODS = AES
SEC_TOKEN_SYSTEM_DIRECTORY = %s
`, sysDir))

	ping := func(ctx context.Context, token string) (*PingResult, error) {
		t.Helper()
		// Each ping gets its own daemon, so no session is resumed.
		addr := newTokenDaemon(t, keyDir)
		if token != "" {
			sec, err := NewClientSecurityConfigWithConfig(ctx, cfg, token, addr, int(commands.DC_NOP), "CLIENT", nil)
			if err != nil {
				t.Fatalf("NewClientSecurityConfigWithConfig: %v", err)
			}
			ctx = WithSecurityConfig(ctx, sec)
		}
		return NewSchedd("fake", addr).WithConfig(cfg).Ping(ctx)
	}

	res, err := ping(daemonContext(t), mint("alice@other.example", "other.example"))
	if err == nil {
		t.Fatalf("an incompatible caller token authenticated as %q; it fell back to the daemon's token directory", res.User)
	}

	res, err = ping(daemonContext(t), mint("alice@pool.example", "pool.example"))
	if err != nil {
		t.Fatalf("compatible caller token: %v", err)
	}
	if res.User != "alice@pool.example" {
		t.Errorf("compatible caller token authenticated as %q, want alice@pool.example", res.User)
	}

	res, err = ping(daemonContext(t), "")
	if err != nil {
		t.Fatalf("daemon path: %v", err)
	}
	if res.User != "condor@pool.example" {
		t.Errorf("daemon path authenticated as %q, want condor@pool.example", res.User)
	}
}
