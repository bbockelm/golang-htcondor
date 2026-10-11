package httpserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/logging"
)

func clientConfigFrom(t *testing.T, text string) *config.Config {
	t.Helper()
	cfg, err := config.NewFromReader(strings.NewReader(text))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	return cfg
}

// TestConfigureSecurityForTokenReadsClientConfig shows the token builder the
// Handler uses takes its configured base from the server's ClientConfig, with
// the session-mode FS rule still applied on top.
func TestConfigureSecurityForTokenReadsClientConfig(t *testing.T) {
	cfg := clientConfigFrom(t, "SEC_CLIENT_AUTHENTICATION_METHODS = FS,KERBEROS,SCITOKENS,SSL\n")

	got, err := configureSecurityForToken(cfg, createTestJWTToken(3600), nil, false)
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	want := []security.AuthMethod{security.AuthToken, security.AuthSciTokens, security.AuthSSL}
	if !slices.Equal(got.AuthMethods, want) {
		t.Errorf("AuthMethods = %v, want %v", got.AuthMethods, want)
	}
}

func TestConfigureSecurityForCollectorPingReadsClientConfig(t *testing.T) {
	cfg := clientConfigFrom(t, "AUTH_SSL_CLIENT_CERTFILE = /pool/cert\nAUTH_SSL_CLIENT_KEYFILE = /pool/key\nAUTH_SSL_CLIENT_CAFILE = /pool/ca\n")

	got, err := configureSecurityForCollectorPing(cfg, "", "collector.example.org")
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	if got.CertFile != "/pool/cert" || got.KeyFile != "/pool/key" || got.CAFile != "/pool/ca" {
		t.Errorf("SSL credentials = (%q, %q, %q), want the ClientConfig's", got.CertFile, got.KeyFile, got.CAFile)
	}
}

// TestFindCreddAddressFileUsesServerConfig shows the local credd address file
// comes from the configuration handed in, not from $CONDOR_CONFIG.
func TestFindCreddAddressFileUsesServerConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".credd_address")
	if err := os.WriteFile(path, []byte("<127.0.0.1:1234>\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := clientConfigFrom(t, "CREDD_ADDRESS_FILE = "+path+"\n")
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatal(err)
	}

	if got := findCreddAddressFile(cfg, logger); got != path {
		t.Errorf("findCreddAddressFile = %q, want %q", got, path)
	}
	if got := localCreddAddress(cfg, logger); got != "<127.0.0.1:1234>" {
		t.Errorf("localCreddAddress = %q", got)
	}
}

// newPoolTokenDaemon starts a CEDAR server for trust domain "pool.example"
// that accepts only TOKEN, verified with the pool signing key in keyDir,
// and answers DC_NOP and DC_NOP_READ.
func newPoolTokenDaemon(t *testing.T, keyDir string) string {
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
	nop := func(context.Context, *cedarserver.Conn) error { return nil }
	srv.Handle(int(commands.DC_NOP), nop, "READ")
	// The identity ping (pingAsCaller) sends DC_NOP_READ, which DaemonCore
	// registers at READ; an unregistered command is refused CMD_NOT_FOUND.
	srv.Handle(int(commands.DC_NOP_READ), nop, "READ")
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx, ln) }()
	t.Cleanup(func() { cancel(); _ = ln.Close() })
	return fmt.Sprintf("<%s>", ln.Addr().String())
}

// TestBearerAuthenticatesOnlyAsTheBearer drives bearer requests through
// createAuthenticatedContext against a schedd that accepts this server's
// own token, which sits in the configured token directory, but not a
// bearer from another issuer. The SecurityConfig put on the context must
// present the bearer and nothing of the server's: no token store (cedar
// sends a token from it when the bearer is incompatible with the peer), no
// SSL client certificate, no method that identifies the process, and
// authentication REQUIRED rather than the configured OPTIONAL. The
// request's identity, which createAuthenticatedContext resolves by asking
// the schedd who the connection is, must then be the bearer's subject for
// one the schedd accepts, and the foreign bearer must be refused as
// unidentified -- not authenticated as the server.
func TestBearerAuthenticatesOnlyAsTheBearer(t *testing.T) {
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	keyDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(keyDir, "POOL"), []byte("bearer-only-test-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	mint := func(sub string) string {
		t.Helper()
		now := time.Now().Unix()
		tok, err := security.GenerateJWT(keyDir, "POOL", sub, "pool.example", now, now+3600, nil)
		if err != nil {
			t.Fatalf("GenerateJWT: %v", err)
		}
		return tok
	}
	tokenDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tokenDir, "condor"), []byte(mint("condor@pool.example")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := clientConfigFrom(t, `
SEC_CLIENT_AUTHENTICATION = OPTIONAL
SEC_CLIENT_AUTHENTICATION_METHODS = FS,IDTOKENS,KERBEROS,SSL,ANONYMOUS
SEC_CLIENT_CRYPTO_METHODS = AES
SEC_TOKEN_DIRECTORY = `+tokenDir+`
AUTH_SSL_CLIENT_CERTFILE = /etc/condor/hostcert.pem
AUTH_SSL_CLIENT_KEYFILE = /etc/condor/hostkey.pem
`)

	authenticate := func(bearer string) (context.Context, error) {
		t.Helper()
		// A fresh daemon per request, so no session is resumed.
		addr := newPoolTokenDaemon(t, keyDir)
		h := &Handler{
			logger:       logger,
			tokenCache:   NewTokenCache(),
			clientConfig: cfg,
			schedd:       htcondor.NewSchedd("fake", addr).WithConfig(cfg),
		}
		r := httptest.NewRequestWithContext(context.Background(), "GET", "/api/v1/jobs", nil)
		r.Header.Set("Authorization", "Bearer "+bearer)
		return h.createAuthenticatedContext(r)
	}

	// createTestJWTToken's issuer is test.domain, not this pool's. The
	// schedd is asked who the connection is and names nobody, so the
	// request is refused; had cedar fallen back to the token directory,
	// the connection would have authenticated as condor.
	ctx, err := authenticate(createTestJWTToken(3600))
	if !errors.Is(err, errUnidentifiedCaller) {
		t.Errorf("a bearer from another issuer: err = %v, want errUnidentifiedCaller", err)
	}
	if ctx != nil {
		t.Errorf("a bearer from another issuer authenticated as %q", htcondor.GetAuthenticatedUserFromContext(ctx))
	}

	alice := mint("alice@pool.example")
	ctx, err = authenticate(alice)
	if err != nil {
		t.Fatalf("createAuthenticatedContext: %v", err)
	}
	if user := htcondor.GetAuthenticatedUserFromContext(ctx); user != "alice@pool.example" {
		t.Errorf("a bearer the schedd accepts authenticated as %q, want alice@pool.example", user)
	}
	got, ok := htcondor.GetSecurityConfigFromContext(ctx)
	if !ok {
		t.Fatal("no SecurityConfig on the authenticated context")
	}
	if got.Token != alice {
		t.Error("the bearer is not the token on the SecurityConfig")
	}
	if got.TokenDir != "" || got.TokenFile != "" {
		t.Errorf("TokenDir = %q, TokenFile = %q; the server's token store is reachable from a bearer request", got.TokenDir, got.TokenFile)
	}
	if got.CertFile != "" || got.KeyFile != "" {
		t.Errorf("CertFile = %q, KeyFile = %q; the server's certificate is presented on a bearer request", got.CertFile, got.KeyFile)
	}
	if want := []security.AuthMethod{security.AuthToken, security.AuthSSL}; !slices.Equal(got.AuthMethods, want) {
		t.Errorf("AuthMethods = %v, want %v", got.AuthMethods, want)
	}
	if got.Authentication != security.SecurityRequired {
		t.Errorf("Authentication = %q, want REQUIRED", got.Authentication)
	}
}
