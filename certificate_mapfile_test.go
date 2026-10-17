package htcondor

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
	"github.com/golang-jwt/jwt/v5"
)

// issuerMapLine is a SCITOKENS line mapping every subject of
// https://issuer.example to itself, in the /regex/ form that
// CERTIFICATE_MAPFILE_ASSUME_HASH_KEYS = true reads as a regular expression.
const issuerMapLine = `SCITOKENS /^https:\/\/issuer\.example,(.*)$/ \1`

// writeMapFile writes a CERTIFICATE_MAPFILE and returns its path.
func writeMapFile(t *testing.T, dir, text string) string {
	t.Helper()
	path := filepath.Join(dir, "certificate_mapfile")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func serverConfigWith(t *testing.T, text string) *security.SecurityConfig {
	t.Helper()
	sc, err := GetServerSecurityConfig(mustConfig(t, text), int(commands.DC_NOP), "DEFAULT")
	if err != nil {
		t.Fatal(err)
	}
	return sc
}

func TestServerSecurityConfigMapsSciTokens(t *testing.T) {
	path := writeMapFile(t, t.TempDir(), issuerMapLine+"\n")
	sc := serverConfigWith(t, fmt.Sprintf(`
CERTIFICATE_MAPFILE = %s
CERTIFICATE_MAPFILE_ASSUME_HASH_KEYS = true
`, path))
	if sc.SciTokensMapper == nil {
		t.Fatal("SciTokensMapper is nil with CERTIFICATE_MAPFILE set")
	}
	if user, ok := sc.SciTokensMapper("https://issuer.example,alice"); !ok || user != "alice" {
		t.Errorf("map(https://issuer.example,alice) = %q, %v; want alice, true", user, ok)
	}
	for _, name := range []string{"https://other.example,alice", "http://issuer.example,alice"} {
		if user, ok := sc.SciTokensMapper(name); ok {
			t.Errorf("map(%s) = %q; want it refused", name, user)
		}
	}
}

func TestServerSecurityConfigWithoutMapFileRefusesSciTokens(t *testing.T) {
	sc := serverConfigWith(t, "SEC_DEFAULT_AUTHENTICATION_METHODS = SCITOKENS\n")
	if sc.SciTokensMapper != nil {
		t.Error("SciTokensMapper is set without CERTIFICATE_MAPFILE; cedar must refuse every SciToken")
	}

	// A map file that cannot be read is no map file.
	sc = serverConfigWith(t, "CERTIFICATE_MAPFILE = "+filepath.Join(t.TempDir(), "missing")+"\n")
	if user, ok := sc.SciTokensMapper("https://issuer.example,alice"); ok {
		t.Errorf("an unreadable map file mapped a SciToken to %q", user)
	}
}

// CERTIFICATE_MAPFILE_ASSUME_HASH_KEYS defaults to false, which makes every
// principal a regular expression with slashes as ordinary characters
// (Authentication::load_map_file). When true, only /.../ is a regular
// expression and anything else is a literal.
func TestSciTokensMapperRegexKeysFollowAssumeHashKeys(t *testing.T) {
	dir := t.TempDir()
	path := writeMapFile(t, dir, issuerMapLine+"\n"+
		`SCITOKENS ^https://bare\.example,(.*)$ bare-\1`+"\n")
	const slashed, bare = "https://issuer.example,alice", "https://bare.example,bob"

	for _, tc := range []struct {
		knob                  string
		wantSlashed, wantBare string
	}{
		{knob: "", wantSlashed: "", wantBare: "bare-bob"},
		{knob: "CERTIFICATE_MAPFILE_ASSUME_HASH_KEYS = false", wantSlashed: "", wantBare: "bare-bob"},
		{knob: "CERTIFICATE_MAPFILE_ASSUME_HASH_KEYS = true", wantSlashed: "alice", wantBare: ""},
	} {
		sc := serverConfigWith(t, "CERTIFICATE_MAPFILE = "+path+"\n"+tc.knob+"\n")
		for name, want := range map[string]string{slashed: tc.wantSlashed, bare: tc.wantBare} {
			got, ok := sc.SciTokensMapper(name)
			if want == "" && ok {
				t.Errorf("%q: map(%s) = %q; want it refused", tc.knob, name, got)
			}
			if want != "" && (!ok || got != want) {
				t.Errorf("%q: map(%s) = %q, %v; want %q", tc.knob, name, got, ok, want)
			}
		}
	}
}

func TestSciTokensMapperFollowsInclude(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "maps.d"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "maps.d", "10-issuer"), []byte(issuerMapLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Skipped as LOCAL_CONFIG_DIR_EXCLUDE_REGEXP skips it in HTCondor.
	if err := os.WriteFile(filepath.Join(dir, "maps.d", "20-other.rpmsave"),
		[]byte(`SCITOKENS /^https:\/\/other\.example,(.*)$/ \1`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := writeMapFile(t, dir, "@include maps.d\n")
	sc := serverConfigWith(t, "CERTIFICATE_MAPFILE = "+path+"\nCERTIFICATE_MAPFILE_ASSUME_HASH_KEYS = true\n")
	if user, ok := sc.SciTokensMapper("https://issuer.example,alice"); !ok || user != "alice" {
		t.Errorf("included line: map = %q, %v; want alice", user, ok)
	}
	if user, ok := sc.SciTokensMapper("https://other.example,alice"); ok {
		t.Errorf("excluded file mapped %q", user)
	}
}

func TestSciTokensMapperRefusesPlugin(t *testing.T) {
	path := writeMapFile(t, t.TempDir(), `SCITOKENS /^https:\/\/issuer\.example,/ PLUGIN:*`+"\n")
	sc := serverConfigWith(t, "CERTIFICATE_MAPFILE = "+path+"\nCERTIFICATE_MAPFILE_ASSUME_HASH_KEYS = true\n")
	if user, ok := sc.SciTokensMapper("https://issuer.example,alice"); ok {
		t.Errorf("PLUGIN mapping accepted as %q", user)
	}
}

// The map file is re-read when it changes, and when ReloadCertificateMapFile
// (reconfig) runs, which also picks up included files.
func TestSciTokensMapperReloads(t *testing.T) {
	dir := t.TempDir()
	inc := filepath.Join(dir, "included")
	if err := os.WriteFile(inc, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	path := writeMapFile(t, dir, "@include "+inc+"\n")
	sc := serverConfigWith(t, "CERTIFICATE_MAPFILE = "+path+"\nCERTIFICATE_MAPFILE_ASSUME_HASH_KEYS = true\n")
	const name = "https://issuer.example,alice"
	if _, ok := sc.SciTokensMapper(name); ok {
		t.Fatal("mapped before any SCITOKENS line exists")
	}

	// Changing the map file itself is seen without a reconfig.
	if err := os.WriteFile(path, []byte("@include "+inc+"\n"+issuerMapLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if user, ok := sc.SciTokensMapper(name); !ok || user != "alice" {
		t.Fatalf("after editing the map file: map = %q, %v; want alice", user, ok)
	}

	// Removing it again is seen too.
	if err := os.WriteFile(path, []byte("@include "+inc+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if user, ok := sc.SciTokensMapper(name); ok {
		t.Fatalf("after removing the line: map = %q; want it refused", user)
	}

	// An included file is re-read on reconfig, as HTCondor re-reads it,
	// not when only it changes.
	if err := os.WriteFile(inc, []byte(`SCITOKENS /^https:\/\/issuer\.example,(.*)$/ new-\1`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if user, ok := sc.SciTokensMapper(name); ok {
		t.Fatalf("included file re-read without a reconfig (mapped %q)", user)
	}
	ReloadCertificateMapFile()
	if user, ok := sc.SciTokensMapper(name); !ok || user != "new-alice" {
		t.Errorf("after ReloadCertificateMapFile: map = %q, %v; want new-alice", user, ok)
	}
}

func TestServerSecurityConfigSciTokensAudience(t *testing.T) {
	if sc := serverConfigWith(t, "\n"); len(sc.SciTokensServerAudience) != 0 {
		t.Errorf("default SciTokensServerAudience = %q; want none", sc.SciTokensServerAudience)
	}
	sc := serverConfigWith(t, "SCITOKENS_SERVER_AUDIENCE = https://a.example, https://b.example\n")
	if want := []string{"https://a.example", "https://b.example"}; !slices.Equal(sc.SciTokensServerAudience, want) {
		t.Errorf("SciTokensServerAudience = %q; want %q", sc.SciTokensServerAudience, want)
	}
}

func TestServerSecurityConfigForeignTokenIssuers(t *testing.T) {
	// HTCondor's defaults: SEC_SCITOKENS_ALLOW_FOREIGN_TOKEN_TYPES = true and
	// SEC_SCITOKENS_FOREIGN_TOKEN_ISSUERS = https://aai-dev.egi.eu/auth/realms/egi.
	sc := serverConfigWith(t, "\n")
	if want := []string{"https://aai-dev.egi.eu/auth/realms/egi"}; !slices.Equal(sc.SciTokensForeignTokenIssuers, want) {
		t.Errorf("default SciTokensForeignTokenIssuers = %q; want %q", sc.SciTokensForeignTokenIssuers, want)
	}
	sc = serverConfigWith(t, "SEC_SCITOKENS_FOREIGN_TOKEN_ISSUERS = *\n")
	if want := []string{"*"}; !slices.Equal(sc.SciTokensForeignTokenIssuers, want) {
		t.Errorf("SciTokensForeignTokenIssuers = %q; want %q", sc.SciTokensForeignTokenIssuers, want)
	}
	sc = serverConfigWith(t, "SEC_SCITOKENS_ALLOW_FOREIGN_TOKEN_TYPES = false\nSEC_SCITOKENS_FOREIGN_TOKEN_ISSUERS = *\n")
	if sc.SciTokensForeignTokenIssuers != nil {
		t.Errorf("SciTokensForeignTokenIssuers = %q with foreign tokens disallowed; want nil", sc.SciTokensForeignTokenIssuers)
	}
}

func TestTCPSessionDeadline(t *testing.T) {
	for text, want := range map[string]time.Duration{
		"":                              120 * time.Second,
		"SEC_TCP_SESSION_DEADLINE = 30": 30 * time.Second,
		"SEC_TCP_SESSION_DEADLINE = -1": 0,
		"SEC_TCP_SESSION_DEADLINE = x":  120 * time.Second,
	} {
		if got := TCPSessionDeadline(mustConfig(t, text+"\n")); got != want {
			t.Errorf("%q: TCPSessionDeadline = %v; want %v", text, got, want)
		}
	}
}

// TestSciTokensHandshakeThroughServerConfig runs a Go client's SCITOKENS
// handshake against a cedar server whose config GetServerSecurityConfig
// built, with a TLS issuer. The peer is the user the map file names, with
// UID_DOMAIN; a token from an issuer the map file does not name is refused.
func TestSciTokensHandshakeThroughServerConfig(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var issuer *httptest.Server
	issuer = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(security.OIDCConfiguration{Issuer: issuer.URL, JWKSURI: issuer.URL + "/jwks"})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(security.JWKS{Keys: []security.JWK{{
				Kty: "RSA", Kid: "test-key", Use: "sig", Alg: "RS256",
				N: base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(issuer.Close)
	sign := func(iss string) string {
		now := time.Now()
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss": iss, "sub": "alice", "scope": "condor:/READ condor:/WRITE",
			"iat": now.Add(-time.Minute).Unix(), "nbf": now.Add(-time.Minute).Unix(),
			"exp": now.Add(time.Hour).Unix(),
		})
		tok.Header["kid"] = "test-key"
		s, err := tok.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	dir := t.TempDir()
	caCert, caKey := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	if err := security.GenerateTestCA(caCert, caKey); err != nil {
		t.Fatal(err)
	}
	hostCert, hostKey := filepath.Join(dir, "host.crt"), filepath.Join(dir, "host.key")
	if err := security.GenerateTestHostCert(hostCert, hostKey, caCert, caKey, "localhost"); err != nil {
		t.Fatal(err)
	}
	issuerRegex := strings.ReplaceAll(regexp.QuoteMeta(issuer.URL), "/", `\/`)
	mapPath := writeMapFile(t, dir, fmt.Sprintf("SCITOKENS /^%s,(.*)$/ \\1\n", issuerRegex))
	cfg := mustConfig(t, fmt.Sprintf(`
SEC_DEFAULT_AUTHENTICATION = REQUIRED
SEC_DEFAULT_AUTHENTICATION_METHODS = SCITOKENS
SEC_CLIENT_AUTHENTICATION_METHODS = SCITOKENS
AUTH_SSL_SERVER_CERTFILE = %s
AUTH_SSL_SERVER_KEYFILE = %s
AUTH_SSL_CLIENT_CAFILE = %s
CERTIFICATE_MAPFILE = %s
CERTIFICATE_MAPFILE_ASSUME_HASH_KEYS = true
UID_DOMAIN = pool.example
`, hostCert, hostKey, caCert, mapPath))

	sc, err := GetServerSecurityConfig(cfg, int(commands.DC_NOP), "DEFAULT")
	if err != nil {
		t.Fatal(err)
	}
	sc.SessionCache = security.NewSessionCache()
	sc.SciTokensHTTPClient = issuer.Client() // trusts the test issuer's certificate
	users := make(chan string, 1)
	srv := cedarserver.New(sc)
	srv.Handle(int(commands.DC_NOP), func(_ context.Context, c *cedarserver.Conn) error {
		users <- c.Negotiation.User
		return nil
	}, "READ")
	ln, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // test-only loopback listener
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	go func() { _ = srv.Serve(ctx, ln) }()
	t.Cleanup(func() { _ = ln.Close() })

	handshake := func(token string) error {
		cc, err := GetSecurityConfig(cfg, int(commands.DC_NOP), "CLIENT")
		if err != nil {
			t.Fatal(err)
		}
		cc.SessionCache = security.NewSessionCache()
		cc.ServerName = "localhost"
		cc.Token = token
		hc, err := client.ConnectAndAuthenticate(ctx, fmt.Sprintf("<%s>", ln.Addr()), cc)
		if err != nil {
			return err
		}
		return hc.Close()
	}

	if err := handshake(sign(issuer.URL)); err != nil {
		t.Fatalf("SCITOKENS handshake with a mapped token: %v", err)
	}
	select {
	case user := <-users:
		if user != "alice@pool.example" {
			t.Errorf("peer authenticated as %q; want alice@pool.example", user)
		}
	case <-ctx.Done():
		t.Fatal("handler never ran")
	}

	if err := handshake(sign("https://unmapped.example")); err == nil {
		user := ""
		select {
		case user = <-users:
		default:
		}
		t.Errorf("SCITOKENS handshake with an unmapped issuer succeeded (peer %q)", user)
	}
}
