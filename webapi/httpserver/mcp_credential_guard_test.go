package httpserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/mcpserver"
)

// An OAuth2 caller reaching MCP with no way to mint a credential is
// refused, rather than handed a context that carries none.
//
// A context with no credential is not unauthenticated downstream. It is
// THIS DAEMON: GetSecurityConfigOrDefault falls through to the daemon's
// own configuration, a queue superuser on a normal access point. So the
// tools would have run as the service account, and owner scoping would
// not have caught it -- mcpAuthContext resolves the caller by asking the
// schedd who the connection is, on that same context, so the schedd
// answers with the daemon's name and that is what gets scoped to.
func TestOAuth2CallerIsRefusedWithoutASigningKey(t *testing.T) {
	for _, tc := range []struct{ name, signingKey, trust string }{
		{"neither", "", ""},
		{"no signing key", "", "flock.example.org"},
		{"no trust domain", "key-path", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &Handler{
				logger:         testLogger(t),
				signingKeyPath: tc.signingKey,
				trustDomain:    tc.trust,
			}
			_, err := h.withCondorCredential(context.Background(), "bbockelm", []string{"condor:/WRITE"})
			if err == nil {
				t.Fatal("a caller with no mintable credential was handed a context anyway; " +
					"every CEDAR call it made would authenticate as this daemon")
			}
			// The error has to name what to set, or an operator meeting
			// it in a log learns only that something is wrong.
			if !strings.Contains(err.Error(), "HTTP_API_SIGNING_KEY") {
				t.Errorf("the refusal does not say what to configure: %v", err)
			}
		})
	}
}

// A site that proxies MCP and forwards an HTCondor token on every request
// keeps working with no signing key configured at all.
//
// This is the case an earlier version of this change broke. It refused to
// START when MCP was enabled without a signing key -- but /mcp is only
// registered when an OAuth2 provider exists, so a forwarding deployment
// has one too and could not be told apart by configuration. Its requests
// never reach withCondorCredential: the forwarded branch builds its own
// security config from the bearer and lets the schedd validate it, which
// is the whole point of forwarding.
func TestForwardedTokenNeedsNoSigningKey(t *testing.T) {
	// TRUST_DOMAIN but no signing key: exactly the shape of a proxying
	// deployment. The trust domain is what lets a forwarded token be
	// recognised as a pool IDTOKEN rather than 401'd; the signing key is
	// only ever used to MINT, which this path never does.
	const trustDomain = "flock.example.org"
	s := newMCPServer(t, "", trustDomain)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+poolIDToken(trustDomain, "bbockelm"))
	// Every caller of this endpoint names it; see mcpserver.AcceptHeader.
	req.Header.Set("Accept", mcpserver.AcceptHeader)
	rec := httptest.NewRecorder()

	ctx, token, ok := s.mcpAuthContext(rec, req)
	if !ok {
		t.Fatalf("a forwarded HTCondor token was refused with no signing key configured: %d %s",
			rec.Code, rec.Body.String())
	}
	if token != nil {
		t.Fatal("the forwarded-token branch should not produce an OAuth2 token")
	}
	// And it carries the caller's own credential, built from the bearer --
	// not the absence of one, which is what would run as this daemon.
	if _, hasCred := htcondor.GetSecurityConfigFromContext(ctx); !hasCred {
		t.Fatal("the forwarded token produced a context with no credential")
	}
}

// Enabling MCP without a signing key starts, and says why in the log.
//
// Deliberately not fatal, unlike startSSHGateway's check of the same two
// settings: the gateway has one way in and it must mint, while MCP has
// two and only one of them does. See warnIfMCPCannotMintCredentials.
func TestMCPWithoutASigningKeyStillStarts(t *testing.T) {
	s := newMCPServer(t, "", "")
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	if err := s.Handler.Start(t.Context(), ln, "http"); err != nil {
		t.Fatalf("a deployment that forwards HTCondor tokens was refused startup: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})
}

func newMCPServer(t *testing.T, signingKey, trustDomain string) *Server {
	t.Helper()
	s, err := NewServer(Config{
		Logger:         testLogger(t),
		ScheddName:     "test-schedd",
		ScheddAddr:     "127.0.0.1:9618",
		OAuth2DBPath:   t.TempDir() + "/oauth2.db",
		EnableMCP:      true,
		SigningKeyPath: signingKey,
		TrustDomain:    trustDomain,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	// Preconditions, or these tests pass for the wrong reason.
	if s.oauth2Provider == nil {
		t.Fatal("precondition: no OAuth2 provider, so the MCP endpoint is not registered")
	}
	if s.Handler.mcpServer == nil {
		t.Fatal("precondition: no MCP server, so no tool call can reach HTCondor")
	}
	return s
}

// poolIDToken builds an unsigned JWT that classifies as a forwarded pool
// IDTOKEN: an `iss` matching the trust domain, and a `kid`, which is what
// inspectToken distinguishes a HTCondor token by. Never verified here --
// the schedd is what checks the signature, which is the whole reason this
// path forwards rather than minting.
func poolIDToken(issuer, subject string) string {
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			panic(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	header := enc(map[string]string{"alg": "HS256", "kid": "POOL"})
	claims := enc(map[string]string{"iss": issuer, "sub": subject})
	return header + "." + claims + "." + base64.RawURLEncoding.EncodeToString([]byte("not-verified-here"))
}
