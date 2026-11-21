package httpserver

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	htcondor "github.com/htcondor/golang-htcondor"
	"github.com/htcondor/golang-htcondor/logging"
	"github.com/htcondor/golang-htcondor/webapi/mcpserver"
)

// HTTP_API_MCP_OAUTH2 = false: MCP served with the forwarded-token path
// alone.
//
// The deployment this is for sits behind a gateway that forwards a
// per-user HTCondor IDTOKEN on every request, and deliberately holds no
// pool signing key. Every OAuth2 endpoint it served was one it could not
// honour -- withCondorCredential refuses without a key -- so they were
// surface with nothing behind them.

const forwardOnlyTrustDomain = "forward-only.example.org"

// newForwardOnlyMCPServer is newMCPServer with OAuth2 withdrawn: MCP on,
// no web UI, no signing key, a trust domain so a forwarded token is
// recognisable as a pool IDTOKEN.
func newForwardOnlyMCPServer(t *testing.T, logger *logging.Logger) *Server {
	t.Helper()
	if logger == nil {
		logger = testLogger(t)
	}
	s, err := NewServer(Config{
		Logger:            logger,
		ScheddName:        "test-schedd",
		ScheddAddr:        "127.0.0.1:9618",
		OAuth2DBPath:      t.TempDir() + "/oauth2.db",
		EnableMCP:         true,
		MCPOAuth2Disabled: true,
		TrustDomain:       forwardOnlyTrustDomain,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if s.oauth2Provider != nil {
		t.Fatal("precondition: the OAuth2 provider was built anyway, so nothing below is being tested")
	}
	if s.Handler.mcpServer == nil {
		t.Fatal("precondition: no MCP server, so no tool call can reach HTCondor")
	}
	return s
}

// startForwardOnly starts the server, which is what builds the mux, and
// returns it ready to take requests.
func startForwardOnly(t *testing.T, s *Server) *Server {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	if err := s.Handler.Start(t.Context(), ln, "http"); err != nil {
		t.Fatalf("a forwarded-token-only deployment was refused startup: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})
	return s
}

// The protocol endpoint is still routed. It is the one thing this
// deployment needs, and before the setting existed it was registered only
// alongside an OAuth2 provider -- so withdrawing OAuth2 would have taken
// /mcp with it.
func TestMCPWithoutOAuth2StillRoutesTheEndpoint(t *testing.T) {
	s := startForwardOnly(t, newForwardOnlyMCPServer(t, nil))

	for _, path := range []string{mcpPath, mcpMessagePath, mcpSetupPath} {
		if !hasRoute(s, path) {
			t.Errorf("%s is not registered; the endpoint this deployment runs on is gone", path)
		}
	}

	// And a request to it is answered by MCP rather than by the mux's 404.
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, mcpPath, strings.NewReader("{}"))
	req.Header.Set("Accept", mcpserver.AcceptHeader)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code == http.StatusNotFound {
		t.Errorf("POST %s is a 404: %s", mcpPath, rec.Body.String())
	}
}

// A forwarded HTCondor token authenticates exactly as it does with OAuth2
// on: the schedd validates it, and the context carries the caller's own
// credential rather than this daemon's.
//
// This is the behaviour the setting promises to leave alone.
func TestMCPWithoutOAuth2AcceptsAForwardedToken(t *testing.T) {
	s := newForwardOnlyMCPServer(t, nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, mcpPath, strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+poolIDToken(forwardOnlyTrustDomain, "gatewayuser"))
	req.Header.Set("Accept", mcpserver.AcceptHeader)
	rec := httptest.NewRecorder()

	ctx, token, ok := s.mcpAuthContext(rec, req)
	if !ok {
		t.Fatalf("a forwarded HTCondor token was refused with OAuth2 off: %d %s", rec.Code, rec.Body.String())
	}
	if token != nil {
		t.Fatal("there is no authorization server here, so no request can produce an OAuth2 token")
	}
	if _, hasCred := htcondor.GetSecurityConfigFromContext(ctx); !hasCred {
		t.Fatal("the forwarded token produced a context with no credential, which runs as this daemon")
	}
}

// A request with no bearer at all is still refused. "No OAuth2" is not
// "no authentication".
func TestMCPWithoutOAuth2StillRefusesAnUnauthenticatedRequest(t *testing.T) {
	s := newForwardOnlyMCPServer(t, nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, mcpPath, strings.NewReader("{}"))
	req.Header.Set("Accept", mcpserver.AcceptHeader)
	rec := httptest.NewRecorder()

	if _, _, ok := s.mcpAuthContext(rec, req); ok {
		t.Fatal("a request carrying no credential was authenticated")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("an unauthenticated MCP request got %d, want 401", rec.Code)
	}
}

// None of the OAuth2 surface is registered: not the authorization server,
// not its discovery metadata, not dynamic client registration, and not
// the protected-resource documents that would name an authorization
// server for /mcp.
func TestMCPWithoutOAuth2ServesNoOAuth2Endpoints(t *testing.T) {
	s := startForwardOnly(t, newForwardOnlyMCPServer(t, nil))

	withdrawn := []string{
		"/.well-known/oauth-authorization-server",
		wellKnownProtectedResource,
		wellKnownProtectedResource + mcpPath,
		wellKnownProtectedResource + mcpMessagePath,
		"/oauth2/authorize",
		"/oauth2/token",
		"/oauth2/register",
		"/oauth2/introspect",
		"/oauth2/revoke",
		"/oauth2/device/authorize",
		webUICallbackPath,
		webUIDeviceVerifyPath,
		mcpCallbackPath,
		mcpDeviceVerifyPath,
		"/mcp/oauth2/authorize",
		"/mcp/oauth2/token",
		"/mcp/oauth2/register",
	}
	for _, path := range withdrawn {
		if hasRoute(s, path) {
			t.Errorf("%s is still registered; it is attack surface this deployment cannot honour", path)
		}
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s answered %d, want 404: %s", path, rec.Code, rec.Body.String())
		}
	}
}

// The startup warning about not being able to mint a credential is the
// expected state here, not a problem, so it is not logged.
//
// Checked against the log rather than against warnIfMCPCannotMintCredentials'
// early return: what an operator complained about is the line, and a
// future caller of the warning from somewhere else would reintroduce it
// without touching that return.
func TestMCPWithoutOAuth2LogsNoCredentialWarning(t *testing.T) {
	path := t.TempDir() + "/api.log"
	logger, err := logging.New(&logging.Config{
		OutputPath:        path,
		DefaultLevel:      logging.VerbosityDebug,
		SkipGlobalInstall: true,
	})
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}

	startForwardOnly(t, newForwardOnlyMCPServer(t, logger))

	logged, err := os.ReadFile(path) //nolint:gosec // this test's own temp file
	if err != nil {
		t.Fatalf("reading the log: %v", err)
	}
	if strings.Contains(string(logged), "no way to mint a per-caller HTCondor credential") {
		t.Error("the credential warning was logged on a deployment that never mints one; " +
			"this is the startup noise HTTP_API_MCP_OAUTH2 exists to remove")
	}
}

// The knob is opt-in: left alone, MCP serves OAuth2 exactly as it always
// has. A regression here is silent -- a site would simply stop being able
// to log in.
func TestMCPOAuth2IsOnByDefault(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  HandlerConfig
		want bool
	}{
		{"MCP alone", HandlerConfig{EnableMCP: true}, true},
		{"MCP with OAuth2 withdrawn", HandlerConfig{EnableMCP: true, MCPOAuth2Disabled: true}, false},
		{"web UI alone", HandlerConfig{WebUIEnabled: true}, true},
		// The web UI logs people in through OAuth2 whatever MCP does, so
		// withdrawing it from MCP must not take the UI's login with it.
		{"web UI with MCP OAuth2 withdrawn",
			HandlerConfig{WebUIEnabled: true, EnableMCP: true, MCPOAuth2Disabled: true}, true},
		{"neither", HandlerConfig{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.OAuth2Enabled(); got != tc.want {
				t.Errorf("OAuth2Enabled() = %v, want %v", got, tc.want)
			}
		})
	}
}

// With the web UI on, withdrawing OAuth2 from MCP leaves the UI's own
// OAuth2 whole and withdraws only what names MCP.
//
// The /mcp/ spelling of the endpoints is a login path like any other:
// serving it on a server whose MCP endpoint accepts no OAuth2 token
// advertises a flow that ends in a refusal.
func TestWebUIKeepsOAuth2WhenMCPWithdrawsIt(t *testing.T) {
	cfg := HandlerConfig{WebUIEnabled: true, EnableMCP: true, MCPOAuth2Disabled: true}
	if !cfg.OAuth2Enabled() {
		t.Fatal("the web UI lost its login because MCP withdrew OAuth2")
	}
	if cfg.MCPOAuth2Enabled() {
		t.Fatal("MCP still claims OAuth2 after it was withdrawn")
	}
	// Which spelling such a server advertises: the plain one, as any
	// server with a web UI does.
	if got := OAuth2CallbackPath(cfg.WebUIEnabled, cfg.MCPOAuth2Enabled()); got != webUICallbackPath {
		t.Errorf("callback path %q, want %q", got, webUICallbackPath)
	}
}

// hasRoute reports whether setupRoutes registered this exact pattern.
func hasRoute(s *Server, pattern string) bool {
	for _, p := range s.routePatterns {
		if p == pattern {
			return true
		}
	}
	return false
}

// The only configuration where the provider survives the setting: a web
// UI, which needs OAuth2 to log anybody in, beside an MCP endpoint that
// has withdrawn it.
//
// Here the setting has to mean the same thing it means without a web UI,
// or an operator who turned it off still has an OAuth2 way into MCP --
// one this server no longer advertises anywhere.
func TestWebUIOAuth2DoesNotOpenAWithdrawnMCP(t *testing.T) {
	s, err := NewServer(Config{
		Logger:            testLogger(t),
		ScheddName:        "test-schedd",
		ScheddAddr:        "127.0.0.1:9618",
		OAuth2DBPath:      t.TempDir() + "/oauth2.db",
		EnableMCP:         true,
		MCPOAuth2Disabled: true,
		WebUIEnabled:      true,
		TrustDomain:       forwardOnlyTrustDomain,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if s.oauth2Provider == nil {
		t.Fatal("precondition: the web UI lost its OAuth2, so nothing below is being tested")
	}
	startForwardOnly(t, s)

	// A token this server issued, with every MCP scope, is still refused
	// at /mcp.
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, mcpPath, strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+
		mintRESTAccessToken(t, s.Handler, "gatewayuser", []string{"mcp:read", "mcp:write"}))
	req.Header.Set("Accept", mcpserver.AcceptHeader)
	rec := httptest.NewRecorder()
	if _, _, ok := s.mcpAuthContext(rec, req); ok {
		t.Error("an OAuth2 token opened an MCP endpoint that serves no OAuth2")
	} else if rec.Code != http.StatusUnauthorized {
		t.Errorf("the refusal was %d, want 401: %s", rec.Code, rec.Body.String())
	}

	// A forwarded HTCondor token still works, which is the point.
	req = httptest.NewRequestWithContext(t.Context(), http.MethodPost, mcpPath, strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+poolIDToken(forwardOnlyTrustDomain, "gatewayuser"))
	req.Header.Set("Accept", mcpserver.AcceptHeader)
	rec = httptest.NewRecorder()
	if _, _, ok := s.mcpAuthContext(rec, req); !ok {
		t.Errorf("a forwarded HTCondor token was refused: %d %s", rec.Code, rec.Body.String())
	}

	// The web UI's own OAuth2 is whole, and nothing names MCP.
	for _, path := range []string{"/oauth2/authorize", "/oauth2/token", webUICallbackPath,
		"/.well-known/oauth-authorization-server"} {
		if !hasRoute(s, path) {
			t.Errorf("%s is gone; the web UI can no longer log anybody in", path)
		}
	}
	for _, path := range []string{"/mcp/oauth2/authorize", "/mcp/oauth2/token", mcpCallbackPath,
		mcpDeviceVerifyPath, wellKnownProtectedResource + mcpPath, wellKnownProtectedResource + mcpMessagePath} {
		if hasRoute(s, path) {
			t.Errorf("%s is still registered; it describes a login this MCP endpoint refuses", path)
		}
	}
}
