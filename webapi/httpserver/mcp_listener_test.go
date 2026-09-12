package httpserver

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// echoHandler answers 200 for anything, so a 404 in these tests can only
// have come from the filter under test.
func echoHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func statusFor(t *testing.T, h http.Handler, path string) int {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w.Code
}

// The MCP listener serves what an MCP client needs, and nothing else.
//
// The reason for a separate port is that it can be firewalled differently
// from the web UI. That only holds if the web UI and the REST API are not
// also answering there, so the filter is the feature rather than a
// tidiness measure.
func TestMCPListenerServesOnlyTheMCPSurface(t *testing.T) {
	h := mcpSurfaceOnly(echoHandler())

	allowed := []string{
		"/mcp/message",
		"/mcp/oauth2/authorize",
		"/mcp/oauth2/token",
		"/mcp/oauth2/register",
		"/.well-known/oauth-authorization-server",
		"/.well-known/oauth-protected-resource",
		"/.well-known/oauth-protected-resource/mcp/message",
		"/healthz",
		"/readyz",
	}
	for _, p := range allowed {
		if got := statusFor(t, h, p); got != http.StatusOK {
			t.Errorf("%s = %d, want 200; an MCP client cannot work without it", p, got)
		}
	}

	refused := []string{
		"/",
		"/api/v1/jobs",
		"/api/v1/admin/logs",
		"/api/v1/whoami",
		"/openapi.json",
		"/login",
		"/idp/authorize",
	}
	for _, p := range refused {
		if got := statusFor(t, h, p); got != http.StatusNotFound {
			t.Errorf("%s = %d, want 404; the MCP port must not expose the web UI or the REST API", p, got)
		}
	}
}

// And the main listener stops serving the protocol endpoint, or the
// separate port has changed nothing.
func TestMainListenerDropsTheMCPProtocolWhenSplit(t *testing.T) {
	h := withoutMCPProtocol(echoHandler())

	if got := statusFor(t, h, "/mcp/message"); got != http.StatusNotFound {
		t.Errorf("/mcp/message = %d on the main listener, want 404; "+
			"MCP answering on both ports leaves the surface as wide as before", got)
	}

	// Everything else is untouched, including the OAuth2 endpoints: a
	// client that reaches this port still has to be able to authenticate,
	// and the consent screens live under the same prefix.
	for _, p := range []string{
		"/", "/api/v1/jobs", "/openapi.json",
		"/mcp/oauth2/authorize", "/mcp/oauth2/token", "/mcp/oauth2/consent",
		"/.well-known/oauth-authorization-server",
		"/.well-known/oauth-protected-resource",
	} {
		if got := statusFor(t, h, p); got != http.StatusOK {
			t.Errorf("%s = %d on the main listener, want 200", p, got)
		}
	}
}

// Combined is the default: with no MCP address configured nothing is
// filtered, and a deployment that never asked for a split is unchanged.
func TestCombinedByDefault(t *testing.T) {
	logger := testLogger(t)
	s, err := NewServer(Config{
		Logger:       logger,
		ScheddName:   "test-schedd",
		ScheddAddr:   "127.0.0.1:9618",
		OAuth2DBPath: t.TempDir() + "/oauth2.db",
	})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	if s.mcpSplit {
		t.Error("the server split MCP off without being asked to")
	}

	s2, err := NewServer(Config{
		Logger:        logger,
		ScheddName:    "test-schedd",
		ScheddAddr:    "127.0.0.1:9618",
		OAuth2DBPath:  t.TempDir() + "/oauth2b.db",
		MCPListenAddr: "127.0.0.1:9443",
	})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	if !s2.mcpSplit {
		t.Error("MCPListenAddr was set but the server did not split")
	}
}
