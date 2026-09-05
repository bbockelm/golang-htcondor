package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/logging"
)

// prmTestBase is the public base URL these tests configure the server
// with; the resource identifiers below are derived from it.
const prmTestBase = "https://ap40-api.example.org"

// prmTestServer builds a server with MCP/OAuth2 on and a public base URL,
// and routes requests through the real mux rather than calling handlers
// directly -- both bugs here were routing behaviour, invisible to a test
// that invokes the handler itself.
func prmTestServer(t *testing.T) *Server {
	t.Helper()
	const baseURL = prmTestBase
	logger, err := logging.New(&logging.Config{OutputPath: "stdout"})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	s, err := NewServer(Config{
		Logger:       logger,
		EnableMCP:    true,
		OAuth2DBPath: filepath.Join(t.TempDir(), "oauth2.db"),
		OAuth2Issuer: baseURL,
		HTTPBaseURL:  baseURL,
		ScheddName:   "test-schedd",
		ScheddAddr:   "127.0.0.1:9618",
	})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	// Routes are wired in Handler.Start, which also starts background
	// goroutines this test has no use for. Registering them directly is
	// what makes the mux, and therefore the routing under test, real.
	s.setupRoutes()
	return s
}

func getPRM(t *testing.T, s *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	return w
}

// RFC 9728 section 3.3: `resource` must equal the identifier the client
// used to build the metadata URL, and a client MUST reject the document
// when it does not. An MCP client configured with https://host/mcp/message
// derives https://host/.well-known/oauth-protected-resource/mcp/message,
// so that document has to name /mcp/message and not the bare host.
//
// It named the token issuer instead, which is a different thing that
// merely looked the same in a deployment where the API and the
// authorization server share an origin.
func TestProtectedResourceMetadataMatchesTheResourceAsked(t *testing.T) {
	const base = prmTestBase
	s := prmTestServer(t)

	for _, tc := range []struct {
		path string
		want string
	}{
		{wellKnownProtectedResource + mcpMessagePath, base + mcpMessagePath},
		{wellKnownProtectedResource, base},
	} {
		t.Run(tc.path, func(t *testing.T) {
			w := getPRM(t, s, tc.path)
			if w.Code != http.StatusOK {
				t.Fatalf("status %d, want 200: %s", w.Code, w.Body.String())
			}
			if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
				t.Fatalf("Content-Type %q is not JSON; a client parsing this reports a syntax error", ct)
			}
			var doc map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
				t.Fatalf("body is not JSON (%v): %s", err, w.Body.String())
			}
			if got := doc["resource"]; got != tc.want {
				t.Errorf("resource = %v, want %q -- RFC 9728 3.3 obliges the client to reject a mismatch", got, tc.want)
			}
			if _, ok := doc["authorization_servers"]; !ok {
				t.Error("no authorization_servers, so the client cannot find where to authenticate")
			}
		})
	}
}

// The resource-specific document must be reachable at all. It was not
// registered, so it fell through to the SPA and answered 200 text/html --
// which is why the client's complaint was a JSON syntax error about
// "<!DOCTYPE" rather than anything naming the real problem.
func TestProtectedResourceMetadataIsNotTheSPA(t *testing.T) {
	s := prmTestServer(t)

	w := getPRM(t, s, wellKnownProtectedResource+mcpMessagePath)
	if body := w.Body.String(); strings.Contains(body, "<!DOCTYPE") || strings.Contains(body, "<html") {
		t.Fatalf("the SPA answered the metadata request: %.80s", body)
	}
}

// Anything else under /.well-known/ is discovery space too. Answering a
// probe with the SPA tells the client the document exists and is
// malformed, when the truth is that it is not served here.
//
// This asserts the matched ROUTE rather than the response body, because
// the body cannot show it: webui.IsEmbedded() is false in a test build,
// so the "/" handler here is handleWelcome, which already 404s. The SPA
// is what "/" resolves to in the builds that ship, and a body assertion
// would pass identically with the guard removed -- proving nothing about
// the case this exists for. What the guard actually changes is which
// pattern wins, and that is the same in every build.
func TestUnknownWellKnownDoesNotFallThroughToRoot(t *testing.T) {
	s := prmTestServer(t)

	for _, path := range []string{
		"/.well-known/openid-configuration",
		"/.well-known/oauth-protected-resource/nope",
		"/.well-known/whatever",
	} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
			_, pattern := s.mux.Handler(req)
			if pattern == "/" {
				t.Errorf("routed to the root handler, which is the SPA in a shipped build")
			}
			if pattern != "/.well-known/" {
				t.Errorf("matched %q, want the /.well-known/ guard", pattern)
			}

			w := getPRM(t, s, path)
			if w.Code != http.StatusNotFound {
				t.Errorf("status %d, want 404", w.Code)
			}
			if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
				t.Errorf("Content-Type %q is not JSON", ct)
			}
		})
	}
}

// The endpoints that were already registered under /.well-known/ must
// still win over the catch-all, since it is a subtree pattern covering
// them.
func TestRegisteredWellKnownStillWins(t *testing.T) {
	s := prmTestServer(t)

	w := getPRM(t, s, "/.well-known/oauth-authorization-server")
	if w.Code != http.StatusOK {
		t.Fatalf("authorization server metadata is now %d: %s", w.Code, w.Body.String())
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatalf("body is not JSON (%v): %s", err, w.Body.String())
	}
	if _, ok := doc["issuer"]; !ok {
		t.Error("no issuer in the authorization server metadata")
	}
}
