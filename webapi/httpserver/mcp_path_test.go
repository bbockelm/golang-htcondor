package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/webapi/mcpserver"
)

// newMCPPathServer builds a server with MCP enabled and its routes
// registered. Routes are wired in Handler.Start, which also starts
// background goroutines these tests have no use for, so they are
// registered directly -- the same approach as prm_rfc9728_test.go.
func newMCPPathServer(t *testing.T) *Server {
	t.Helper()
	cfg := newTestConfig(t)
	cfg.EnableMCP = true
	cfg.OAuth2Issuer = "https://api.example.org"
	cfg.HTTPBaseURL = "https://api.example.org"
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	s.setupRoutes()
	return s
}

// MCP is reachable at /mcp, the URL a client is configured with, as well
// as at the original /mcp/message.
//
// Both are registered on purpose: the short one is what people type, and
// the long one keeps clients that were configured before it moved.
func TestMCPProtocolEndpointAnswersOnBothPaths(t *testing.T) {
	s := newMCPPathServer(t)

	for _, path := range []string{"/mcp", "/mcp/message"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(),
				http.MethodPost, path, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
			req.Header.Set("Content-Type", "application/json")
			// The SDK transport answers 400 without this; the built-in
			// one ignores it. See mcpserver.AcceptHeader.
			req.Header.Set("Accept", mcpserver.AcceptHeader)
			w := httptest.NewRecorder()
			s.ServeHTTP(w, req)

			// Unauthenticated, so 401 is the expected answer -- what
			// matters is that the route exists and is the MCP handler
			// rather than the SPA returning HTML or a 404.
			if got := w.Result().StatusCode; got == http.StatusNotFound {
				t.Fatalf("%s is not routed (404)", path)
			}
			if ct := w.Header().Get("Content-Type"); strings.HasPrefix(ct, "text/html") {
				t.Errorf("%s fell through to the SPA (content-type %q)", path, ct)
			}
		})
	}
}

// RFC 9728 3.3 requires the metadata document to name the identifier the
// client used to build its URL, and says clients MUST reject it
// otherwise. A client configured with https://host/mcp derives
// /.well-known/oauth-protected-resource/mcp, so that document has to
// exist and name .../mcp -- not .../mcp/message.
func TestProtectedResourceMetadataMatchesWhicheverMCPPathWasAsked(t *testing.T) {
	s := newMCPPathServer(t)

	for _, tc := range []struct{ metadataPath, wantResource string }{
		{"/.well-known/oauth-protected-resource/mcp", "https://api.example.org/mcp"},
		{"/.well-known/oauth-protected-resource/mcp/message", "https://api.example.org/mcp/message"},
	} {
		t.Run(tc.metadataPath, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, tc.metadataPath, nil)
			w := httptest.NewRecorder()
			s.ServeHTTP(w, req)

			if w.Result().StatusCode != http.StatusOK {
				t.Fatalf("status %d for %s", w.Result().StatusCode, tc.metadataPath)
			}
			var doc struct {
				Resource string `json:"resource"`
			}
			if err := json.NewDecoder(w.Body).Decode(&doc); err != nil {
				t.Fatalf("decoding metadata: %v", err)
			}
			if doc.Resource != tc.wantResource {
				t.Errorf("resource = %q, want %q: a client is obliged to reject a document naming a different identifier",
					doc.Resource, tc.wantResource)
			}
		})
	}
}

// The short path must not shadow the OAuth2 endpoints beneath /mcp/.
func TestMCPPathDoesNotShadowTheOAuthEndpoints(t *testing.T) {
	s := newMCPPathServer(t)

	req := httptest.NewRequestWithContext(context.Background(),
		http.MethodGet, "/mcp/oauth2/authorize", nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)

	// Anything but the MCP protocol handler's answer: the authorize
	// endpoint rejects a request with no parameters on its own terms.
	if w.Result().StatusCode == http.StatusNotFound {
		t.Error("/mcp/oauth2/authorize is no longer routed")
	}
}
