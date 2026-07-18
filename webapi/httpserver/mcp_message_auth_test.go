package httpserver

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/logging"
)

// newAuthTestHandler builds a Handler with a real fosite OAuth2 provider
// (throwaway SQLite DB) and a quiet logger — enough to exercise
// handleMCPMessage's auth gate without a schedd. trustDomain is set so
// the classifier's "forward to schedd" branch is reachable in principle,
// but the cases below deliberately never trigger it (that path needs a
// live schedd and is covered by the integration suite).
func newAuthTestHandler(t *testing.T) *Handler {
	t.Helper()
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	provider, err := NewOAuth2Provider(OAuth2ProviderOptions{
		DB:                   newTestDB(t, filepath.Join(t.TempDir(), "auth.db")),
		Issuer:               "https://mcp.example.com",
		AccessTokenLifespan:  time.Hour,
		RefreshTokenLifespan: 2 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewOAuth2Provider: %v", err)
	}
	t.Cleanup(func() { _ = provider.Close() })
	return &Handler{
		oauth2Provider: provider,
		logger:         logger,
		trustDomain:    "pool.example.com",
	}
}

// TestMCPMessageRejectsBadTokenWith401 pins the contract that protects
// MCP clients from the "expired token, 200 + JSON-RPC error, never
// refreshes" failure mode: any bearer that fosite can't introspect and
// that isn't a forwardable pool IDTOKEN must yield a real 401 from
// /mcp/message. This covers the opaque-token case (an expired/unknown
// fosite access token is opaque, so it parses as nothing → unparseable),
// a foreign-issuer JWT, a stale JWT bearing our own issuer, and a
// missing bearer.
func TestMCPMessageRejectsBadTokenWith401(t *testing.T) {
	h := newAuthTestHandler(t)

	cases := []struct {
		name   string
		bearer string // "" means send no Authorization header
	}{
		{"opaque/garbage bearer (expired or unknown fosite token)", "ory_at_not-a-real-token"},
		{"foreign-issuer JWT", makeJWT(t, "https://login.example.org")},
		{"stale JWT bearing our own issuer", makeJWT(t, "https://mcp.example.com")},
		{"missing bearer entirely", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp/message",
				bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
			if tc.bearer != "" {
				req.Header.Set("Authorization", "Bearer "+tc.bearer)
			}
			w := httptest.NewRecorder()

			h.handleMCPMessage(w, req)

			if w.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401 (body: %s)", w.Code, w.Body.String())
			}
		})
	}
}
