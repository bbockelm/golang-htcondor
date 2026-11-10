package httpserver

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// collectorReadRoutes are the routes that read the collector. Each must send
// the query under the caller's credential: the request context carries none,
// and ServeHTTP marks it as the caller's, so a handler that passes it along
// as is gets refused before the collector is ever contacted. /pool showed
// exactly that, on every load.
var collectorReadRoutes = []string{
	"/api/v1/collector/ads",
	"/api/v1/collector/ads/startd",
	"/api/v1/collector/ads/startd/slot1@example.org",
	"/api/v1/collector/pool-summary",
}

// newCollectorReadServer returns a server whose collector is an address
// nothing listens on, so a query that gets past the credential gate fails at
// the dial. Which of the two failures a route produces is what the tests
// below tell apart: the security config is built before the dial, so
// "connection refused" means a credential was present.
func newCollectorReadServer(t *testing.T) *Server {
	t.Helper()

	var lc net.ListenConfig
	l, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a port: %v", err)
	}
	collectorAddr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("releasing the reserved port: %v", err)
	}

	signingKeyPath := filepath.Join(t.TempDir(), "POOL")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	if err := os.WriteFile(signingKeyPath, key, 0600); err != nil {
		t.Fatalf("writing the signing key: %v", err)
	}

	server, err := NewServer(Config{
		Logger:                   testLogger(t),
		ScheddName:               "test-schedd",
		ScheddAddr:               "127.0.0.1:0",
		UserHeader:               "X-Test-User",
		UserHeaderTrustAnyUnsafe: true,
		SigningKeyPath:           signingKeyPath,
		TrustDomain:              "test.htcondor.org",
		UIDDomain:                "test.htcondor.org",
		Collector:                htcondor.NewCollector(collectorAddr),
		OAuth2DBPath:             filepath.Join(t.TempDir(), "sessions.db"),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	// Start() would bind a listener and spawn background work; the routes
	// are all this needs.
	server.setupRoutes()
	return server
}

func TestCollectorReadsCarryTheCallersCredential(t *testing.T) {
	server := newCollectorReadServer(t)

	for _, route := range collectorReadRoutes {
		t.Run(route, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, route, nil)
			req.Header.Set("X-Test-User", "alice")
			rec := httptest.NewRecorder()
			server.ServeHTTP(rec, req)

			body, _ := io.ReadAll(rec.Body)
			// The ads routes stream: they answer 200 and report the
			// failure in the body's "error" field, so the status alone
			// cannot tell a refusal from success. The integration test
			// checked only the status, which is how this shipped.
			if rec.Code == http.StatusUnauthorized || !strings.Contains(string(body), "connection refused") {
				t.Fatalf("an authenticated read did not reach the collector with a credential: "+
					"got %d, want the dial to the (closed) collector port to fail. Body: %s",
					rec.Code, body)
			}
		})
	}
}

// Authenticating the caller is the fix, and its other half is that a caller
// who cannot be authenticated is told so up front, rather than having the
// query refused deeper down with a message about this server's internals.
func TestCollectorReadsRequireAnAuthenticatedCaller(t *testing.T) {
	server := newCollectorReadServer(t)

	for _, route := range collectorReadRoutes {
		t.Run(route, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, route, nil)
			rec := httptest.NewRecorder()
			server.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				body, _ := io.ReadAll(rec.Body)
				t.Fatalf("an anonymous read answered %d, want 401. Body: %s", rec.Code, body)
			}
		})
	}
}

// A streamed query's "error" field is shown to the user as is. A refusal is
// reported by its own message, without the connection layers' wrappers.
func TestStreamErrorMessageUnwrapsARefusal(t *testing.T) {
	refusal := &htcondor.ErrDaemonFallbackRefused{
		Origin:   htcondor.OriginUser,
		Reason:   "HTTP request GET /api/v1/collector/ads/startd",
		PeerName: "cm.example.org:9618",
	}
	wrapped := fmt.Errorf("failed to connect and authenticate to collector: %w",
		fmt.Errorf("failed to create security config: %w", refusal))
	if got := streamErrorMessage(wrapped); got != refusal.Error() {
		t.Errorf("streamErrorMessage = %q, want the refusal's own message %q", got, refusal.Error())
	}
}
