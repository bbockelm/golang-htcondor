package httpserver

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
)

// TestAPIRoutesWWWAuthenticateHeader verifies that /api routes return WWW-Authenticate header
// when authentication fails, as required by RFC 6750
// oauth2TestServer builds a server with OAuth2 configured, which is the
// shape every subtest below needs.
func oauth2TestServer(t *testing.T, logger *logging.Logger) *Server {
	t.Helper()
	server, err := NewServer(Config{
		ScheddName:   "test-schedd",
		ScheddAddr:   "localhost:9618",
		Logger:       logger,
		EnableMCP:    true,
		OAuth2DBPath: t.TempDir() + "/oauth2-test.db",
		OAuth2Issuer: "http://localhost:8080",
	})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	return server
}

func TestAPIRoutesWWWAuthenticateHeader(t *testing.T) {
	// Create a logger
	logger, err := logging.New(&logging.Config{
		OutputPath: "stderr",
		// Keep it quiet during tests - no debug levels configured means default warn
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	t.Run("WithoutOAuth2Provider", func(t *testing.T) {
		// Create server WITHOUT OAuth2 provider
		server, err := NewServer(Config{
			ScheddName:   "test-schedd",
			ScheddAddr:   "localhost:9618",
			Logger:       logger,
			EnableMCP:    false,
			OAuth2DBPath: t.TempDir() + "/sessions.db",
		})
		if err != nil {
			t.Fatalf("Failed to create server: %v", err)
		}

		// Test various /api endpoints
		endpoints := []string{
			"/api/v1/jobs",
			"/api/v1/jobs/123.0",
		}

		for _, endpoint := range endpoints {
			t.Run(endpoint, func(t *testing.T) {
				req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, endpoint, nil)
				w := httptest.NewRecorder()

				// Handle the request based on endpoint
				if endpoint == "/api/v1/jobs" {
					server.handleJobs(w, req)
				} else if strings.HasPrefix(endpoint, "/api/v1/jobs/") {
					server.handleJobByID(w, req)
				}

				resp := w.Result()
				defer func() {
					if err := resp.Body.Close(); err != nil {
						t.Errorf("Failed to close response body: %v", err)
					}
				}()

				// Should return 401 Unauthorized
				if resp.StatusCode != http.StatusUnauthorized {
					t.Errorf("Expected status 401, got %d", resp.StatusCode)
				}

				// Should have WWW-Authenticate header even without OAuth2 provider
				// This is the key requirement from the issue
				wwwAuth := resp.Header.Get("WWW-Authenticate")
				if wwwAuth == "" {
					t.Error("WWW-Authenticate header should be present for 401 responses on /api routes")
				}

				// The header should indicate Bearer authentication
				if !strings.Contains(wwwAuth, "Bearer") {
					t.Errorf("WWW-Authenticate header should contain 'Bearer', got: %s", wwwAuth)
				}
			})
		}
	})

	t.Run("WithOAuth2Provider", func(t *testing.T) {
		// Create server WITH OAuth2 provider
		server, err := NewServer(Config{
			ScheddName:   "test-schedd",
			ScheddAddr:   "localhost:9618",
			Logger:       logger,
			EnableMCP:    true,
			OAuth2DBPath: t.TempDir() + "/oauth2-test.db",
			OAuth2Issuer: "http://localhost:8080",
		})
		if err != nil {
			t.Fatalf("Failed to create server: %v", err)
		}

		// Test various /api endpoints
		endpoints := []string{
			"/api/v1/jobs",
			"/api/v1/jobs/123.0",
		}

		for _, endpoint := range endpoints {
			t.Run(endpoint, func(t *testing.T) {
				req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, endpoint, nil)
				w := httptest.NewRecorder()

				// Handle the request based on endpoint
				if endpoint == "/api/v1/jobs" {
					server.handleJobs(w, req)
				} else if strings.HasPrefix(endpoint, "/api/v1/jobs/") {
					server.handleJobByID(w, req)
				}

				resp := w.Result()
				defer func() {
					if err := resp.Body.Close(); err != nil {
						t.Errorf("Failed to close response body: %v", err)
					}
				}()

				// Should return 401 Unauthorized
				if resp.StatusCode != http.StatusUnauthorized {
					t.Errorf("Expected status 401, got %d", resp.StatusCode)
				}

				// Should have WWW-Authenticate header
				wwwAuth := resp.Header.Get("WWW-Authenticate")
				if wwwAuth == "" {
					t.Error("WWW-Authenticate header should be present for 401 responses")
				}

				// The header should indicate Bearer authentication with realm
				if !strings.Contains(wwwAuth, "Bearer") {
					t.Errorf("WWW-Authenticate header should contain 'Bearer', got: %s", wwwAuth)
				}

				// When OAuth2 provider is configured, should include realm
				if !strings.Contains(wwwAuth, "realm=") {
					t.Errorf("WWW-Authenticate header should contain 'realm=' when OAuth2 is configured, got: %s", wwwAuth)
				}
			})
		}
	})

	// A syntactically valid bearer token is not yet an identity.
	//
	// This server verifies no JWT signatures -- the schedd is the trust
	// root and authenticates the forwarded token over CEDAR -- so the
	// sub claim means nothing until a schedd op has succeeded with the
	// token (TokenCache.MarkValidated) or the schedd has been asked who
	// the caller is. /api/v1/jobs is owner-scoped, so with neither
	// available it must fail closed.
	//
	// This subtest used to assert the opposite ("should not return 401
	// with valid token"), which held only because TokenCache.Add marked
	// every freshly parsed token validated -- the behaviour that made a
	// forged signature resolve to its own sub.
	t.Run("UnvalidatedTokenIsRefusedOnAnOwnerScopedRoute", func(t *testing.T) {
		server := oauth2TestServer(t, logger)

		token := createTestJWTToken(3600)
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/jobs", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()

		server.handleJobs(w, req)

		resp := w.Result()
		defer func() {
			if err := resp.Body.Close(); err != nil {
				t.Errorf("Failed to close response body: %v", err)
			}
		}()
		body, _ := io.ReadAll(resp.Body)

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Status = %d, want 401: an owner-scoped listing must not run for a caller it cannot name. Body: %s",
				resp.StatusCode, body)
		}
		if !strings.Contains(string(body), "identity") {
			t.Errorf("the refusal does not say why: %s", body)
		}
	})

	// The other half: once the schedd has accepted the token, the same
	// request is no longer refused for lack of an identity. It still
	// fails here -- there is no schedd to query -- but not with a 401.
	t.Run("ValidatedTokenPassesTheIdentityGate", func(t *testing.T) {
		server := oauth2TestServer(t, logger)

		token := createTestJWTToken(3600)
		if _, err := server.tokenCache.Add(token); err != nil {
			t.Fatalf("caching the token: %v", err)
		}
		// What a successful schedd op does for a real request.
		server.tokenCache.MarkValidated(token, "alice@test.domain")

		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/jobs", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()

		server.handleJobs(w, req)

		resp := w.Result()
		defer func() {
			if err := resp.Body.Close(); err != nil {
				t.Errorf("Failed to close response body: %v", err)
			}
		}()
		if resp.StatusCode == http.StatusUnauthorized {
			body, _ := io.ReadAll(resp.Body)
			t.Errorf("a validated token was refused for identity: %s", body)
		}
	})

	t.Run("WithInvalidToken", func(t *testing.T) {
		// Create server with OAuth2
		server, err := NewServer(Config{
			ScheddName:   "test-schedd",
			ScheddAddr:   "localhost:9618",
			Logger:       logger,
			EnableMCP:    true,
			OAuth2DBPath: t.TempDir() + "/oauth2-test.db",
			OAuth2Issuer: "http://localhost:8080",
		})
		if err != nil {
			t.Fatalf("Failed to create server: %v", err)
		}

		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/jobs", nil)
		req.Header.Set("Authorization", "Bearer invalid.token.here")
		w := httptest.NewRecorder()

		server.handleJobs(w, req)

		resp := w.Result()
		defer func() {
			if err := resp.Body.Close(); err != nil {
				t.Errorf("Failed to close response body: %v", err)
			}
		}()

		// Should return 401 for invalid token
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected status 401 for invalid token, got %d", resp.StatusCode)
		}

		// Should have WWW-Authenticate header
		wwwAuth := resp.Header.Get("WWW-Authenticate")
		if wwwAuth == "" {
			t.Error("WWW-Authenticate header should be present for 401 responses")
		}

		// Should contain error information for invalid token
		if !strings.Contains(wwwAuth, "Bearer") {
			t.Errorf("WWW-Authenticate header should contain 'Bearer', got: %s", wwwAuth)
		}
	})
}

// TestCollectorRoutesNoAuth verifies that collector routes don't require authentication
func TestCollectorRoutesNoAuth(t *testing.T) {
	// Create a logger
	logger, err := logging.New(&logging.Config{
		OutputPath: "stderr",
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Create a mock collector
	collector := htcondor.NewCollector("localhost:9618")

	// Create server with collector but no auth
	server, err := NewServer(Config{
		ScheddName:   "test-schedd",
		ScheddAddr:   "localhost:9618",
		Collector:    collector,
		Logger:       logger,
		OAuth2DBPath: t.TempDir() + "/sessions.db",
	})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/collector/ads", nil)
	w := httptest.NewRecorder()

	// Use a context to avoid timeout issues with real collector
	ctx, cancel := context.WithCancel(req.Context())
	cancel() // Immediately cancel to avoid hanging
	req = req.WithContext(ctx)

	server.handleCollectorPath(w, req)

	resp := w.Result()
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Errorf("Failed to close response body: %v", err)
		}
	}()

	// Collector endpoints should work without authentication
	// They may fail for other reasons (no collector), but should not return 401
	if resp.StatusCode == http.StatusUnauthorized {
		t.Error("Collector endpoints should not require authentication")
	}
}
