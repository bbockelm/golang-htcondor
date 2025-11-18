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
func TestAPIRoutesWWWAuthenticateHeader(t *testing.T) {
	// Create a logger
	logger, err := logging.New(&logging.Config{
		OutputPath:   "stderr",
		MinVerbosity: logging.VerbosityError, // Keep it quiet during tests
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Create a mock schedd
	schedd := htcondor.NewSchedd("test-schedd", "localhost:9618")

	t.Run("WithoutOAuth2Provider", func(t *testing.T) {
		// Create server WITHOUT OAuth2 provider
		server := &Server{
			schedd:         schedd,
			logger:         logger,
			tokenCache:     NewTokenCache(),
			oauth2Provider: nil, // No OAuth2 provider configured
		}

		// Test various /api endpoints
		endpoints := []string{
			"/api/v1/jobs",
			"/api/v1/jobs/123.0",
		}

		for _, endpoint := range endpoints {
			t.Run(endpoint, func(t *testing.T) {
				req := httptest.NewRequest(http.MethodGet, endpoint, nil)
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
		// Create OAuth2 provider
		oauth2Provider, err := NewOAuth2Provider(t.TempDir()+"/oauth2-test.db", "http://localhost:8080")
		if err != nil {
			t.Fatalf("Failed to create OAuth2 provider: %v", err)
		}
		defer func() {
			if err := oauth2Provider.Close(); err != nil {
				t.Errorf("Failed to close OAuth2 provider: %v", err)
			}
		}()

		// Create server WITH OAuth2 provider
		server := &Server{
			schedd:         schedd,
			logger:         logger,
			tokenCache:     NewTokenCache(),
			oauth2Provider: oauth2Provider,
		}

		// Test various /api endpoints
		endpoints := []string{
			"/api/v1/jobs",
			"/api/v1/jobs/123.0",
		}

		for _, endpoint := range endpoints {
			t.Run(endpoint, func(t *testing.T) {
				req := httptest.NewRequest(http.MethodGet, endpoint, nil)
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

	t.Run("WithValidToken", func(t *testing.T) {
		// Create OAuth2 provider
		oauth2Provider, err := NewOAuth2Provider(t.TempDir()+"/oauth2-test.db", "http://localhost:8080")
		if err != nil {
			t.Fatalf("Failed to create OAuth2 provider: %v", err)
		}
		defer func() {
			if err := oauth2Provider.Close(); err != nil {
				t.Errorf("Failed to close OAuth2 provider: %v", err)
			}
		}()

		// Create server
		server := &Server{
			schedd:         schedd,
			logger:         logger,
			tokenCache:     NewTokenCache(),
			oauth2Provider: oauth2Provider,
		}

		// Create a valid test token
		token := createTestJWTToken(3600)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/jobs", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()

		server.handleJobs(w, req)

		resp := w.Result()
		defer func() {
			if err := resp.Body.Close(); err != nil {
				t.Errorf("Failed to close response body: %v", err)
			}
		}()

		// With a valid token, we won't get 401
		// (We might get 500 because we're not connected to a real schedd,
		// but that's expected in this test)
		if resp.StatusCode == http.StatusUnauthorized {
			body, _ := io.ReadAll(resp.Body)
			t.Errorf("Should not return 401 with valid token. Status: %d, Body: %s", resp.StatusCode, string(body))
		}
	})

	t.Run("WithInvalidToken", func(t *testing.T) {
		// Create OAuth2 provider
		oauth2Provider, err := NewOAuth2Provider(t.TempDir()+"/oauth2-test.db", "http://localhost:8080")
		if err != nil {
			t.Fatalf("Failed to create OAuth2 provider: %v", err)
		}
		defer func() {
			if err := oauth2Provider.Close(); err != nil {
				t.Errorf("Failed to close OAuth2 provider: %v", err)
			}
		}()

		// Create server
		server := &Server{
			schedd:         schedd,
			logger:         logger,
			tokenCache:     NewTokenCache(),
			oauth2Provider: oauth2Provider,
		}

		req := httptest.NewRequest(http.MethodGet, "/api/v1/jobs", nil)
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
		OutputPath:   "stderr",
		MinVerbosity: logging.VerbosityError,
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Create a mock collector
	collector := htcondor.NewCollector("localhost:9618")

	// Create server with collector but no auth
	server := &Server{
		collector:  collector,
		logger:     logger,
		tokenCache: NewTokenCache(),
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/collector/ads", nil)
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
