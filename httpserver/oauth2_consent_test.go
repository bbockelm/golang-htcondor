package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/ory/fosite"
	"golang.org/x/crypto/bcrypt"
)

// setupTestOAuth2Server creates a test server with OAuth2 provider for testing
func setupTestOAuth2Server(t *testing.T) (*Server, *OAuth2Provider, string, context.Context) {
	t.Helper()

	// Create a logger
	logger, err := logging.New(&logging.Config{
		OutputPath: "stderr",
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Create OAuth2 provider
	oauth2Provider, err := NewOAuth2Provider(t.TempDir()+"/oauth2-test.db", "http://localhost:8080")
	if err != nil {
		t.Fatalf("Failed to create OAuth2 provider: %v", err)
	}

	// Create a test client
	ctx := context.Background()
	clientID := "test-client"
	clientSecret := "test-secret"
	hashedSecret, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash client secret: %v", err)
	}

	client := &fosite.DefaultClient{
		ID:            clientID,
		Secret:        hashedSecret,
		RedirectURIs:  []string{"http://localhost:8080/callback"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid", "mcp:read", "mcp:write"},
	}

	if err := oauth2Provider.GetStorage().CreateClient(ctx, client); err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Create server with OAuth2 provider
	server, err := NewServer(Config{
		ScheddName:   "test-schedd",
		ScheddAddr:   "localhost:9618",
		Logger:       logger,
		EnableMCP:    true,
		OAuth2DBPath: t.TempDir() + "/oauth2-test2.db", // Use different path to avoid conflict
		OAuth2Issuer: "http://localhost:8080",
	})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	return server, oauth2Provider, clientID, ctx
}

func TestOAuth2ConsentPage_GetConsentPage(t *testing.T) {
	server, oauth2Provider, clientID, ctx := setupTestOAuth2Server(t)
	defer func() {
		if err := oauth2Provider.Close(); err != nil {
			t.Errorf("Failed to close OAuth2 provider: %v", err)
		}
	}()

	t.Run("GetConsentPage", func(t *testing.T) {
		// Create a mock authorize request
		authorizeReq := httptest.NewRequest(http.MethodGet, "/mcp/oauth2/authorize", nil)
		authorizeReq.URL.RawQuery = url.Values{
			"response_type": []string{"code"},
			"client_id":     []string{clientID},
			"redirect_uri":  []string{"http://localhost:8080/callback"},
			"scope":         []string{"openid mcp:read mcp:write"},
			"state":         []string{"test-state"},
		}.Encode()

		ar, err := oauth2Provider.GetProvider().NewAuthorizeRequest(ctx, authorizeReq)
		if err != nil {
			t.Fatalf("Failed to create authorize request: %v", err)
		}

		// Store the authorize request with username
		state, err := server.oauth2StateStore.GenerateState()
		if err != nil {
			t.Fatalf("Failed to generate state: %v", err)
		}
		username := "testuser"
		server.oauth2StateStore.StoreWithUsername(state, ar, "", username)

		// Create consent page request
		req := httptest.NewRequest(http.MethodGet, "/mcp/oauth2/consent?state="+state, nil)
		w := httptest.NewRecorder()

		// Handle the request
		server.handleOAuth2Consent(w, req)

		resp := w.Result()
		defer func() {
			if err := resp.Body.Close(); err != nil {
				t.Errorf("Failed to close response body: %v", err)
			}
		}()

		// Check status code
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		// Check content type
		contentType := resp.Header.Get("Content-Type")
		if !strings.Contains(contentType, "text/html") {
			t.Errorf("Expected HTML content type, got %s", contentType)
		}

		// Read and check body
		body := w.Body.String()

		// Check for key elements in the HTML
		expectedStrings := []string{
			"Authorize Application",
			"testuser",
			"test-client",
			"openid",
			"mcp:read",
			"mcp:write",
			"Basic authentication information",
			"Read-only access to HTCondor jobs",
			"Full access to submit and manage HTCondor jobs",
			"Authorize",
			"Deny",
		}

		for _, expected := range expectedStrings {
			if !strings.Contains(body, expected) {
				t.Errorf("Expected consent page to contain '%s', but it was not found", expected)
			}
		}
	})
}

func TestOAuth2ConsentPage_ApproveConsent(t *testing.T) {
	server, oauth2Provider, clientID, ctx := setupTestOAuth2Server(t)
	defer func() {
		if err := oauth2Provider.Close(); err != nil {
			t.Errorf("Failed to close OAuth2 provider: %v", err)
		}
	}()

	t.Run("ApproveConsent", func(t *testing.T) {
		// Create a mock authorize request
		authorizeReq := httptest.NewRequest(http.MethodGet, "/mcp/oauth2/authorize", nil)
		authorizeReq.URL.RawQuery = url.Values{
			"response_type": []string{"code"},
			"client_id":     []string{clientID},
			"redirect_uri":  []string{"http://localhost:8080/callback"},
			"scope":         []string{"openid mcp:read"},
			"state":         []string{"test-state"},
		}.Encode()

		ar, err := oauth2Provider.GetProvider().NewAuthorizeRequest(ctx, authorizeReq)
		if err != nil {
			t.Fatalf("Failed to create authorize request: %v", err)
		}

		// Store the authorize request with username
		state, err := server.oauth2StateStore.GenerateState()
		if err != nil {
			t.Fatalf("Failed to generate state: %v", err)
		}
		username := "testuser"
		server.oauth2StateStore.StoreWithUsername(state, ar, "", username)

		// Create approval request
		form := url.Values{
			"state":  []string{state},
			"action": []string{"approve"},
		}
		req := httptest.NewRequest(http.MethodPost, "/mcp/oauth2/consent", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		// Handle the request
		server.handleOAuth2Consent(w, req)

		resp := w.Result()
		defer func() {
			if err := resp.Body.Close(); err != nil {
				t.Errorf("Failed to close response body: %v", err)
			}
		}()

		// Check for redirect with authorization code
		if resp.StatusCode != http.StatusSeeOther && resp.StatusCode != http.StatusFound {
			t.Errorf("Expected redirect status (303 or 302), got %d", resp.StatusCode)
		}

		location := resp.Header.Get("Location")
		if location == "" {
			t.Error("Expected Location header for redirect")
		}

		// Check that location contains callback URL and code
		if !strings.Contains(location, "http://localhost:8080/callback") {
			t.Errorf("Expected redirect to callback URL, got %s", location)
		}
		if !strings.Contains(location, "code=") {
			t.Errorf("Expected code parameter in redirect URL, got %s", location)
		}
	})
}

func TestOAuth2ConsentPage_DenyConsent(t *testing.T) {
	server, oauth2Provider, clientID, ctx := setupTestOAuth2Server(t)
	defer func() {
		if err := oauth2Provider.Close(); err != nil {
			t.Errorf("Failed to close OAuth2 provider: %v", err)
		}
	}()

	t.Run("DenyConsent", func(t *testing.T) {
		// Create a mock authorize request
		authorizeReq := httptest.NewRequest(http.MethodGet, "/mcp/oauth2/authorize", nil)
		authorizeReq.URL.RawQuery = url.Values{
			"response_type": []string{"code"},
			"client_id":     []string{clientID},
			"redirect_uri":  []string{"http://localhost:8080/callback"},
			"scope":         []string{"openid mcp:read"},
			"state":         []string{"test-state"},
		}.Encode()

		ar, err := oauth2Provider.GetProvider().NewAuthorizeRequest(ctx, authorizeReq)
		if err != nil {
			t.Fatalf("Failed to create authorize request: %v", err)
		}

		// Store the authorize request with username
		state, err := server.oauth2StateStore.GenerateState()
		if err != nil {
			t.Fatalf("Failed to generate state: %v", err)
		}
		username := "testuser"
		server.oauth2StateStore.StoreWithUsername(state, ar, "", username)

		// Create denial request
		form := url.Values{
			"state":  []string{state},
			"action": []string{"deny"},
		}
		req := httptest.NewRequest(http.MethodPost, "/mcp/oauth2/consent", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		// Handle the request
		server.handleOAuth2Consent(w, req)

		resp := w.Result()
		defer func() {
			if err := resp.Body.Close(); err != nil {
				t.Errorf("Failed to close response body: %v", err)
			}
		}()

		// Check for redirect with error
		if resp.StatusCode != http.StatusSeeOther && resp.StatusCode != http.StatusFound {
			t.Errorf("Expected redirect status (303 or 302), got %d", resp.StatusCode)
		}

		location := resp.Header.Get("Location")
		if location == "" {
			t.Error("Expected Location header for redirect")
		}

		// Check that location contains error parameter
		if !strings.Contains(location, "error=access_denied") {
			t.Errorf("Expected access_denied error in redirect URL, got %s", location)
		}
	})
}

func TestOAuth2ConsentPage_InvalidState(t *testing.T) {
	server, oauth2Provider, _, _ := setupTestOAuth2Server(t)
	defer func() {
		if err := oauth2Provider.Close(); err != nil {
			t.Errorf("Failed to close OAuth2 provider: %v", err)
		}
	}()

	t.Run("InvalidState", func(t *testing.T) {
		// Create consent page request with invalid state
		req := httptest.NewRequest(http.MethodGet, "/mcp/oauth2/consent?state=invalid", nil)
		w := httptest.NewRecorder()

		// Handle the request
		server.handleOAuth2Consent(w, req)

		resp := w.Result()
		defer func() {
			if err := resp.Body.Close(); err != nil {
				t.Errorf("Failed to close response body: %v", err)
			}
		}()

		// Should return error
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", resp.StatusCode)
		}
	})
}

func TestOAuth2ConsentPage_MissingState(t *testing.T) {
	server, oauth2Provider, _, _ := setupTestOAuth2Server(t)
	defer func() {
		if err := oauth2Provider.Close(); err != nil {
			t.Errorf("Failed to close OAuth2 provider: %v", err)
		}
	}()

	t.Run("MissingState", func(t *testing.T) {
		// Create consent page request without state
		req := httptest.NewRequest(http.MethodGet, "/mcp/oauth2/consent", nil)
		w := httptest.NewRecorder()

		// Handle the request
		server.handleOAuth2Consent(w, req)

		resp := w.Result()
		defer func() {
			if err := resp.Body.Close(); err != nil {
				t.Errorf("Failed to close response body: %v", err)
			}
		}()

		// Should return error
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", resp.StatusCode)
		}
	})
}

func TestGetScopeDescription(t *testing.T) {
	tests := []struct {
		scope       string
		description string
	}{
		{
			scope:       "openid",
			description: "Basic authentication information",
		},
		{
			scope:       "mcp:read",
			description: "Read-only access to HTCondor jobs and resources via MCP protocol",
		},
		{
			scope:       "mcp:write",
			description: "Full access to submit and manage HTCondor jobs via MCP protocol",
		},
		{
			scope:       "condor:/READ",
			description: "HTCondor READ authorization - allows reading job and daemon information",
		},
		{
			scope:       "condor:/WRITE",
			description: "HTCondor WRITE authorization - allows submitting and managing jobs",
		},
		{
			scope:       "condor:/CUSTOM",
			description: "HTCondor CUSTOM authorization",
		},
		{
			scope:       "unknown:scope",
			description: "Access with scope: unknown:scope",
		},
	}

	for _, tt := range tests {
		t.Run(tt.scope, func(t *testing.T) {
			desc := getScopeDescription(tt.scope)
			if desc != tt.description {
				t.Errorf("Expected description '%s', got '%s'", tt.description, desc)
			}
		})
	}
}
