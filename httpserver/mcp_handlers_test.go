package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/logging"
)

// TestDynamicClientRegistrationScopes tests scope validation in client registration
func TestDynamicClientRegistrationScopes(t *testing.T) {
	// Create temporary directory for test database
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_oauth2.db")

	// Create test logger
	logger, err := logging.New(&logging.Config{
		OutputPath: "stdout",
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Create server with OAuth2 enabled
	server, err := NewServer(Config{
		Logger:       logger,
		EnableMCP:    true,
		OAuth2DBPath: dbPath,
		OAuth2Issuer: "http://localhost:8080",
		ScheddName:   "test-schedd",
		ScheddAddr:   "127.0.0.1:9618",
	})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	tests := []struct {
		name           string
		requestScopes  []string
		expectedStatus int
		expectError    bool
	}{
		{
			name:           "Valid scopes - openid only",
			requestScopes:  []string{"openid"},
			expectedStatus: http.StatusCreated,
			expectError:    false,
		},
		{
			name:           "Valid scopes - all supported scopes",
			requestScopes:  []string{"openid", "profile", "email", "mcp:read", "mcp:write"},
			expectedStatus: http.StatusCreated,
			expectError:    false,
		},
		{
			name:           "Valid scopes - profile and email",
			requestScopes:  []string{"openid", "profile", "email"},
			expectedStatus: http.StatusCreated,
			expectError:    false,
		},
		{
			name:           "Valid scopes - mcp scopes",
			requestScopes:  []string{"openid", "mcp:read", "mcp:write"},
			expectedStatus: http.StatusCreated,
			expectError:    false,
		},
		{
			name:           "Invalid scope - unsupported scope",
			requestScopes:  []string{"openid", "invalid_scope"},
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
		},
		{
			name:           "Invalid scope - random scope",
			requestScopes:  []string{"openid", "profile", "admin"},
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
		},
		{
			name:           "Default scopes when empty",
			requestScopes:  []string{},
			expectedStatus: http.StatusCreated,
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create registration request
			regReq := map[string]interface{}{
				"redirect_uris":  []string{"http://localhost:8080/callback"},
				"grant_types":    []string{"authorization_code"},
				"response_types": []string{"code"},
				"client_name":    "Test Client",
			}

			// Only set scope if not testing default behavior
			if len(tt.requestScopes) > 0 {
				regReq["scope"] = tt.requestScopes
			}

			reqBody, err := json.Marshal(regReq)
			if err != nil {
				t.Fatalf("Failed to marshal request: %v", err)
			}

			// Create HTTP request
			req := httptest.NewRequestWithContext(context.Background(), "POST", "/mcp/oauth2/register", bytes.NewReader(reqBody))
			req.Header.Set("Content-Type", "application/json")

			// Create response recorder
			rr := httptest.NewRecorder()

			// Call handler
			server.handleOAuth2Register(rr, req)

			// Check status code
			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Body: %s",
					tt.expectedStatus, rr.Code, rr.Body.String())
			}

			if !tt.expectError && rr.Code == http.StatusCreated {
				// Verify response contains expected fields
				var resp map[string]interface{}
				if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
					t.Fatalf("Failed to decode response: %v", err)
				}

				if resp["client_id"] == nil || resp["client_secret"] == nil {
					t.Error("Response missing client_id or client_secret")
				}

				// Verify scopes in response
				if scopeStr, ok := resp["scope"].(string); ok {
					if len(tt.requestScopes) == 0 {
						// Should have default scopes
						if scopeStr == "" {
							t.Error("Expected default scopes, got empty string")
						}
					}
				}
			}
		})
	}
}

// TestDynamicClientRegistrationScopeFormats tests that scope can be sent as a string (RFC 7591) or array
func TestDynamicClientRegistrationScopeFormats(t *testing.T) {
	// Create temporary directory for test database
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_oauth2.db")

	logger, err := logging.New(&logging.Config{
		OutputPath: "stdout",
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	server, err := NewServer(Config{
		Logger:       logger,
		EnableMCP:    true,
		OAuth2DBPath: dbPath,
		OAuth2Issuer: "http://localhost:8080",
		ScheddName:   "test-schedd",
		ScheddAddr:   "127.0.0.1:9618",
	})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	tests := []struct {
		name           string
		scopeValue     interface{} // string or []string
		expectedStatus int
		expectedScopes string
	}{
		{
			name:           "Scope as space-separated string (RFC 7591)",
			scopeValue:     "openid profile mcp:read",
			expectedStatus: http.StatusCreated,
			expectedScopes: "openid profile mcp:read",
		},
		{
			name:           "Scope as array of strings",
			scopeValue:     []string{"openid", "mcp:write"},
			expectedStatus: http.StatusCreated,
			expectedScopes: "openid mcp:write",
		},
		{
			name:           "Scope omitted - use defaults",
			scopeValue:     nil,
			expectedStatus: http.StatusCreated,
		},
		{
			name:           "Scope as empty string",
			scopeValue:     "",
			expectedStatus: http.StatusCreated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			regReq := map[string]interface{}{
				"redirect_uris":  []string{"http://localhost:8080/callback"},
				"grant_types":    []string{"authorization_code"},
				"response_types": []string{"code"},
				"client_name":    "Test Client",
			}
			if tt.scopeValue != nil {
				regReq["scope"] = tt.scopeValue
			}

			reqBody, err := json.Marshal(regReq)
			if err != nil {
				t.Fatalf("Failed to marshal request: %v", err)
			}

			req := httptest.NewRequestWithContext(context.Background(), "POST", "/mcp/oauth2/register", bytes.NewReader(reqBody))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			server.handleOAuth2Register(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Fatalf("Expected status %d, got %d. Body: %s",
					tt.expectedStatus, rr.Code, rr.Body.String())
			}

			if rr.Code == http.StatusCreated && tt.expectedScopes != "" {
				var resp map[string]interface{}
				if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
					t.Fatalf("Failed to decode response: %v", err)
				}
				if got := resp["scope"].(string); got != tt.expectedScopes {
					t.Errorf("Expected scope %q, got %q", tt.expectedScopes, got)
				}
			}
		})
	}
}

// TestOAuth2MetadataScopes tests that the OAuth2 metadata includes all supported scopes
func TestOAuth2MetadataScopes(t *testing.T) {
	// Create temporary directory for test database
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_oauth2.db")

	// Create test logger
	logger, err := logging.New(&logging.Config{
		OutputPath: "stdout",
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Create server with OAuth2 enabled
	server, err := NewServer(Config{
		Logger:       logger,
		EnableMCP:    true,
		OAuth2DBPath: dbPath,
		OAuth2Issuer: "http://localhost:8080",
		ScheddName:   "test-schedd",
		ScheddAddr:   "127.0.0.1:9618",
	})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Create HTTP request
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/.well-known/oauth-authorization-server", nil)

	// Create response recorder
	rr := httptest.NewRecorder()

	// Call handler
	server.handleOAuth2Metadata(rr, req)

	// Check status code
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d. Body: %s", rr.Code, rr.Body.String())
	}

	// Decode response
	var metadata map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&metadata); err != nil {
		t.Fatalf("Failed to decode metadata: %v", err)
	}

	// Verify scopes_supported includes all expected scopes
	scopesSupported, ok := metadata["scopes_supported"].([]interface{})
	if !ok {
		t.Fatal("scopes_supported not found or not an array")
	}

	expectedScopes := map[string]bool{
		"openid":    false,
		"profile":   false,
		"email":     false,
		"mcp:read":  false,
		"mcp:write": false,
	}

	for _, scope := range scopesSupported {
		scopeStr, ok := scope.(string)
		if !ok {
			continue
		}
		if _, exists := expectedScopes[scopeStr]; exists {
			expectedScopes[scopeStr] = true
		}
	}

	// Check all expected scopes are present
	for scope, found := range expectedScopes {
		if !found {
			t.Errorf("Expected scope '%s' not found in scopes_supported", scope)
		}
	}

	// Verify registration_endpoint is present
	if regEndpoint, ok := metadata["registration_endpoint"].(string); !ok || regEndpoint == "" {
		t.Error("registration_endpoint not found or empty in metadata")
	}
}

// TestMain ensures cleanup of temporary files
func TestMain(m *testing.M) {
	code := m.Run()
	os.Exit(code)
}

// TestOAuth2ProtectedResourceMetadata tests the OAuth 2.0 Protected Resource metadata endpoint
func TestOAuth2ProtectedResourceMetadata(t *testing.T) {
	// Create temporary directory for test database
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_oauth2.db")

	// Create test logger
	logger, err := logging.New(&logging.Config{
		OutputPath: "stdout",
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Create server with OAuth2 enabled
	server, err := NewServer(Config{
		Logger:       logger,
		EnableMCP:    true,
		OAuth2DBPath: dbPath,
		OAuth2Issuer: "http://localhost:8080",
		ScheddName:   "test-schedd",
		ScheddAddr:   "127.0.0.1:9618",
	})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Create HTTP request
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/.well-known/oauth-protected-resource", nil)

	// Create response recorder
	rr := httptest.NewRecorder()

	// Call handler
	server.handleOAuth2ProtectedResourceMetadata(rr, req)

	// Check status code
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d. Body: %s", rr.Code, rr.Body.String())
	}

	// Decode response
	var metadata map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&metadata); err != nil {
		t.Fatalf("Failed to decode metadata: %v", err)
	}

	// Verify required fields
	if resource, ok := metadata["resource"].(string); !ok || resource == "" {
		t.Error("resource field missing or empty")
	}

	if authServers, ok := metadata["authorization_servers"].([]interface{}); !ok || len(authServers) == 0 {
		t.Error("authorization_servers field missing or empty")
	}

	if bearerMethods, ok := metadata["bearer_methods_supported"].([]interface{}); !ok || len(bearerMethods) == 0 {
		t.Error("bearer_methods_supported field missing or empty")
	}

	// Verify scopes_supported includes all expected scopes
	scopesSupported, ok := metadata["scopes_supported"].([]interface{})
	if !ok {
		t.Fatal("scopes_supported not found or not an array")
	}

	expectedScopes := map[string]bool{
		"openid":    false,
		"profile":   false,
		"email":     false,
		"mcp:read":  false,
		"mcp:write": false,
	}

	for _, scope := range scopesSupported {
		scopeStr, ok := scope.(string)
		if !ok {
			continue
		}
		if _, exists := expectedScopes[scopeStr]; exists {
			expectedScopes[scopeStr] = true
		}
	}

	// Check all expected scopes are present
	for scope, found := range expectedScopes {
		if !found {
			t.Errorf("Expected scope '%s' not found in scopes_supported", scope)
		}
	}
}

// TestWWWAuthenticateHeader tests that WWW-Authenticate headers are added for 401 responses
func TestWWWAuthenticateHeader(t *testing.T) {
	// Create temporary directory for test database
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_oauth2.db")

	// Create test logger
	logger, err := logging.New(&logging.Config{
		OutputPath: "stdout",
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Create server with OAuth2 enabled
	server, err := NewServer(Config{
		Logger:       logger,
		EnableMCP:    true,
		OAuth2DBPath: dbPath,
		OAuth2Issuer: "http://localhost:8080",
		ScheddName:   "test-schedd",
		ScheddAddr:   "127.0.0.1:9618",
	})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	tests := []struct {
		name                string
		statusCode          int
		errorCode           string
		errorDescription    string
		expectHeader        bool
		expectedRealm       string
		expectedError       string
		expectedDescription string
	}{
		{
			name:                "401 with error details",
			statusCode:          http.StatusUnauthorized,
			errorCode:           "invalid_token",
			errorDescription:    "The access token is invalid",
			expectHeader:        true,
			expectedRealm:       "http://localhost:8080",
			expectedError:       "invalid_token",
			expectedDescription: "The access token is invalid",
		},
		{
			name:             "401 without error details",
			statusCode:       http.StatusUnauthorized,
			errorCode:        "",
			errorDescription: "",
			expectHeader:     true,
			expectedRealm:    "http://localhost:8080",
		},
		{
			name:                "403 with insufficient_scope",
			statusCode:          http.StatusForbidden,
			errorCode:           "insufficient_scope",
			errorDescription:    "The request requires higher privileges",
			expectHeader:        true,
			expectedRealm:       "http://localhost:8080",
			expectedError:       "insufficient_scope",
			expectedDescription: "The request requires higher privileges",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create response recorder
			rr := httptest.NewRecorder()

			// Call writeOAuthError
			server.writeOAuthError(rr, tt.statusCode, tt.errorCode, tt.errorDescription)

			// Check status code
			if rr.Code != tt.statusCode {
				t.Errorf("Expected status %d, got %d", tt.statusCode, rr.Code)
			}

			// Check WWW-Authenticate header
			authHeader := rr.Header().Get("WWW-Authenticate")
			if tt.expectHeader {
				if authHeader == "" {
					t.Error("Expected WWW-Authenticate header, but it was missing")
				} else {
					// Verify header contains expected values
					if !strings.Contains(authHeader, "Bearer") {
						t.Errorf("WWW-Authenticate header should contain 'Bearer', got: %s", authHeader)
					}
					if !strings.Contains(authHeader, tt.expectedRealm) {
						t.Errorf("WWW-Authenticate header should contain realm '%s', got: %s", tt.expectedRealm, authHeader)
					}
					if tt.expectedError != "" && !strings.Contains(authHeader, tt.expectedError) {
						t.Errorf("WWW-Authenticate header should contain error '%s', got: %s", tt.expectedError, authHeader)
					}
					if tt.expectedDescription != "" && !strings.Contains(authHeader, tt.expectedDescription) {
						t.Errorf("WWW-Authenticate header should contain description '%s', got: %s", tt.expectedDescription, authHeader)
					}
				}
			} else if authHeader != "" {
				t.Errorf("Did not expect WWW-Authenticate header, but got: %s", authHeader)
			}
		})
	}
}
