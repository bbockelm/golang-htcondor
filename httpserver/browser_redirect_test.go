package httpserver

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bbockelm/golang-htcondor/logging"
	"golang.org/x/oauth2"
)

// TestIsBrowserRequest tests the browser detection logic
func TestIsBrowserRequest(t *testing.T) {
	tests := []struct {
		name        string
		acceptHeader string
		expected    bool
	}{
		{
			name:        "Browser request with text/html",
			acceptHeader: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			expected:    true,
		},
		{
			name:        "Browser request with only text/html",
			acceptHeader: "text/html",
			expected:    true,
		},
		{
			name:        "API request with JSON",
			acceptHeader: "application/json",
			expected:    false,
		},
		{
			name:        "API request with XML",
			acceptHeader: "application/xml",
			expected:    false,
		},
		{
			name:        "Empty Accept header",
			acceptHeader: "",
			expected:    false,
		},
		{
			name:        "Wildcard Accept",
			acceptHeader: "*/*",
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/v1/jobs", nil)
			req.Header.Set("Accept", tt.acceptHeader)

			result := isBrowserRequest(req)
			if result != tt.expected {
				t.Errorf("isBrowserRequest() = %v, want %v for Accept: %s", result, tt.expected, tt.acceptHeader)
			}
		})
	}
}

// TestBrowserRedirectWithoutOAuth2 tests that browser requests without OAuth2 configured return error
func TestBrowserRedirectWithoutOAuth2(t *testing.T) {
	// Create a test server without OAuth2 configured
	server := &Server{
		oauth2Config: nil, // No OAuth2 provider
	}

	req := httptest.NewRequest("GET", "/api/v1/jobs", nil)
	req.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()

	// Call handleListJobs which requires authentication
	server.handleListJobs(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	// Should return 401 Unauthorized, not redirect
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", resp.StatusCode)
	}
}

// TestBrowserRedirectWithOAuth2 tests that browser requests with OAuth2 configured redirect
func TestBrowserRedirectWithOAuth2(t *testing.T) {
	// Create a test OAuth2 state store
	stateStore := NewOAuth2StateStore()

	// Create a test logger
	logConfig := &logging.Config{
		OutputPath:        "stderr",
		DestinationLevels: nil,
	}
	logger, err := logging.New(logConfig)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Create a test server with OAuth2 configured
	server := &Server{
		oauth2Config: &oauth2.Config{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://idp.example.com/authorize",
				TokenURL: "https://idp.example.com/token",
			},
			RedirectURL: "https://server.example.com/mcp/oauth2/callback",
			Scopes:      []string{"openid", "profile"},
		},
		oauth2StateStore: stateStore,
		logger:           logger,
	}

	req := httptest.NewRequest("GET", "/api/v1/jobs?constraint=true", nil)
	req.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()

	// Call handleListJobs which requires authentication
	server.handleListJobs(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	// Should redirect
	if resp.StatusCode != http.StatusFound {
		t.Errorf("Expected status 302 Found, got %d", resp.StatusCode)
	}

	// Check that redirect location is set
	location := resp.Header.Get("Location")
	if location == "" {
		t.Error("Expected Location header to be set")
	}

	// Verify it redirects to the IDP
	if location[:len("https://idp.example.com/authorize")] != "https://idp.example.com/authorize" {
		t.Errorf("Expected redirect to IDP auth URL, got %s", location)
	}
}

// TestWelcomePageUnauthenticated tests the welcome page for unauthenticated users
func TestWelcomePageUnauthenticated(t *testing.T) {
	server := &Server{
		oauth2Config: &oauth2.Config{
			ClientID: "test-client",
		},
	}

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	server.handleWelcome(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Check content type
	contentType := resp.Header.Get("Content-Type")
	if contentType != "text/html; charset=utf-8" {
		t.Errorf("Expected Content-Type text/html, got %s", contentType)
	}
}

// TestWelcomePageNotFound tests that non-root paths return 404
func TestWelcomePageNotFound(t *testing.T) {
	server := &Server{}

	req := httptest.NewRequest("GET", "/notfound", nil)
	w := httptest.NewRecorder()

	server.handleWelcome(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", resp.StatusCode)
	}
}

// TestOAuth2StateStoreOriginalURL tests that OAuth2 state store preserves original URL
func TestOAuth2StateStoreOriginalURL(t *testing.T) {
	store := NewOAuth2StateStore()

	// Generate state
	state, err := store.GenerateState()
	if err != nil {
		t.Fatalf("Failed to generate state: %v", err)
	}

	// Store with original URL
	originalURL := "/api/v1/jobs?constraint=Owner==\"alice\""
	store.StoreWithURL(state, nil, originalURL)

	// Retrieve
	ar, retrievedURL, ok := store.GetWithURL(state)
	if !ok {
		t.Error("Failed to retrieve state")
	}

	if ar != nil {
		t.Error("Expected nil authorize request for browser flow")
	}

	if retrievedURL != originalURL {
		t.Errorf("Expected original URL %s, got %s", originalURL, retrievedURL)
	}

	// Verify state is removed after retrieval (one-time use)
	_, _, ok = store.GetWithURL(state)
	if ok {
		t.Error("State should be removed after first retrieval")
	}
}
