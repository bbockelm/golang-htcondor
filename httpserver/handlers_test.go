package httpserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestParseJobID tests the parseJobID helper function
func TestParseJobID(t *testing.T) {
	tests := []struct {
		name        string
		jobID       string
		wantCluster int
		wantProc    int
		wantErr     bool
	}{
		{"valid job ID", "123.0", 123, 0, false},
		{"valid job ID with proc", "456.7", 456, 7, false},
		{"invalid format - no dot", "123", 0, 0, true},
		{"invalid format - multiple dots", "123.4.5", 0, 0, true},
		{"invalid cluster", "abc.0", 0, 0, true},
		{"invalid proc", "123.xyz", 0, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cluster, proc, err := parseJobID(tt.jobID)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseJobID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if cluster != tt.wantCluster {
					t.Errorf("parseJobID() cluster = %v, want %v", cluster, tt.wantCluster)
				}
				if proc != tt.wantProc {
					t.Errorf("parseJobID() proc = %v, want %v", proc, tt.wantProc)
				}
			}
		})
	}
}

// TestCollectorAdsResponse verifies the response structure for collector ads
func TestCollectorAdsResponse(t *testing.T) {
	response := CollectorAdsResponse{
		Ads: nil,
	}

	if response.Ads != nil {
		t.Error("Expected nil ads in empty response")
	}
}

// testHealthEndpoint is a helper function to test health check endpoints
func testHealthEndpoint(t *testing.T, handlerFunc func(http.ResponseWriter, *http.Request), path string, expectedStatus string) {
	t.Helper()

	tests := []struct {
		name           string
		method         string
		wantStatusCode int
		wantStatus     string
	}{
		{
			name:           "GET " + path + " returns " + expectedStatus,
			method:         http.MethodGet,
			wantStatusCode: http.StatusOK,
			wantStatus:     expectedStatus,
		},
		{
			name:           "POST " + path + " returns Method Not Allowed",
			method:         http.MethodPost,
			wantStatusCode: http.StatusMethodNotAllowed,
			wantStatus:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, path, nil)
			w := httptest.NewRecorder()

			handlerFunc(w, req)

			resp := w.Result()
			defer func() {
				if err := resp.Body.Close(); err != nil {
					t.Errorf("Failed to close response body: %v", err)
				}
			}()

			if resp.StatusCode != tt.wantStatusCode {
				t.Errorf("handler status = %v, want %v", resp.StatusCode, tt.wantStatusCode)
			}

			if tt.wantStatus != "" {
				var response map[string]string
				if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
					t.Fatalf("Failed to decode response: %v", err)
				}
				if response["status"] != tt.wantStatus {
					t.Errorf("handler response status = %v, want %v", response["status"], tt.wantStatus)
				}
			}
		})
	}
}

// TestHealthzEndpoint verifies the /healthz endpoint returns OK
func TestHealthzEndpoint(t *testing.T) {
	testHealthEndpoint(t, (&Server{}).handleHealthz, "/healthz", "ok")
}

// TestReadyzEndpoint verifies the /readyz endpoint returns ready status
func TestReadyzEndpoint(t *testing.T) {
	testHealthEndpoint(t, (&Server{}).handleReadyz, "/readyz", "ready")
}

// TestLogoutEndpoint verifies the /logout endpoint clears session cookies
func TestLogoutEndpoint(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		cookies        []*http.Cookie
		wantStatusCode int
		wantStatus     string
		wantMessage    string
		checkCookies   bool
	}{
		{
			name:           "POST /logout without cookies returns success",
			method:         http.MethodPost,
			cookies:        nil,
			wantStatusCode: http.StatusOK,
			wantStatus:     "success",
			wantMessage:    "Logged out successfully",
			checkCookies:   false,
		},
		{
			name:   "POST /logout with cookies clears them",
			method: http.MethodPost,
			cookies: []*http.Cookie{
				{Name: "session_id", Value: "test-session-123"},
				{Name: "auth_token", Value: "test-token-456"},
			},
			wantStatusCode: http.StatusOK,
			wantStatus:     "success",
			wantMessage:    "Logged out successfully",
			checkCookies:   true,
		},
		{
			name:           "GET /logout returns Method Not Allowed",
			method:         http.MethodGet,
			cookies:        nil,
			wantStatusCode: http.StatusMethodNotAllowed,
			wantStatus:     "",
			wantMessage:    "",
			checkCookies:   false,
		},
		{
			name:           "PUT /logout returns Method Not Allowed",
			method:         http.MethodPut,
			cookies:        nil,
			wantStatusCode: http.StatusMethodNotAllowed,
			wantStatus:     "",
			wantMessage:    "",
			checkCookies:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/logout", nil)

			// Add cookies to request if provided
			for _, cookie := range tt.cookies {
				req.AddCookie(cookie)
			}

			w := httptest.NewRecorder()

			// Create a minimal server instance for testing
			server := &Server{}
			server.handleLogout(w, req)

			resp := w.Result()
			defer func() {
				if err := resp.Body.Close(); err != nil {
					t.Errorf("Failed to close response body: %v", err)
				}
			}()

			if resp.StatusCode != tt.wantStatusCode {
				t.Errorf("handler status = %v, want %v", resp.StatusCode, tt.wantStatusCode)
			}

			if tt.wantStatus != "" {
				var response map[string]string
				if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
					t.Fatalf("Failed to decode response: %v", err)
				}
				if response["status"] != tt.wantStatus {
					t.Errorf("handler response status = %v, want %v", response["status"], tt.wantStatus)
				}
				if response["message"] != tt.wantMessage {
					t.Errorf("handler response message = %v, want %v", response["message"], tt.wantMessage)
				}
			}

			// Verify cookies are cleared when checkCookies is true
			if tt.checkCookies {
				respCookies := resp.Cookies()
				// We should have at least as many cookies as we sent
				// (may have additional session cookie cleared)
				if len(respCookies) < len(tt.cookies) {
					t.Errorf("Expected at least %d cookies to be cleared, got %d", len(tt.cookies), len(respCookies))
				}

				// Check that each cookie is set to expire
				for _, respCookie := range respCookies {
					if respCookie.MaxAge != -1 {
						t.Errorf("Cookie %s MaxAge = %v, want -1", respCookie.Name, respCookie.MaxAge)
					}
					if respCookie.Value != "" {
						t.Errorf("Cookie %s Value = %v, want empty string", respCookie.Name, respCookie.Value)
					}
					if respCookie.Path != "/" {
						t.Errorf("Cookie %s Path = %v, want /", respCookie.Name, respCookie.Path)
					}
					if !respCookie.HttpOnly {
						t.Errorf("Cookie %s HttpOnly = %v, want true", respCookie.Name, respCookie.HttpOnly)
					}
				}
			}
		})
	}
}

// TestLogoutEndpointWithSessionStore verifies the /logout endpoint clears session from SQL store
func TestLogoutEndpointWithSessionStore(t *testing.T) {
	// Create an in-memory database and session store for testing
	store := createTestSessionStore(t, 1*time.Hour)

	// Create a test session
	sessionID, _, err := store.Create("testuser")
	if err != nil {
		t.Fatalf("Failed to create test session: %v", err)
	}

	// Verify session exists in store before logout
	sessionBefore := store.Get(sessionID)
	if sessionBefore == nil {
		t.Fatal("Session should exist before logout")
	}
	if sessionBefore.Username != "testuser" {
		t.Errorf("Session username = %v, want testuser", sessionBefore.Username)
	}

	// Create a request with the session cookie
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(&http.Cookie{
		Name:  sessionCookieName,
		Value: sessionID,
	})

	w := httptest.NewRecorder()

	// Create a server instance with the session store
	server := &Server{
		sessionStore: store,
	}
	server.handleLogout(w, req)

	resp := w.Result()
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Errorf("Failed to close response body: %v", err)
		}
	}()

	// Verify successful response
	if resp.StatusCode != http.StatusOK {
		t.Errorf("handler status = %v, want %v", resp.StatusCode, http.StatusOK)
	}

	var response map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if response["status"] != "success" {
		t.Errorf("handler response status = %v, want %v", response["status"], "success")
	}

	// Verify session was deleted from the SQL store
	if retrieved := store.Get(sessionID); retrieved != nil {
		t.Errorf("Session should be deleted from store after logout, but got session for user %s", retrieved.Username)
	}

	// Verify the session cookie was cleared
	cookies := resp.Cookies()
	var sessionCookieCleared bool
	for _, cookie := range cookies {
		if cookie.Name == sessionCookieName {
			sessionCookieCleared = true
			if cookie.MaxAge != -1 {
				t.Errorf("Session cookie MaxAge = %v, want -1", cookie.MaxAge)
			}
			if cookie.Value != "" {
				t.Errorf("Session cookie Value = %v, want empty string", cookie.Value)
			}
		}
	}
	if !sessionCookieCleared {
		t.Error("Session cookie should be cleared in response")
	}

}

// TestHandleJobFile tests the handleJobFile handler
func TestHandleJobFile(t *testing.T) {
	tests := []struct {
		name               string
		method             string
		filename           string
		wantStatusCode     int
		wantErr            bool
		wantContentType    string
		wantContentPattern string
	}{
		{
			name:            "POST method not allowed",
			method:          http.MethodPost,
			filename:        "test.txt",
			wantStatusCode:  http.StatusMethodNotAllowed,
			wantErr:         true,
			wantContentType: "",
		},
		{
			name:            "empty filename returns bad request",
			method:          http.MethodGet,
			filename:        "",
			wantStatusCode:  http.StatusBadRequest,
			wantErr:         true,
			wantContentType: "",
		},
		{
			name:            "path traversal with .. rejected",
			method:          http.MethodGet,
			filename:        "../etc/passwd",
			wantStatusCode:  http.StatusBadRequest,
			wantErr:         true,
			wantContentType: "",
		},
		{
			name:            "path traversal with / rejected",
			method:          http.MethodGet,
			filename:        "etc/passwd",
			wantStatusCode:  http.StatusBadRequest,
			wantErr:         true,
			wantContentType: "",
		},
		{
			name:            "path traversal with backslash rejected",
			method:          http.MethodGet,
			filename:        "etc\\passwd",
			wantStatusCode:  http.StatusBadRequest,
			wantErr:         true,
			wantContentType: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/api/v1/jobs/123.0/files/"+tt.filename, nil)
			w := httptest.NewRecorder()

			// Create a minimal server instance for testing
			server := &Server{}
			server.handleJobFile(w, req, 123, 0, tt.filename)

			resp := w.Result()
			defer func() {
				if err := resp.Body.Close(); err != nil {
					t.Errorf("Failed to close response body: %v", err)
				}
			}()

			if resp.StatusCode != tt.wantStatusCode {
				t.Errorf("handler status = %v, want %v", resp.StatusCode, tt.wantStatusCode)
			}

			if tt.wantContentType != "" {
				gotContentType := resp.Header.Get("Content-Type")
				if gotContentType != tt.wantContentType {
					t.Errorf("Content-Type = %v, want %v", gotContentType, tt.wantContentType)
				}
			}
		})
	}
}
