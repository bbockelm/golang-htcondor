package httpserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bbockelm/golang-htcondor/logging"
)

// TestHandleWhoAmI tests the whoami endpoint handler
func TestHandleWhoAmI(t *testing.T) {
	// Create a test logger
	logger, err := logging.New(&logging.Config{
		OutputPath: "stderr",
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	t.Run("Authenticated with Bearer token", func(t *testing.T) {
		// Create a server with token cache
		s := &Server{
			logger:     logger,
			tokenCache: NewTokenCache(),
		}

		// Create a valid test JWT token
		token := createTestJWTToken(3600)

		// Create request with Bearer token
		req := httptest.NewRequest(http.MethodGet, "/api/v1/whoami", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		w := httptest.NewRecorder()

		// Call handler
		s.handleWhoAmI(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		// Check status code
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		// Decode response
		var whoamiResp WhoAmIResponse
		if err := json.NewDecoder(resp.Body).Decode(&whoamiResp); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		// Verify response
		if !whoamiResp.Authenticated {
			t.Error("Expected authenticated to be true")
		}

		if whoamiResp.User != "alice@test.domain" {
			t.Errorf("Expected user 'alice@test.domain', got '%s'", whoamiResp.User)
		}
	})

	t.Run("Unauthenticated - no token", func(t *testing.T) {
		s := &Server{
			logger:     logger,
			tokenCache: NewTokenCache(),
		}

		// Create request without token
		req := httptest.NewRequest(http.MethodGet, "/api/v1/whoami", nil)

		w := httptest.NewRecorder()

		// Call handler
		s.handleWhoAmI(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		// Check status code
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		// Decode response
		var whoamiResp WhoAmIResponse
		if err := json.NewDecoder(resp.Body).Decode(&whoamiResp); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		// Verify response
		if whoamiResp.Authenticated {
			t.Error("Expected authenticated to be false")
		}

		if whoamiResp.User != "" {
			t.Errorf("Expected empty user, got '%s'", whoamiResp.User)
		}
	})

	t.Run("Method not allowed", func(t *testing.T) {
		s := &Server{
			logger:     logger,
			tokenCache: NewTokenCache(),
		}

		// Create POST request (not allowed)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/whoami", nil)

		w := httptest.NewRecorder()

		// Call handler
		s.handleWhoAmI(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		// Check status code
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("Expected status 405, got %d", resp.StatusCode)
		}
	})

	t.Run("Authenticated with user header", func(t *testing.T) {
		// This test requires the signing key to exist, so we skip it
		// In a real test environment, you would set up the key properly
		t.Skip("Skipping user header test - requires proper signing key setup")
	})
}

// TestWhoAmIResponse tests the JSON marshaling of WhoAmIResponse
func TestWhoAmIResponse(t *testing.T) {
	t.Run("Authenticated response", func(t *testing.T) {
		resp := WhoAmIResponse{
			Authenticated: true,
			User:          "alice@test.domain",
		}

		data, err := json.Marshal(resp)
		if err != nil {
			t.Fatalf("Failed to marshal response: %v", err)
		}

		// Unmarshal to verify
		var decoded WhoAmIResponse
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("Failed to unmarshal response: %v", err)
		}

		if decoded.Authenticated != resp.Authenticated {
			t.Error("Authenticated field mismatch")
		}

		if decoded.User != resp.User {
			t.Error("User field mismatch")
		}
	})

	t.Run("Unauthenticated response", func(t *testing.T) {
		resp := WhoAmIResponse{
			Authenticated: false,
		}

		data, err := json.Marshal(resp)
		if err != nil {
			t.Fatalf("Failed to marshal response: %v", err)
		}

		// Verify that the user field is omitted when empty
		var rawJSON map[string]interface{}
		if err := json.Unmarshal(data, &rawJSON); err != nil {
			t.Fatalf("Failed to unmarshal to map: %v", err)
		}

		if _, exists := rawJSON["user"]; exists {
			t.Error("Expected user field to be omitted when empty")
		}

		if rawJSON["authenticated"] != false {
			t.Error("Expected authenticated to be false")
		}
	})
}
