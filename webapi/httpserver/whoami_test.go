package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestHandleWhoAmI tests the whoami endpoint handler
func TestHandleWhoAmI(t *testing.T) {
	// A bearer token authenticates the REQUEST; it does not by itself
	// name the caller.
	//
	// This server verifies no JWT signatures -- the schedd is the trust
	// root -- so the sub claim is not an identity until a schedd op has
	// succeeded with the token or the schedd has been asked who the
	// caller is. With no schedd reachable here, the honest answer is a
	// request that carried a credential and a user we cannot name.
	//
	// This subtest used to assert the sub WAS the identity, which held
	// only because TokenCache.Add marked every freshly parsed token
	// validated -- the behaviour that let a forged signature resolve to
	// its own sub.
	t.Run("Authenticated with Bearer token", func(t *testing.T) {
		// Create a server with token cache
		s, err := NewServer(newTestConfig(t))
		if err != nil {
			t.Fatalf("Failed to create server: %v", err)
		}

		// Create a valid test JWT token
		token := createTestJWTToken(3600)

		// Create request with Bearer token
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/whoami", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		w := httptest.NewRecorder()

		// Call handler
		s.handleWhoAmI(w, req)

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

		// Decode response
		var whoamiResp WhoAmIResponse
		if err := json.NewDecoder(resp.Body).Decode(&whoamiResp); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		// Verify response
		if !whoamiResp.Authenticated {
			t.Error("Expected authenticated to be true")
		}

		if whoamiResp.User != "" {
			t.Errorf("User = %q, want empty: the sub of an unvalidated token is not an identity",
				whoamiResp.User)
		}
	})

	t.Run("Unauthenticated - no token", func(t *testing.T) {
		s, err := NewServer(newTestConfig(t))
		if err != nil {
			t.Fatalf("Failed to create server: %v", err)
		}

		// Create request without token
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/whoami", nil)

		w := httptest.NewRecorder()

		// Call handler
		s.handleWhoAmI(w, req)

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
		s, err := NewServer(newTestConfig(t))
		if err != nil {
			t.Fatalf("Failed to create server: %v", err)
		}

		// Create POST request (not allowed)
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/whoami", nil)

		w := httptest.NewRecorder()

		// Call handler
		s.handleWhoAmI(w, req)

		resp := w.Result()
		defer func() {
			if err := resp.Body.Close(); err != nil {
				t.Errorf("Failed to close response body: %v", err)
			}
		}()

		// Check status code
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("Expected status 405, got %d", resp.StatusCode)
		}
	})

	// The user-header path, which this subtest asserted nothing about
	// for as long as it has existed: its whole body was a t.Skip whose
	// stated reason -- "requires proper signing key setup" -- is a
	// 32-byte file. It appeared in CI as a skip and in the summary as a
	// test.
	//
	// Worth covering for real: header authentication is how a
	// deployment behind an authenticating proxy identifies every
	// caller, and how the integration tests in this package
	// authenticate. A break here reads as "authentication failed"
	// everywhere downstream.
	t.Run("Authenticated with user header", func(t *testing.T) {
		cfg := newTestConfig(t)
		cfg.SigningKeyPath = writeTestSigningKey(t)
		cfg.UserHeader = "X-Remote-User"
		// The header is honored only from a trusted source; httptest
		// requests come from 192.0.2.1, which is no proxy CIDR.
		cfg.UserHeaderTrustAnyUnsafe = true
		cfg.TrustDomain = "test.htcondor.org"
		cfg.UIDDomain = "uid.test.htcondor.org"

		s, err := NewServer(cfg)
		if err != nil {
			t.Fatalf("Failed to create server: %v", err)
		}

		req := httptest.NewRequestWithContext(context.Background(),
			http.MethodGet, "/api/v1/whoami", nil)
		req.Header.Set("X-Remote-User", "alice")

		w := httptest.NewRecorder()
		s.handleWhoAmI(w, req)

		resp := w.Result()
		defer func() {
			if err := resp.Body.Close(); err != nil {
				t.Errorf("Failed to close response body: %v", err)
			}
		}()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status 200, got %d", resp.StatusCode)
		}

		var whoamiResp WhoAmIResponse
		if err := json.NewDecoder(resp.Body).Decode(&whoamiResp); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if !whoamiResp.Authenticated {
			t.Error("Expected authenticated=true for a trusted user header")
		}
		// The bare header value, not "alice@uid.test.htcondor.org".
		// The two are deliberately different: the token minted for the
		// schedd carries the UID domain, while the identity in context
		// is what owner scoping compares against Owner, and HTCondor's
		// Owner attribute is the bare username.
		if want := "alice"; whoamiResp.User != want {
			t.Errorf("User = %q, want %q", whoamiResp.User, want)
		}
	})

	// The other half of the same contract, which turns out to be
	// enforced earlier and harder than at request time: a UserHeader
	// with no trust policy is refused at construction, so a deployment
	// cannot come up in a state where anyone who reaches the listener
	// directly authenticates as anyone.
	t.Run("User header with no trust policy refuses to start", func(t *testing.T) {
		cfg := newTestConfig(t)
		cfg.SigningKeyPath = writeTestSigningKey(t)
		cfg.UserHeader = "X-Remote-User"
		cfg.TrustDomain = "test.htcondor.org"
		cfg.UIDDomain = "uid.test.htcondor.org"
		// Neither UserHeaderTrustedProxies nor UserHeaderTrustAnyUnsafe.

		if _, err := NewServer(cfg); err == nil {
			t.Fatal("NewServer accepted a user header with no trusted-proxy policy")
		} else if !strings.Contains(err.Error(), "UserHeaderTrustedProxies") {
			t.Errorf("the error does not name what is missing: %v", err)
		}
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
