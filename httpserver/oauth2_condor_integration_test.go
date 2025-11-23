//go:build integration

//nolint:errcheck,noctx,gosec,errorlint,govet // Integration test file with acceptable test patterns
package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ory/fosite"
	"golang.org/x/crypto/bcrypt"
)

// TestCondorScopesIntegration tests the condor:/* scope functionality with a real HTCondor setup
func TestCondorScopesIntegration(t *testing.T) {
	// Skip if condor_master is not available
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH, skipping integration test")
	}

	// Create temporary directory for mini condor
	tempDir, err := os.MkdirTemp("", "htcondor-condor-scopes-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create secure socket directory
	socketDir, err := os.MkdirTemp("/tmp", "htc_sock_*")
	if err != nil {
		t.Fatalf("Failed to create socket directory: %v", err)
	}
	defer os.RemoveAll(socketDir)

	t.Logf("Using temporary directory: %s", tempDir)
	t.Logf("Using socket directory: %s", socketDir)

	// Print HTCondor logs on test failure
	defer func() {
		if t.Failed() {
			printHTCondorLogs(tempDir, t)
		}
	}()

	// Generate signing key for HTCondor authentication in passwords.d directory
	passwordsDir := filepath.Join(tempDir, "passwords.d")
	if err := os.MkdirAll(passwordsDir, 0700); err != nil {
		t.Fatalf("Failed to create passwords.d directory: %v", err)
	}
	poolKeyPath := filepath.Join(passwordsDir, "POOL")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	if err := os.WriteFile(poolKeyPath, key, 0600); err != nil {
		t.Fatalf("Failed to write signing key: %v", err)
	}

	trustDomain := "test.htcondor.org"

	// Write mini condor configuration
	configFile := filepath.Join(tempDir, "condor_config")
	if err := writeMiniCondorConfig(configFile, tempDir, socketDir, passwordsDir, trustDomain, t); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	// Set CONDOR_CONFIG environment variable
	os.Setenv("CONDOR_CONFIG", configFile)
	defer os.Unsetenv("CONDOR_CONFIG")

	// Start condor_master
	t.Log("Starting condor_master...")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	condorMaster, err := startCondorMaster(ctx, configFile, tempDir)
	if err != nil {
		t.Fatalf("Failed to start condor_master: %v", err)
	}
	defer stopCondorMaster(condorMaster, t)

	// Wait for condor to be ready
	t.Log("Waiting for HTCondor to be ready...")
	if err := waitForCondor(tempDir, 60*time.Second, t); err != nil {
		t.Fatalf("Condor failed to start: %v", err)
	}

	// Get schedd address
	scheddAddr, err := getScheddAddress(tempDir, 30*time.Second)
	if err != nil {
		t.Fatalf("Failed to get schedd address: %v", err)
	}
	t.Logf("Schedd address: %s", scheddAddr)

	// Create OAuth2 database
	oauth2DBPath := filepath.Join(tempDir, "oauth2.db")

	// Start HTTP server
	serverAddr := "127.0.0.1:18082"
	baseURL := "http://" + serverAddr

	server, err := NewServer(Config{
		ListenAddr:     serverAddr,
		ScheddName:     "local",
		ScheddAddr:     scheddAddr,
		UserHeader:     "X-Test-User",
		SigningKeyPath: poolKeyPath,
		TrustDomain:    trustDomain,
		UIDDomain:      trustDomain,
		EnableMCP:      true,
		OAuth2DBPath:   oauth2DBPath,
		OAuth2Issuer:   baseURL,
	})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	go func() {
		if err := server.Start(); err != nil && err != http.ErrServerClosed {
			t.Logf("Server error: %v", err)
		}
	}()
	defer server.Shutdown(context.Background())

	// Wait for server to start
	time.Sleep(500 * time.Millisecond)

	// Create HTTP client
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Test 1: Register OAuth2 client with condor scopes
	t.Run("RegisterClientWithCondorScopes", func(t *testing.T) {
		clientID, clientSecret := registerOAuth2ClientWithCondorScopes(t, server.oauth2Provider.GetStorage())
		t.Logf("Registered client: %s", clientID)

		// Test 2: Request token with condor:/READ scope
		t.Run("RequestTokenWithCondorReadScope", func(t *testing.T) {
			token, refreshToken := getOAuth2TokenWithCondorScopes(t, httpClient, baseURL, clientID, clientSecret, "testuser", []string{"condor:/READ"})
			t.Logf("Received access token: %s...", token[:min(50, len(token))])

			// Verify the token is a JWT (3 parts separated by dots)
			parts := strings.Split(token, ".")
			if len(parts) != 3 {
				t.Errorf("Token should be a JWT with 3 parts, got %d parts", len(parts))
			}

			// Verify refresh token is present
			if refreshToken == "" {
				t.Error("Refresh token should not be empty")
			}
		})

		// Test 3: Request token with condor:/WRITE scope
		t.Run("RequestTokenWithCondorWriteScope", func(t *testing.T) {
			token, refreshToken := getOAuth2TokenWithCondorScopes(t, httpClient, baseURL, clientID, clientSecret, "testuser", []string{"condor:/WRITE"})
			t.Logf("Received access token: %s...", token[:min(50, len(token))])

			// Verify the token is a JWT
			parts := strings.Split(token, ".")
			if len(parts) != 3 {
				t.Errorf("Token should be a JWT with 3 parts, got %d parts", len(parts))
			}

			// Verify refresh token is present
			if refreshToken == "" {
				t.Error("Refresh token should not be empty")
			}
		})

		// Test 4: Request token with multiple condor scopes
		t.Run("RequestTokenWithMultipleCondorScopes", func(t *testing.T) {
			scopes := []string{"condor:/READ", "condor:/ADVERTISE_STARTD"}
			token, refreshToken := getOAuth2TokenWithCondorScopes(t, httpClient, baseURL, clientID, clientSecret, "testuser", scopes)
			t.Logf("Received access token: %s...", token[:min(50, len(token))])

			// Verify the token is a JWT
			parts := strings.Split(token, ".")
			if len(parts) != 3 {
				t.Errorf("Token should be a JWT with 3 parts, got %d parts", len(parts))
			}

			// Verify refresh token is present
			if refreshToken == "" {
				t.Error("Refresh token should not be empty")
			}
		})

		// Test 5: Token refresh flow with condor scopes
		t.Run("TokenRefreshWithCondorScopes", func(t *testing.T) {
			// Get initial token with condor scopes
			scopes := []string{"condor:/READ", "condor:/WRITE"}
			initialToken, refreshToken := getOAuth2TokenWithCondorScopes(t, httpClient, baseURL, clientID, clientSecret, "testuser", scopes)
			t.Logf("Initial access token: %s...", initialToken[:min(50, len(initialToken))])
			t.Logf("Refresh token: %s...", refreshToken[:min(50, len(refreshToken))])

			if refreshToken == "" {
				t.Fatal("Refresh token should not be empty")
			}

			// Wait a moment to ensure timestamps differ
			time.Sleep(1 * time.Second)

			// Use refresh token to get a new access token
			newToken := refreshOAuth2Token(t, httpClient, baseURL, clientID, clientSecret, refreshToken)
			t.Logf("Refreshed access token: %s...", newToken[:min(50, len(newToken))])

			// Verify the new token is also a JWT
			parts := strings.Split(newToken, ".")
			if len(parts) != 3 {
				t.Errorf("Refreshed token should be a JWT with 3 parts, got %d parts", len(parts))
			}

			// Tokens should be different (different timestamps at minimum)
			if newToken == initialToken {
				t.Error("Refreshed token should be different from initial token")
			}
		})

		// Test 6: Request token without condor scopes (legacy behavior)
		t.Run("RequestTokenWithoutCondorScopes", func(t *testing.T) {
			// This should return a standard OAuth2 token, not an IDTOKEN
			token, refreshToken := getOAuth2TokenWithCondorScopes(t, httpClient, baseURL, clientID, clientSecret, "testuser", []string{"mcp:read"})
			t.Logf("Received access token (legacy): %s...", token[:min(50, len(token))])
			// Legacy tokens are opaque and not JWTs

			// Verify refresh token is present even for legacy flow
			if refreshToken == "" {
				t.Error("Refresh token should not be empty even for legacy flow")
			}
		})
	})
}

// getOAuth2TokenWithCondorScopes obtains an OAuth2 access token with specified condor scopes using authorization code flow
func getOAuth2TokenWithCondorScopes(t *testing.T, httpClient *http.Client, baseURL, clientID, clientSecret, username string, scopes []string) (string, string) {
	// Add offline_access scope to get refresh token
	scopesWithOffline := append([]string{}, scopes...)
	scopesWithOffline = append(scopesWithOffline, "offline_access")
	scopeStr := strings.Join(scopesWithOffline, "+")

	// Step 1: Create authorization request
	authURL := fmt.Sprintf("%s/mcp/oauth2/authorize?response_type=code&client_id=%s&redirect_uri=http://localhost:18082/callback&scope=%s&state=teststate&username=%s",
		baseURL, clientID, scopeStr, username)

	req, err := http.NewRequest("GET", authURL, nil)
	if err != nil {
		t.Fatalf("Failed to create auth request: %v", err)
	}
	req.Header.Set("X-Test-User", username)

	// Don't follow redirects automatically
	originalCheckRedirect := httpClient.CheckRedirect
	httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	defer func() { httpClient.CheckRedirect = originalCheckRedirect }()

	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to send auth request: %v", err)
	}
	defer resp.Body.Close()

	t.Logf("Authorization response: status=%d", resp.StatusCode)

	// Accept both 302 (Found) and 303 (See Other) as valid OAuth2 redirects
	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Authorization request failed: status %d, body: %s", resp.StatusCode, string(body))
	}

	// Extract authorization code from redirect
	location := resp.Header.Get("Location")
	if location == "" {
		t.Fatal("No redirect location in authorization response")
	}

	t.Logf("Redirect location: %s", location)

	// Check if the redirect contains an error
	if redirectURL, parseErr := url.Parse(location); parseErr == nil {
		if errorCode := redirectURL.Query().Get("error"); errorCode != "" {
			errorDesc := redirectURL.Query().Get("error_description")
			t.Fatalf("OAuth2 error in redirect: %s - %s", errorCode, errorDesc)
		}
	}

	// Check if we were redirected to the consent page
	if strings.Contains(location, "/mcp/oauth2/consent") {
		t.Log("Redirected to consent page, approving...")

		// Extract state from consent URL
		consentURL, err := url.Parse(location)
		if err != nil {
			t.Fatalf("Failed to parse consent URL: %v", err)
		}
		state := consentURL.Query().Get("state")
		if state == "" {
			t.Fatal("No state parameter in consent URL")
		}

		// Submit consent form
		consentReq, err := http.NewRequest("POST", baseURL+"/mcp/oauth2/consent", bytes.NewBufferString(
			fmt.Sprintf("state=%s&action=approve", state),
		))
		if err != nil {
			t.Fatalf("Failed to create consent request: %v", err)
		}
		consentReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		consentReq.Header.Set("X-Test-User", username) // Ensure we are still the same user

		consentResp, err := httpClient.Do(consentReq)
		if err != nil {
			t.Fatalf("Failed to send consent request: %v", err)
		}
		defer consentResp.Body.Close()

		// Should be redirected back to callback
		if consentResp.StatusCode != http.StatusFound && consentResp.StatusCode != http.StatusSeeOther {
			body, _ := io.ReadAll(consentResp.Body)
			t.Fatalf("Consent request failed: status %d, body: %s", consentResp.StatusCode, string(body))
		}

		location = consentResp.Header.Get("Location")
		t.Logf("Consent redirect location: %s", location)
	}

	// Parse the authorization code from the redirect URL
	code := extractCodeFromURL(t, location)
	if code == "" {
		t.Fatal("No authorization code in redirect URL")
	}

	t.Logf("Received authorization code: %s...", code[:min(10, len(code))])

	// Step 2: Exchange authorization code for access token
	tokenReq, err := http.NewRequest("POST", baseURL+"/mcp/oauth2/token", bytes.NewBufferString(
		fmt.Sprintf("grant_type=authorization_code&code=%s&redirect_uri=http://localhost:18082/callback&client_id=%s&client_secret=%s",
			code, clientID, clientSecret),
	))
	if err != nil {
		t.Fatalf("Failed to create token request: %v", err)
	}

	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	tokenResp, err := httpClient.Do(tokenReq)
	if err != nil {
		t.Fatalf("Failed to send token request: %v", err)
	}
	defer tokenResp.Body.Close()

	body, _ := io.ReadAll(tokenResp.Body)
	if tokenResp.StatusCode != http.StatusOK {
		t.Fatalf("Token request failed: status %d, body: %s", tokenResp.StatusCode, string(body))
	}

	var tokenRespData struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		Scope        string `json:"scope"`
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.Unmarshal(body, &tokenRespData); err != nil {
		t.Fatalf("Failed to decode token response: %v, body: %s", err, string(body))
	}

	if tokenRespData.AccessToken == "" {
		t.Fatal("Empty access token received")
	}

	t.Logf("Token response: token_type=%s, expires_in=%d, scope=%s",
		tokenRespData.TokenType, tokenRespData.ExpiresIn, tokenRespData.Scope)

	return tokenRespData.AccessToken, tokenRespData.RefreshToken
}

// refreshOAuth2Token uses a refresh token to obtain a new access token
func refreshOAuth2Token(t *testing.T, httpClient *http.Client, baseURL, clientID, clientSecret, refreshToken string) string {
	t.Helper()

	// Exchange refresh token for new access token
	tokenReq, err := http.NewRequest("POST", baseURL+"/mcp/oauth2/token", bytes.NewBufferString(
		fmt.Sprintf("grant_type=refresh_token&refresh_token=%s&client_id=%s&client_secret=%s",
			refreshToken, clientID, clientSecret),
	))
	if err != nil {
		t.Fatalf("Failed to create refresh token request: %v", err)
	}

	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	tokenResp, err := httpClient.Do(tokenReq)
	if err != nil {
		t.Fatalf("Failed to send refresh token request: %v", err)
	}
	defer tokenResp.Body.Close()

	body, _ := io.ReadAll(tokenResp.Body)
	if tokenResp.StatusCode != http.StatusOK {
		t.Fatalf("Refresh token request failed: status %d, body: %s", tokenResp.StatusCode, string(body))
	}

	var tokenRespData struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		Scope        string `json:"scope"`
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.Unmarshal(body, &tokenRespData); err != nil {
		t.Fatalf("Failed to decode refresh token response: %v, body: %s", err, string(body))
	}

	if tokenRespData.AccessToken == "" {
		t.Fatal("Empty access token received from refresh")
	}

	t.Logf("Refresh token response: token_type=%s, expires_in=%d, scope=%s",
		tokenRespData.TokenType, tokenRespData.ExpiresIn, tokenRespData.Scope)

	return tokenRespData.AccessToken
}

// Helper to register a client with condor scopes support
func registerOAuth2ClientWithCondorScopes(t *testing.T, storage *OAuth2Storage) (string, string) {
	t.Helper()
	clientID := fmt.Sprintf("test_client_%d", time.Now().UnixNano())
	clientSecret := "test_secret_" + clientID

	// Hash the client secret with bcrypt
	hashedSecret, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash client secret: %v", err)
	}

	client := &fosite.DefaultClient{
		ID:            clientID,
		Secret:        hashedSecret,
		RedirectURIs:  []string{"http://localhost:18082/callback"},
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid", "offline_access", "mcp:read", "mcp:write", "condor:/READ", "condor:/WRITE", "condor:/ADVERTISE_STARTD"},
		Public:        false,
	}

	if err := storage.CreateClient(context.Background(), client); err != nil {
		t.Fatalf("Failed to create OAuth2 client: %v", err)
	}

	return clientID, clientSecret
}
