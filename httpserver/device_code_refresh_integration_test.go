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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ory/fosite"
	"golang.org/x/crypto/bcrypt"
)

// TestDeviceCodeWithRefreshFlow tests device code flow followed by refresh token flow
func TestDeviceCodeWithRefreshFlow(t *testing.T) {
	// Skip if condor_master is not available
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH, skipping integration test")
	}

	// Create temporary directory for mini condor
	tempDir, err := os.MkdirTemp("", "htcondor-refresh-test-*")
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
	t.Log("HTCondor is ready!")

	// Find the actual schedd address
	scheddAddr, err := getScheddAddress(tempDir, 10*time.Second)
	if err != nil {
		t.Fatalf("Failed to get schedd address: %v", err)
	}
	t.Logf("Using schedd address: %s", scheddAddr)

	// Request port 0 to get a random available port
	serverAddr := "127.0.0.1:0"

	// OAuth2 database path
	oauth2DBPath := filepath.Join(tempDir, "oauth2.db")

	// Create HTTP server with MCP enabled (we'll update the URL after getting the actual port)
	server, err := NewServer(Config{
		ListenAddr:     serverAddr,
		ScheddName:     "local",
		ScheddAddr:     scheddAddr,
		UserHeader:     "X-Test-User",
		SigningKeyPath: passwordsDir,
		TrustDomain:    trustDomain,
		UIDDomain:      trustDomain,
		EnableMCP:      true,
		OAuth2DBPath:   oauth2DBPath,
		OAuth2Issuer:   "http://127.0.0.1:0", // Will use actual address from GetAddr()
	})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Start server in background
	serverErrChan := make(chan error, 1)
	go func() {
		serverErrChan <- server.Start()
	}()

	// Wait for server to start and get actual address
	time.Sleep(500 * time.Millisecond)

	// Get actual server address using GetAddr() method
	actualAddr := server.GetAddr()
	if actualAddr == "" {
		t.Fatalf("Failed to get server address")
	}

	baseURL := fmt.Sprintf("http://%s", actualAddr)
	t.Logf("HTTP server listening on: %s", baseURL)

	// Update OAuth2 issuer with actual address
	server.GetOAuth2Provider().UpdateIssuer(baseURL)

	// Wait for server to be ready
	t.Logf("Waiting for server to be ready on %s", baseURL)
	if err := waitForServer(baseURL, 10*time.Second); err != nil {
		t.Fatalf("Server failed to start: %v", err)
	}
	t.Logf("Server is ready on %s", baseURL)

	// Ensure server is stopped at the end
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			t.Logf("Warning: server shutdown error: %v", err)
		}
	}()

	// Create HTTP client
	client := &http.Client{Timeout: 30 * time.Second}

	// Test user for authentication
	testUser := "refreshuser"

	// Step 1: Create an OAuth2 client for device flow with refresh_token grant
	t.Log("Step 1: Creating OAuth2 client for device flow with refresh token support...")
	clientID, clientSecret := createDeviceFlowClientWithRefresh(t, server, testUser)
	t.Logf("OAuth2 client created: %s", clientID)

	// Step 2: Initiate device authorization
	t.Log("Step 2: Initiating device authorization...")
	deviceCode, userCode, verificationURI := initiateDeviceAuthorization(t, client, baseURL, clientID)
	t.Logf("Device code: %s", deviceCode)
	t.Logf("User code: %s", userCode)
	t.Logf("Verification URI: %s", verificationURI)

	// Step 3: User approves the device
	t.Log("Step 3: User approving device...")
	approveDevice(t, client, verificationURI, userCode, testUser)

	// Step 4: Poll for token (should succeed and get refresh token)
	t.Log("Step 4: Polling for token after authorization...")
	accessToken, refreshToken := pollForTokenWithRefresh(t, client, baseURL, clientID, clientSecret, deviceCode)
	t.Logf("Access token obtained: %s...", accessToken[:20])
	t.Logf("Refresh token obtained: %s...", refreshToken[:20])

	// Step 5: Use the refresh token to get a new access token
	t.Log("Step 5: Using refresh token to obtain new access token...")
	newAccessToken := useRefreshToken(t, client, baseURL, clientID, clientSecret, refreshToken)
	t.Logf("New access token obtained: %s...", newAccessToken[:20])

	// Step 6: Verify the new access token works
	t.Log("Step 6: Testing MCP API with refreshed token...")
	testMCPWithDeviceToken(t, client, baseURL, newAccessToken)

	// Step 7: Verify the old access token still works (hasn't been revoked)
	t.Log("Step 7: Testing MCP API with original token...")
	testMCPWithDeviceToken(t, client, baseURL, accessToken)

	t.Log("All device code flow with refresh token integration tests passed!")
}

// createDeviceFlowClientWithRefresh creates an OAuth2 client configured for device flow and refresh tokens
func createDeviceFlowClientWithRefresh(t *testing.T, server *Server, username string) (string, string) {
	storage := server.GetOAuth2Provider().GetStorage()

	clientID := "device-refresh-client"
	clientSecret := "device-refresh-secret"

	hashedSecret, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash client secret: %v", err)
	}

	client := &fosite.DefaultClient{
		ID:            clientID,
		Secret:        hashedSecret,
		RedirectURIs:  []string{}, // Device flow doesn't use redirect URIs
		GrantTypes:    []string{"urn:ietf:params:oauth:grant-type:device_code", "refresh_token"},
		ResponseTypes: []string{},
		Scopes:        []string{"openid", "mcp:read", "mcp:write", "offline_access"},
		Public:        false,
	}

	if err := storage.CreateClient(context.Background(), client); err != nil {
		t.Fatalf("Failed to create OAuth2 client: %v", err)
	}

	return clientID, clientSecret
}

// pollForTokenWithRefresh polls the token endpoint until access token is received
func pollForTokenWithRefresh(t *testing.T, httpClient *http.Client, baseURL, clientID, clientSecret, deviceCode string) (string, string) {
	maxAttempts := 10
	pollInterval := 2 * time.Second

	for i := 0; i < maxAttempts; i++ {
		if i > 0 {
			time.Sleep(pollInterval)
		}

		data := fmt.Sprintf("grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=%s&client_id=%s&client_secret=%s", deviceCode, clientID, clientSecret)
		req, err := http.NewRequest("POST", baseURL+"/mcp/oauth2/token", strings.NewReader(data))
		if err != nil {
			t.Fatalf("Failed to create token request: %v", err)
		}

		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := httpClient.Do(req)
		if err != nil {
			t.Fatalf("Failed to send token request: %v", err)
		}

		if resp.StatusCode == http.StatusOK {
			var tokenResp struct {
				AccessToken  string `json:"access_token"`
				TokenType    string `json:"token_type"`
				ExpiresIn    int    `json:"expires_in"`
				RefreshToken string `json:"refresh_token"`
				Scope        string `json:"scope"`
			}

			if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
				resp.Body.Close()
				t.Fatalf("Failed to decode token response: %v", err)
			}
			resp.Body.Close()

			if tokenResp.AccessToken == "" {
				t.Fatal("Empty access token received")
			}
			if tokenResp.RefreshToken == "" {
				t.Fatal("Empty refresh token received")
			}

			return tokenResp.AccessToken, tokenResp.RefreshToken
		}

		// Check for authorization_pending
		var errorResp struct {
			Error string `json:"error"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&errorResp); err == nil {
			resp.Body.Close()
			if errorResp.Error == "authorization_pending" {
				t.Logf("Attempt %d: Still pending, will retry...", i+1)
				continue
			}
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("Token request failed: status %d, body: %s", resp.StatusCode, string(body))
	}

	t.Fatal("Failed to get access token after max attempts")
	return "", ""
}

// useRefreshToken uses a refresh token to obtain a new access token
func useRefreshToken(t *testing.T, httpClient *http.Client, baseURL, clientID, clientSecret, refreshToken string) string {
	data := fmt.Sprintf("grant_type=refresh_token&refresh_token=%s&client_id=%s&client_secret=%s", refreshToken, clientID, clientSecret)
	req, err := http.NewRequest("POST", baseURL+"/mcp/oauth2/token", strings.NewReader(data))
	if err != nil {
		t.Fatalf("Failed to create refresh token request: %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to send refresh token request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Refresh token request failed: status %d, body: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("Failed to decode refresh token response: %v", err)
	}

	if tokenResp.AccessToken == "" {
		t.Fatal("Empty access token received from refresh")
	}

	return tokenResp.AccessToken
}
