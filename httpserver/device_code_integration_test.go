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

// TestDeviceCodeFlowIntegration tests the OAuth2 device code authorization flow
func TestDeviceCodeFlowIntegration(t *testing.T) {
	// Skip if condor_master is not available
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH, skipping integration test")
	}

	// Create temporary directory for mini condor
	tempDir, err := os.MkdirTemp("", "htcondor-device-test-*")
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
	t.Logf("Waiting for server to be fully ready")
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
	testUser := "deviceuser"

	// Step 1: Create an OAuth2 client for device flow
	t.Log("Step 1: Creating OAuth2 client for device flow...")
	clientID, _ := createDeviceFlowClient(t, server, testUser)
	t.Logf("OAuth2 client created: %s", clientID)

	// Step 2: Initiate device authorization
	t.Log("Step 2: Initiating device authorization...")
	deviceCode, userCode, verificationURI := initiateDeviceAuthorization(t, client, baseURL, clientID)
	t.Logf("Device code: %s", deviceCode)
	t.Logf("User code: %s", userCode)
	t.Logf("Verification URI: %s", verificationURI)

	// Step 3: Poll for token (should get authorization_pending)
	t.Log("Step 3: Polling for token (expecting authorization_pending)...")
	testPollBeforeAuthorization(t, client, baseURL, clientID, deviceCode)

	// Step 4: User approves the device
	t.Log("Step 4: User approving device...")
	approveDevice(t, client, verificationURI, userCode, testUser)

	// Step 5: Poll for token again (should succeed)
	t.Log("Step 5: Polling for token after authorization...")
	accessToken := pollForToken(t, client, baseURL, clientID, deviceCode)
	t.Logf("Access token obtained: %s...", accessToken[:20])

	// Step 6: Use the access token to call MCP API
	t.Log("Step 6: Testing MCP API with device flow token...")
	testMCPWithDeviceToken(t, client, baseURL, accessToken)

	t.Log("All device code flow integration tests passed!")
}

// createDeviceFlowClient creates an OAuth2 client configured for device flow
func createDeviceFlowClient(t *testing.T, server *Server, username string) (string, string) {
	storage := server.GetOAuth2Provider().GetStorage()

	clientID := "device-test-client"
	clientSecret := "device-test-secret"

	hashedSecret, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash client secret: %v", err)
	}

	client := &fosite.DefaultClient{
		ID:            clientID,
		Secret:        hashedSecret,
		RedirectURIs:  []string{},                                           // Device flow doesn't use redirect URIs
		GrantTypes:    []string{"urn:ietf:params:oauth:grant-type:device_code"}, // Device code grant type
		ResponseTypes: []string{},
		Scopes:        []string{"openid", "mcp:read", "mcp:write"},
		Public:        false,
	}

	if err := storage.CreateClient(context.Background(), client); err != nil {
		t.Fatalf("Failed to create OAuth2 client: %v", err)
	}

	return clientID, clientSecret
}

// initiateDeviceAuthorization initiates the device authorization flow
func initiateDeviceAuthorization(t *testing.T, httpClient *http.Client, baseURL, clientID string) (string, string, string) {
	data := fmt.Sprintf("client_id=%s&scope=openid+mcp:read+mcp:write", clientID)
	req, err := http.NewRequest("POST", baseURL+"/mcp/oauth2/device/authorize", strings.NewReader(data))
	if err != nil {
		t.Fatalf("Failed to create device auth request: %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to send device auth request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Device authorization failed: status %d, body: %s", resp.StatusCode, string(body))
	}

	var authResp struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int    `json:"expires_in"`
		Interval                int    `json:"interval"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		t.Fatalf("Failed to decode device auth response: %v", err)
	}

	if authResp.DeviceCode == "" || authResp.UserCode == "" {
		t.Fatal("Device authorization response missing required fields")
	}

	return authResp.DeviceCode, authResp.UserCode, authResp.VerificationURI
}

// testPollBeforeAuthorization tests polling before user authorization
func testPollBeforeAuthorization(t *testing.T, httpClient *http.Client, baseURL, clientID, deviceCode string) {
	data := fmt.Sprintf("grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=%s&client_id=%s", deviceCode, clientID)
	req, err := http.NewRequest("POST", baseURL+"/mcp/oauth2/token", strings.NewReader(data))
	if err != nil {
		t.Fatalf("Failed to create token request: %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to send token request: %v", err)
	}
	defer resp.Body.Close()

	// Should get authorization_pending error
	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected 400 Bad Request, got %d: %s", resp.StatusCode, string(body))
	}

	var errorResp struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&errorResp); err != nil {
		t.Fatalf("Failed to decode error response: %v", err)
	}

	if errorResp.Error != "authorization_pending" {
		t.Fatalf("Expected authorization_pending error, got: %s", errorResp.Error)
	}

	t.Logf("Got expected authorization_pending error")
}

// approveDevice approves the device using the user code
func approveDevice(t *testing.T, httpClient *http.Client, verificationURI, userCode, username string) {
	data := fmt.Sprintf("user_code=%s&action=approve&username=%s", userCode, username)
	req, err := http.NewRequest("POST", verificationURI, strings.NewReader(data))
	if err != nil {
		t.Fatalf("Failed to create approval request: %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Test-User", username)

	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to send approval request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Device approval failed: status %d, body: %s", resp.StatusCode, string(body))
	}

	t.Log("Device approved successfully")
}

// pollForToken polls the token endpoint until access token is received
func pollForToken(t *testing.T, httpClient *http.Client, baseURL, clientID, deviceCode string) string {
	maxAttempts := 10
	pollInterval := 2 * time.Second

	for i := 0; i < maxAttempts; i++ {
		if i > 0 {
			time.Sleep(pollInterval)
		}

		data := fmt.Sprintf("grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=%s&client_id=%s", deviceCode, clientID)
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

			return tokenResp.AccessToken
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
	return ""
}

// testMCPWithDeviceToken tests using the device flow token with MCP API
func testMCPWithDeviceToken(t *testing.T, httpClient *http.Client, baseURL, accessToken string) {
	// Test MCP initialize
	mcpReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]interface{}{},
			"clientInfo": map[string]interface{}{
				"name":    "device-test",
				"version": "1.0",
			},
		},
	}

	reqBody, _ := json.Marshal(mcpReq)
	req, err := http.NewRequest("POST", baseURL+"/mcp/message", bytes.NewBuffer(reqBody))
	if err != nil {
		t.Fatalf("Failed to create MCP request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to send MCP request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("MCP request failed: status %d, body: %s", resp.StatusCode, string(body))
	}

	var mcpResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&mcpResp); err != nil {
		t.Fatalf("Failed to decode MCP response: %v", err)
	}

	if mcpResp["error"] != nil {
		t.Fatalf("MCP request returned error: %v", mcpResp["error"])
	}

	result, ok := mcpResp["result"].(map[string]interface{})
	if !ok || result["protocolVersion"] == nil {
		t.Fatal("MCP initialize result missing protocolVersion")
	}

	t.Log("MCP API works with device flow token!")
}
