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

	"github.com/bbockelm/golang-htcondor/mcpserver"
	"github.com/ory/fosite"
	"golang.org/x/crypto/bcrypt"
)

// TestMCPHTTPIntegration tests the MCP protocol via HTTP with OAuth2 authentication
func TestMCPHTTPIntegration(t *testing.T) {
	// Skip if condor_master is not available
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH, skipping integration test")
	}

	// Create temporary directory for mini condor
	tempDir, err := os.MkdirTemp("", "htcondor-mcp-test-*")
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
	// The signing key should be in passwords.d/POOL
	// GenerateJWT expects the directory path and key name separately
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

	// Use a fixed port for testing
	serverPort := 18081
	serverAddr := fmt.Sprintf("127.0.0.1:%d", serverPort)
	baseURL := fmt.Sprintf("http://%s", serverAddr)

	// OAuth2 database path
	oauth2DBPath := filepath.Join(tempDir, "oauth2.db")

	// Create HTTP server with MCP enabled
	server, err := NewServer(Config{
		ListenAddr:     serverAddr,
		ScheddName:     "local",
		ScheddAddr:     scheddAddr,
		UserHeader:     "X-Test-User",
		SigningKeyPath: passwordsDir, // Pass the directory, GenerateJWT will look for POOL inside
		TrustDomain:    trustDomain,
		UIDDomain:      trustDomain,
		EnableMCP:      true,
		OAuth2DBPath:   oauth2DBPath,
		OAuth2Issuer:   baseURL,
	})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Start server in background
	serverErrChan := make(chan error, 1)
	go func() {
		serverErrChan <- server.Start()
	}()

	// Wait for server to be ready
	t.Logf("Waiting for server to start on %s", baseURL)
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
	testUser := "testuser"

	// Step 1: Create an OAuth2 client
	t.Log("Step 1: Creating OAuth2 client...")
	clientID, clientSecret := createOAuth2Client(t, server, testUser)
	t.Logf("OAuth2 client created: %s", clientID)

	// Step 2: Get OAuth2 access token using authorization code flow
	t.Log("Step 2: Getting OAuth2 access token via authorization code flow...")
	accessToken := getOAuth2TokenAuthCode(t, client, baseURL, clientID, clientSecret, testUser)
	t.Logf("Access token obtained: %s...", accessToken[:20])

	// Step 3: Test MCP initialize
	t.Log("Step 3: Testing MCP initialize...")
	testMCPInitialize(t, client, baseURL, accessToken)

	// Step 4: Test MCP tools/list
	t.Log("Step 4: Testing MCP tools/list...")
	testMCPToolsList(t, client, baseURL, accessToken)

	// Step 5: Test MCP tools/call (submit_job)
	t.Log("Step 5: Testing MCP job submission...")
	clusterID := testMCPSubmitJob(t, client, baseURL, accessToken)
	t.Logf("Job submitted: cluster ID %d", clusterID)

	// Step 6: Test MCP query_jobs
	t.Log("Step 6: Testing MCP job query...")
	testMCPQueryJobs(t, client, baseURL, accessToken, clusterID)

	t.Log("All MCP HTTP integration tests passed!")
}

// createOAuth2Client creates a new OAuth2 client in the storage
func createOAuth2Client(t *testing.T, server *Server, username string) (string, string) {
	// Access the OAuth2 storage directly
	storage := server.GetOAuth2Provider().GetStorage()

	clientID := "test-client"
	clientSecret := "test-secret"

	// Hash the client secret with bcrypt (fosite expects hashed secrets)
	hashedSecret, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash client secret: %v", err)
	}

	client := &fosite.DefaultClient{
		ID:            clientID,
		Secret:        hashedSecret,
		RedirectURIs:  []string{"http://localhost:18081/callback"},
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid", "mcp:read", "mcp:write"},
		Public:        false,
	}

	if err := storage.CreateClient(context.Background(), client); err != nil {
		t.Fatalf("Failed to create OAuth2 client: %v", err)
	}

	return clientID, clientSecret
}

// getOAuth2TokenAuthCode obtains an OAuth2 access token using authorization code flow
func getOAuth2TokenAuthCode(t *testing.T, httpClient *http.Client, baseURL, clientID, clientSecret, username string) string {
	// Step 1: Create authorization request
	authURL := fmt.Sprintf("%s/mcp/oauth2/authorize?response_type=code&client_id=%s&redirect_uri=http://localhost:18081/callback&scope=openid+mcp:read+mcp:write&state=teststate&username=%s",
		baseURL, clientID, username)

	req, err := http.NewRequest("GET", authURL, nil)
	if err != nil {
		t.Fatalf("Failed to create auth request: %v", err)
	}
	req.Header.Set("X-Test-User", username)

	// Don't follow redirects automatically
	httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	defer func() { httpClient.CheckRedirect = nil }()

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

	// Parse the authorization code from the redirect URL
	code := extractCodeFromURL(t, location)
	if code == "" {
		t.Fatal("No authorization code in redirect URL")
	}

	t.Logf("Received authorization code: %s...", code[:10])

	// Step 2: Exchange authorization code for access token
	tokenReq, err := http.NewRequest("POST", baseURL+"/mcp/oauth2/token", bytes.NewBufferString(
		fmt.Sprintf("grant_type=authorization_code&code=%s&redirect_uri=http://localhost:18081/callback&client_id=%s&client_secret=%s",
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

	if tokenResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(tokenResp.Body)
		t.Fatalf("Token request failed: status %d, body: %s", tokenResp.StatusCode, string(body))
	}

	var tokenRespData struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenRespData); err != nil {
		t.Fatalf("Failed to decode token response: %v", err)
	}

	if tokenRespData.AccessToken == "" {
		t.Fatal("Empty access token received")
	}

	return tokenRespData.AccessToken
}

// extractCodeFromURL extracts the authorization code from a redirect URL
func extractCodeFromURL(t *testing.T, urlStr string) string {
	if idx := strings.Index(urlStr, "code="); idx != -1 {
		code := urlStr[idx+5:]
		if end := strings.Index(code, "&"); end != -1 {
			code = code[:end]
		}
		return code
	}
	return ""
}

// Deprecated: kept for backward compatibility
// getOAuth2Token obtains an OAuth2 access token using client credentials flow
func getOAuth2Token(t *testing.T, client *http.Client, baseURL, clientID, clientSecret, username string) string {
	// Build token request
	req, err := http.NewRequest("POST", baseURL+"/mcp/oauth2/token", bytes.NewBufferString(
		fmt.Sprintf("grant_type=client_credentials&client_id=%s&client_secret=%s&scope=htcondor:jobs", clientID, clientSecret),
	))
	if err != nil {
		t.Fatalf("Failed to create token request: %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Test-User", username)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to request token: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Token request failed: status %d, body: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("Failed to decode token response: %v", err)
	}

	if tokenResp.AccessToken == "" {
		t.Fatal("Empty access token received")
	}

	return tokenResp.AccessToken
}

// testMCPInitialize tests the MCP initialize method
func testMCPInitialize(t *testing.T, client *http.Client, baseURL, accessToken string) {
	mcpReq := mcpserver.MCPMessage{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
		Params:  json.RawMessage(`{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}`),
	}

	mcpResp := sendMCPRequest(t, client, baseURL, accessToken, mcpReq)

	if mcpResp.Error != nil {
		t.Fatalf("MCP initialize failed: %v", mcpResp.Error.Message)
	}

	// Check response has expected structure
	result, ok := mcpResp.Result.(map[string]interface{})
	if !ok {
		t.Fatal("Initialize result is not a map")
	}

	if _, ok := result["protocolVersion"]; !ok {
		t.Fatal("Initialize result missing protocolVersion")
	}

	t.Logf("MCP initialized: %+v", result)
}

// testMCPToolsList tests the MCP tools/list method
func testMCPToolsList(t *testing.T, client *http.Client, baseURL, accessToken string) {
	mcpReq := mcpserver.MCPMessage{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "tools/list",
	}

	mcpResp := sendMCPRequest(t, client, baseURL, accessToken, mcpReq)

	if mcpResp.Error != nil {
		t.Fatalf("MCP tools/list failed: %v", mcpResp.Error.Message)
	}

	result, ok := mcpResp.Result.(map[string]interface{})
	if !ok {
		t.Fatal("tools/list result is not a map")
	}

	tools, ok := result["tools"].([]interface{})
	if !ok || len(tools) == 0 {
		t.Fatal("tools/list returned no tools")
	}

	t.Logf("Found %d MCP tools", len(tools))
}

// testMCPSubmitJob tests submitting a job via MCP
func testMCPSubmitJob(t *testing.T, client *http.Client, baseURL, accessToken string) int {
	submitFile := `executable = /bin/echo
arguments = "Hello from MCP!"
output = mcp-test.out
error = mcp-test.err
log = mcp-test.log
queue`

	params := map[string]interface{}{
		"name": "submit_job",
		"arguments": map[string]interface{}{
			"submit_file": submitFile,
		},
	}

	paramsBytes, _ := json.Marshal(params)

	mcpReq := mcpserver.MCPMessage{
		JSONRPC: "2.0",
		ID:      3,
		Method:  "tools/call",
		Params:  json.RawMessage(paramsBytes),
	}

	mcpResp := sendMCPRequest(t, client, baseURL, accessToken, mcpReq)

	if mcpResp.Error != nil {
		t.Fatalf("MCP submit_job failed: %v", mcpResp.Error.Message)
	}

	result, ok := mcpResp.Result.(map[string]interface{})
	if !ok {
		t.Fatal("submit_job result is not a map")
	}

	metadata, ok := result["metadata"].(map[string]interface{})
	if !ok {
		t.Fatal("submit_job result missing metadata")
	}

	clusterID, ok := metadata["cluster_id"].(float64)
	if !ok {
		t.Fatal("submit_job result missing cluster_id")
	}

	t.Logf("Job submitted with cluster ID: %d", int(clusterID))
	return int(clusterID)
}

// testMCPQueryJobs tests querying jobs via MCP
func testMCPQueryJobs(t *testing.T, client *http.Client, baseURL, accessToken string, clusterID int) {
	params := map[string]interface{}{
		"name": "query_jobs",
		"arguments": map[string]interface{}{
			"constraint": fmt.Sprintf("ClusterId == %d", clusterID),
			"projection": []string{"ClusterId", "ProcId", "Owner", "JobStatus"},
		},
	}

	paramsBytes, _ := json.Marshal(params)

	mcpReq := mcpserver.MCPMessage{
		JSONRPC: "2.0",
		ID:      4,
		Method:  "tools/call",
		Params:  json.RawMessage(paramsBytes),
	}

	mcpResp := sendMCPRequest(t, client, baseURL, accessToken, mcpReq)

	if mcpResp.Error != nil {
		t.Fatalf("MCP query_jobs failed: %v", mcpResp.Error.Message)
	}

	result, ok := mcpResp.Result.(map[string]interface{})
	if !ok {
		t.Fatal("query_jobs result is not a map")
	}

	metadata, ok := result["metadata"].(map[string]interface{})
	if !ok {
		t.Fatal("query_jobs result missing metadata")
	}

	count, ok := metadata["count"].(float64)
	if !ok {
		t.Fatal("query_jobs result missing count")
	}

	if int(count) == 0 {
		t.Fatal("query_jobs returned no jobs")
	}

	// Validate that the results contain the submitted job
	content, ok := result["content"].([]interface{})
	if !ok || len(content) == 0 {
		t.Fatal("query_jobs result missing content array")
	}

	// Parse the text content to find job information
	foundClusterID := false
	for _, item := range content {
		contentItem, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		text, ok := contentItem["text"].(string)
		if !ok {
			continue
		}
		// Check if the text contains our cluster ID
		if strings.Contains(text, fmt.Sprintf("ClusterId\": %d", clusterID)) ||
			strings.Contains(text, fmt.Sprintf("\"ClusterId\":%d", clusterID)) {
			foundClusterID = true
			break
		}
	}

	if !foundClusterID {
		t.Fatalf("query_jobs did not return the expected cluster ID %d", clusterID)
	}

	t.Logf("Query found %d job(s), including expected cluster ID %d", int(count), clusterID)
}

// sendMCPRequest sends an MCP request and returns the response
func sendMCPRequest(t *testing.T, client *http.Client, baseURL, accessToken string, mcpReq mcpserver.MCPMessage) *mcpserver.MCPMessage {
	reqBody, err := json.Marshal(mcpReq)
	if err != nil {
		t.Fatalf("Failed to marshal MCP request: %v", err)
	}

	req, err := http.NewRequest("POST", baseURL+"/mcp/message", bytes.NewBuffer(reqBody))
	if err != nil {
		t.Fatalf("Failed to create HTTP request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send MCP request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("MCP request failed: status %d, body: %s", resp.StatusCode, string(body))
	}

	var mcpResp mcpserver.MCPMessage
	if err := json.NewDecoder(resp.Body).Decode(&mcpResp); err != nil {
		t.Fatalf("Failed to decode MCP response: %v", err)
	}

	return &mcpResp
}
