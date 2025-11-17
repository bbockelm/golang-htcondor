//go:build integration

//nolint:errcheck,noctx,gosec,errorlint,govet // Integration test file with acceptable test patterns
package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
	"golang.org/x/crypto/bcrypt"
)

// TestDynamicClientRegistration tests OAuth2 dynamic client registration
func TestDynamicClientRegistration(t *testing.T) {
	// Skip if condor_master is not available
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH, skipping integration test")
	}

	// Setup server (reuse helper from main test)
	_, _, baseURL := setupTestServer(t)

	client := &http.Client{Timeout: 30 * time.Second}
	testUser := "regtest"

	// Test dynamic client registration
	t.Log("Testing dynamic client registration...")

	regReq := map[string]interface{}{
		"redirect_uris":  []string{fmt.Sprintf("%s/callback", baseURL)},
		"grant_types":    []string{"authorization_code", "refresh_token"},
		"response_types": []string{"code"},
		"scope":          []string{"openid", "mcp:read", "mcp:write"},
		"client_name":    "Test Dynamic Client",
	}

	regReqBytes, _ := json.Marshal(regReq)
	req, err := http.NewRequest("POST", baseURL+"/mcp/oauth2/register", bytes.NewBuffer(regReqBytes))
	if err != nil {
		t.Fatalf("Failed to create registration request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send registration request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Registration failed: status %d, body: %s", resp.StatusCode, string(body))
	}

	var regResp struct {
		ClientID      string   `json:"client_id"`
		ClientSecret  string   `json:"client_secret"`
		RedirectURIs  []string `json:"redirect_uris"`
		GrantTypes    []string `json:"grant_types"`
		ResponseTypes []string `json:"response_types"`
		Scope         string   `json:"scope"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&regResp); err != nil {
		t.Fatalf("Failed to decode registration response: %v", err)
	}

	if regResp.ClientID == "" || regResp.ClientSecret == "" {
		t.Fatal("Registration response missing client_id or client_secret")
	}

	t.Logf("Client registered: ID=%s", regResp.ClientID)

	// Use the dynamically registered client to get a token
	t.Log("Testing token acquisition with dynamically registered client...")
	accessToken := getOAuth2TokenAuthCodeForClient(t, client, baseURL, regResp.ClientID, regResp.ClientSecret, testUser)

	if accessToken == "" {
		t.Fatal("Failed to get access token with dynamically registered client")
	}

	t.Logf("Successfully obtained token with dynamic client")

	// Test MCP access with the token
	t.Log("Testing MCP access with dynamic client token...")
	testMCPInitialize(t, client, baseURL, accessToken)

	t.Log("Dynamic client registration test passed!")
}

// TestMCPWithSSO tests MCP access via SSO (mock SSO server with authorization code flow)
func TestMCPWithSSO(t *testing.T) {
	// Skip if condor_master is not available
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH, skipping integration test")
	}

	// Setup mock SSO server first (so we know its URL)
	ssoServer, ssoStorage, ssoBaseURL := setupMockSSOServer(t, "")
	t.Cleanup(func() { shutdownMockSSOServer(t, ssoServer) })

	// Setup main MCP server with SSO integration enabled
	_, mcpServer, mcpBaseURL := setupTestServerWithSSO(t, ssoBaseURL)

	// Update SSO callback URL now that we know MCP's URL
	ssoStorage.callbackURL = mcpBaseURL + "/mcp/oauth2/callback"

	// Create a test OAuth2 client in MCP for accessing MCP endpoints
	t.Log("Creating test OAuth2 client in MCP...")
	mcpStorage := mcpServer.GetOAuth2Provider().GetStorage()
	testClientSecret, _ := bcrypt.GenerateFromPassword([]byte("test-secret"), bcrypt.DefaultCost)
	testClient := &fosite.DefaultClient{
		ID:            "test-client",
		Secret:        testClientSecret,
		RedirectURIs:  []string{mcpBaseURL + "/callback"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid", "mcp:read", "mcp:write"},
	}
	if err := mcpStorage.CreateClient(context.Background(), testClient); err != nil {
		t.Fatalf("Failed to create test client in MCP: %v", err)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	testUser := "ssouser"
	testPassword := "ssopassword"

	t.Log("Testing end-to-end SSO authorization flow...")

	// Step 1: User initiates OAuth2 flow with MCP (simulating browser)
	// MCP will redirect to SSO for authentication
	mcpAuthURL := fmt.Sprintf("%s/mcp/oauth2/authorize?response_type=code&client_id=test-client&redirect_uri=%s/callback&scope=openid+mcp:read+mcp:write&state=clientstate",
		mcpBaseURL, mcpBaseURL)

	// Disable auto-redirect to handle each step manually
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	defer func() { client.CheckRedirect = nil }()

	// Make initial request to MCP authorize endpoint
	req, _ := http.NewRequest("GET", mcpAuthURL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to start MCP authorization: %v", err)
	}
	defer resp.Body.Close()

	// Should redirect to SSO
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected redirect to SSO, got status %d, body: %s", resp.StatusCode, string(body))
	}

	ssoAuthURL := resp.Header.Get("Location")
	if !strings.Contains(ssoAuthURL, ssoBaseURL) {
		t.Fatalf("Expected redirect to SSO (%s), got: %s", ssoBaseURL, ssoAuthURL)
	}
	t.Logf("MCP redirected to SSO: %s", ssoAuthURL)

	// Step 2: Follow redirect to SSO, which will redirect to login
	resp2, err := client.Get(ssoAuthURL)
	if err != nil {
		t.Fatalf("Failed to follow SSO redirect: %v", err)
	}
	defer resp2.Body.Close()

	loginURL := resp2.Header.Get("Location")
	if loginURL == "" {
		body, _ := io.ReadAll(resp2.Body)
		t.Fatalf("Expected redirect to login, got status %d, body: %s", resp2.StatusCode, string(body))
	}
	if loginURL[0] == '/' {
		loginURL = ssoBaseURL + loginURL
	}
	t.Logf("SSO redirected to login: %s", loginURL)

	// Step 3: Submit login credentials
	formData := url.Values{}
	formData.Set("username", testUser)
	formData.Set("password", testPassword)

	loginResp, err := client.PostForm(loginURL, formData)
	if err != nil {
		t.Fatalf("Failed to submit login: %v", err)
	}
	defer loginResp.Body.Close()

	// Should redirect back to SSO authorize with authenticated_user
	authorizeURL := loginResp.Header.Get("Location")
	if authorizeURL == "" {
		body, _ := io.ReadAll(loginResp.Body)
		t.Fatalf("No redirect after login, status %d, body: %s", loginResp.StatusCode, string(body))
	}
	if authorizeURL[0] == '/' {
		authorizeURL = ssoBaseURL + authorizeURL
	}
	t.Logf("Login successful, redirect to: %s", authorizeURL)

	// Step 4: Follow redirect back to SSO authorize (now authenticated)
	authResp, err := client.Get(authorizeURL)
	if err != nil {
		t.Fatalf("Failed to follow authorize redirect: %v", err)
	}
	defer authResp.Body.Close()

	// Should redirect to MCP callback with SSO authorization code
	mcpCallbackURL := authResp.Header.Get("Location")
	if !strings.Contains(mcpCallbackURL, mcpBaseURL+"/mcp/oauth2/callback") {
		body, _ := io.ReadAll(authResp.Body)
		t.Fatalf("Expected redirect to MCP callback, got status %d, location: %s, body: %s",
			authResp.StatusCode, mcpCallbackURL, string(body))
	}
	t.Logf("SSO redirecting to MCP callback: %s", mcpCallbackURL)

	// Step 5: Follow redirect to MCP callback
	// MCP will now exchange the SSO code for a token and complete the flow
	callbackResp, err := client.Get(mcpCallbackURL)
	if err != nil {
		t.Fatalf("Failed to follow MCP callback: %v", err)
	}
	defer callbackResp.Body.Close()

	// Should redirect to original client callback with MCP authorization code
	clientCallbackURL := callbackResp.Header.Get("Location")
	if !strings.Contains(clientCallbackURL, mcpBaseURL+"/callback") {
		body, _ := io.ReadAll(callbackResp.Body)
		t.Fatalf("Expected redirect to client callback, got status %d, location: %s, body: %s",
			callbackResp.StatusCode, clientCallbackURL, string(body))
	}
	t.Logf("MCP callback completed, redirect to client: %s", clientCallbackURL)

	// Extract MCP authorization code from callback
	mcpAuthCode := extractCodeFromURL(t, clientCallbackURL)
	if mcpAuthCode == "" {
		t.Fatalf("No code in client callback URL: %s", clientCallbackURL)
	}
	t.Logf("Received MCP authorization code: %s...", mcpAuthCode[:min(10, len(mcpAuthCode))])

	// Step 6: Exchange MCP authorization code for access token
	tokenReq, _ := http.NewRequest("POST", mcpBaseURL+"/mcp/oauth2/token", bytes.NewBufferString(
		fmt.Sprintf("grant_type=authorization_code&code=%s&redirect_uri=%s/callback&client_id=test-client&client_secret=test-secret",
			mcpAuthCode, mcpBaseURL),
	))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	tokenResp, err := client.Do(tokenReq)
	if err != nil {
		t.Fatalf("MCP token exchange failed: %v", err)
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(tokenResp.Body)
		t.Fatalf("MCP token exchange returned error: status %d, body: %s", tokenResp.StatusCode, string(body))
	}

	var mcpToken struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(tokenResp.Body).Decode(&mcpToken); err != nil {
		t.Fatalf("Failed to decode MCP token: %v", err)
	}

	accessToken := mcpToken.AccessToken
	if accessToken == "" {
		t.Fatal("Failed to get MCP access token")
	}

	t.Log("Successfully obtained MCP token via full SSO flow")

	// Test MCP access
	t.Log("Testing MCP access with SSO-authenticated token...")
	testMCPInitialize(t, client, mcpBaseURL, accessToken)

	t.Log("SSO integration test passed!")
}

// TestMCPGroupMembership tests various group membership scenarios
func TestMCPGroupMembership(t *testing.T) {
	// Skip if condor_master is not available
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH, skipping integration test")
	}

	testCases := []struct {
		name         string
		username     string
		password     string
		groups       interface{} // Can be []string or string (space-delimited)
		accessGroup  string      // Required to access MCP
		readGroup    string      // Required for mcp:read scope
		writeGroup   string      // Required for mcp:write scope
		expectAccess bool        // Should user get access at all?
		expectRead   bool        // Should user get mcp:read scope?
		expectWrite  bool        // Should user get mcp:write scope?
		description  string
	}{
		{
			name:         "User with no groups - access denied",
			username:     "nogroups",
			password:     "password",
			groups:       []string{},
			accessGroup:  "mcp-access",
			expectAccess: false,
			description:  "User without any groups should be denied when access group is required",
		},
		{
			name:         "User with no groups - no access group required",
			username:     "nogroups",
			password:     "password",
			groups:       []string{},
			accessGroup:  "", // No access group required
			expectAccess: true,
			expectRead:   false,
			expectWrite:  false,
			description:  "User without groups can access if no access group is required, but gets no scopes",
		},
		{
			name:         "User with only access group",
			username:     "accessonly",
			password:     "password",
			groups:       []string{"mcp-access"},
			accessGroup:  "mcp-access",
			readGroup:    "mcp-read",
			writeGroup:   "mcp-write",
			expectAccess: true,
			expectRead:   false,
			expectWrite:  false,
			description:  "User with only access group gets access but no read/write scopes",
		},
		{
			name:         "User with read group",
			username:     "reader",
			password:     "password",
			groups:       []string{"mcp-access", "mcp-read"},
			accessGroup:  "mcp-access",
			readGroup:    "mcp-read",
			writeGroup:   "mcp-write",
			expectAccess: true,
			expectRead:   true,
			expectWrite:  false,
			description:  "User with read group gets access and mcp:read scope",
		},
		{
			name:         "User with write group",
			username:     "writer",
			password:     "password",
			groups:       []string{"mcp-access", "mcp-read", "mcp-write"},
			accessGroup:  "mcp-access",
			readGroup:    "mcp-read",
			writeGroup:   "mcp-write",
			expectAccess: true,
			expectRead:   true,
			expectWrite:  true,
			description:  "User with write group gets access and both read/write scopes",
		},
		{
			name:         "Groups as space-delimited string",
			username:     "reader",
			password:     "password",
			groups:       "mcp-access mcp-read",
			accessGroup:  "mcp-access",
			readGroup:    "mcp-read",
			writeGroup:   "mcp-write",
			expectAccess: true,
			expectRead:   true,
			expectWrite:  false,
			description:  "Groups can be provided as space-delimited string instead of array",
		},
		{
			name:         "Case-insensitive group matching",
			username:     "reader",
			password:     "password",
			groups:       []string{"MCP-ACCESS", "MCP-READ"},
			accessGroup:  "mcp-access",
			readGroup:    "mcp-read",
			expectAccess: true,
			expectRead:   true,
			expectWrite:  false,
			description:  "Group matching should be case-insensitive",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock SSO server
			ssoServer, ssoStorage, ssoBaseURL := setupMockSSOServer(t, "")
			t.Cleanup(func() { shutdownMockSSOServer(t, ssoServer) })

			// Configure user info for this test case
			ssoStorage.userInfos[tc.username] = map[string]interface{}{
				"sub":    tc.username,
				"email":  tc.username + "@example.com",
				"name":   tc.username,
				"groups": tc.groups,
			}

			// Setup main MCP server with SSO integration and group config
			_, mcpServer, mcpBaseURL := setupTestServerWithSSOAndGroups(t, ssoBaseURL, tc.accessGroup, tc.readGroup, tc.writeGroup)
			ssoStorage.callbackURL = mcpBaseURL + "/mcp/oauth2/callback"

			// Create a test OAuth2 client in MCP
			mcpStorage := mcpServer.GetOAuth2Provider().GetStorage()
			testClientSecret, _ := bcrypt.GenerateFromPassword([]byte("test-secret"), bcrypt.DefaultCost)
			testClient := &fosite.DefaultClient{
				ID:            "test-client",
				Secret:        testClientSecret,
				RedirectURIs:  []string{mcpBaseURL + "/callback"},
				GrantTypes:    []string{"authorization_code"},
				ResponseTypes: []string{"code"},
				Scopes:        []string{"openid", "mcp:read", "mcp:write"},
			}
			if err := mcpStorage.CreateClient(context.Background(), testClient); err != nil {
				t.Fatalf("Failed to create test client: %v", err)
			}

			client := &http.Client{Timeout: 30 * time.Second}

			t.Logf("Testing: %s", tc.description)

			// Perform OAuth2 flow
			mcpAuthURL := fmt.Sprintf("%s/mcp/oauth2/authorize?response_type=code&client_id=test-client&redirect_uri=%s/callback&scope=openid+mcp:read+mcp:write&state=teststate",
				mcpBaseURL, mcpBaseURL)

			client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			}
			defer func() { client.CheckRedirect = nil }()

			// Follow OAuth2 flow through SSO
			req, _ := http.NewRequest("GET", mcpAuthURL, nil)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Failed to start authorization: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusFound {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("Expected redirect to SSO, got status %d, body: %s", resp.StatusCode, string(body))
			}

			ssoAuthURL := resp.Header.Get("Location")
			resp2, _ := client.Get(ssoAuthURL)
			defer resp2.Body.Close()

			loginURL := resp2.Header.Get("Location")
			if loginURL[0] == '/' {
				loginURL = ssoBaseURL + loginURL
			}

			// Submit login
			formData := url.Values{}
			formData.Set("username", tc.username)
			formData.Set("password", tc.password)
			loginResp, _ := client.PostForm(loginURL, formData)
			defer loginResp.Body.Close()

			authorizeURL := loginResp.Header.Get("Location")
			if authorizeURL[0] == '/' {
				authorizeURL = ssoBaseURL + authorizeURL
			}

			authResp, _ := client.Get(authorizeURL)
			defer authResp.Body.Close()

			mcpCallbackURL := authResp.Header.Get("Location")

			// Follow redirect to MCP callback - this is where access control happens
			callbackResp, _ := client.Get(mcpCallbackURL)
			defer callbackResp.Body.Close()

			clientCallbackURL := callbackResp.Header.Get("Location")

			// If access should be denied, check for error in client callback
			if !tc.expectAccess {
				if !strings.Contains(clientCallbackURL, "error=access_denied") {
					t.Fatalf("Expected access_denied error, got redirect: %s", clientCallbackURL)
				}
				t.Logf("Access correctly denied for user without required groups")
				return
			}

			// User should have access - verify we got a code
			if !strings.Contains(clientCallbackURL, "code=") {
				body, _ := io.ReadAll(callbackResp.Body)
				t.Fatalf("Expected code in callback, got: %s, body: %s", clientCallbackURL, string(body))
			}

			mcpAuthCode := extractCodeFromURL(t, clientCallbackURL)

			// Exchange code for token
			tokenReq, _ := http.NewRequest("POST", mcpBaseURL+"/mcp/oauth2/token", bytes.NewBufferString(
				fmt.Sprintf("grant_type=authorization_code&code=%s&redirect_uri=%s/callback&client_id=test-client&client_secret=test-secret",
					mcpAuthCode, mcpBaseURL),
			))
			tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			tokenResp, _ := client.Do(tokenReq)
			defer tokenResp.Body.Close()

			if tokenResp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(tokenResp.Body)
				t.Fatalf("Token exchange failed: status %d, body: %s", tokenResp.StatusCode, string(body))
			}

			var tokenData struct {
				AccessToken string `json:"access_token"`
				Scope       string `json:"scope"`
			}
			json.NewDecoder(tokenResp.Body).Decode(&tokenData)

			// Verify scopes
			scopes := strings.Split(tokenData.Scope, " ")
			hasRead := false
			hasWrite := false
			for _, scope := range scopes {
				if scope == "mcp:read" {
					hasRead = true
				}
				if scope == "mcp:write" {
					hasWrite = true
				}
			}

			if hasRead != tc.expectRead {
				t.Errorf("Expected mcp:read=%v, got %v (scopes: %s)", tc.expectRead, hasRead, tokenData.Scope)
			}
			if hasWrite != tc.expectWrite {
				t.Errorf("Expected mcp:write=%v, got %v (scopes: %s)", tc.expectWrite, hasWrite, tokenData.Scope)
			}

			t.Logf("Group membership test passed: %s (scopes: %s)", tc.description, tokenData.Scope)
		})
	}
}

// setupTestServerWithSSOAndGroups sets up test server with SSO and group configuration
func setupTestServerWithSSOAndGroups(t *testing.T, ssoBaseURL, accessGroup, readGroup, writeGroup string) (string, *Server, string) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "htcondor-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(tempDir) })

	// Create secure socket directory
	socketDir, err := os.MkdirTemp("/tmp", "htc_sock_*")
	if err != nil {
		t.Fatalf("Failed to create socket directory: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(socketDir) })

	// Generate signing key
	passwordsDir := filepath.Join(tempDir, "passwords.d")
	if err := os.MkdirAll(passwordsDir, 0700); err != nil {
		t.Fatalf("Failed to create passwords.d directory: %v", err)
	}
	poolKeyPath := filepath.Join(passwordsDir, "POOL")
	key, err := GenerateSigningKey()
	if err != nil {
		t.Fatalf("Failed to generate signing key: %v", err)
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

	os.Setenv("CONDOR_CONFIG", configFile)
	t.Cleanup(func() { os.Unsetenv("CONDOR_CONFIG") })

	// Start condor_master
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	condorMaster, err := startCondorMaster(ctx, configFile, tempDir)
	if err != nil {
		t.Fatalf("Failed to start condor_master: %v", err)
	}
	t.Cleanup(func() { stopCondorMaster(condorMaster, t) })

	// Wait for condor
	if err := waitForCondor(tempDir, 60*time.Second, t); err != nil {
		t.Fatalf("Condor failed to start: %v", err)
	}

	// Find an available port for MCP server
	serverAddr := "127.0.0.1:0"
	placeholderBaseURL := "http://127.0.0.1:0"
	oauth2DBPath := filepath.Join(tempDir, "oauth2.db")

	// Setup user info endpoint
	userInfoURL := ssoBaseURL + "/userinfo"

	// Create server with SSO integration and group configuration
	server, err := NewServer(Config{
		ListenAddr:         serverAddr,
		ScheddName:         "local",
		ScheddAddr:         "127.0.0.1:9618",
		SigningKeyPath:     passwordsDir,
		TrustDomain:        "test.local",
		UIDDomain:          "test.local",
		EnableMCP:          true,
		OAuth2DBPath:       oauth2DBPath,
		OAuth2Issuer:       placeholderBaseURL,
		OAuth2ClientID:     "mcp-client",
		OAuth2ClientSecret: "mcp-secret",
		OAuth2AuthURL:      ssoBaseURL + "/authorize",
		OAuth2TokenURL:     ssoBaseURL + "/token",
		OAuth2RedirectURL:  placeholderBaseURL + "/mcp/oauth2/callback",
		OAuth2UserInfoURL:  userInfoURL,
		OAuth2GroupsClaim:  "groups",
		MCPAccessGroup:     accessGroup,
		MCPReadGroup:       readGroup,
		MCPWriteGroup:      writeGroup,
	})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Start server in background
	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Start()
	}()

	// Wait for server to start
	time.Sleep(500 * time.Millisecond)

	// Verify server is listening and get actual address
	actualAddr := server.GetAddr()
	if actualAddr == "" {
		t.Fatal("Server failed to start - no listening address available")
	}
	baseURL := fmt.Sprintf("http://%s", actualAddr)

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(ctx)
	})

	// Check for startup errors
	select {
	case err := <-errChan:
		if err != nil && err != http.ErrServerClosed {
			t.Fatalf("Server error: %v", err)
		}
	default:
		// Server is running
	}

	return tempDir, server, baseURL
}

// setupTestServerWithSSO sets up the test server with SSO integration enabled
func setupTestServerWithSSO(t *testing.T, ssoBaseURL string) (string, *Server, string) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "htcondor-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(tempDir) })

	// Create secure socket directory
	socketDir, err := os.MkdirTemp("/tmp", "htc_sock_*")
	if err != nil {
		t.Fatalf("Failed to create socket directory: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(socketDir) })

	// Generate signing key
	passwordsDir := filepath.Join(tempDir, "passwords.d")
	if err := os.MkdirAll(passwordsDir, 0700); err != nil {
		t.Fatalf("Failed to create passwords.d directory: %v", err)
	}
	poolKeyPath := filepath.Join(passwordsDir, "POOL")
	key, err := GenerateSigningKey()
	if err != nil {
		t.Fatalf("Failed to generate signing key: %v", err)
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

	os.Setenv("CONDOR_CONFIG", configFile)
	t.Cleanup(func() { os.Unsetenv("CONDOR_CONFIG") })

	// Start condor_master
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	condorMaster, err := startCondorMaster(ctx, configFile, tempDir)
	if err != nil {
		t.Fatalf("Failed to start condor_master: %v", err)
	}
	t.Cleanup(func() { stopCondorMaster(condorMaster, t) })

	// Wait for condor
	if err := waitForCondor(tempDir, 60*time.Second, t); err != nil {
		t.Fatalf("Condor failed to start: %v", err)
	}

	// Use dynamic port allocation for MCP server
	serverAddr := "127.0.0.1:0"
	oauth2DBPath := filepath.Join(tempDir, "oauth2.db")

	// Setup user info endpoint in mock SSO
	userInfoURL := ssoBaseURL + "/userinfo"

	// Create server with SSO integration
	// Note: OAuth2Issuer and OAuth2RedirectURL will use placeholder baseURL
	// The actual baseURL is computed after server starts
	placeholderBaseURL := "http://127.0.0.1:0"
	server, err := NewServer(Config{
		ListenAddr:         serverAddr,
		ScheddName:         "local",
		ScheddAddr:         "127.0.0.1:9618",
		SigningKeyPath:     passwordsDir,
		TrustDomain:        "test.local",
		UIDDomain:          "test.local",
		EnableMCP:          true,
		OAuth2DBPath:       oauth2DBPath,
		OAuth2Issuer:       placeholderBaseURL,
		OAuth2ClientID:     "mcp-client",
		OAuth2ClientSecret: "mcp-secret",
		OAuth2AuthURL:      ssoBaseURL + "/authorize",
		OAuth2TokenURL:     ssoBaseURL + "/token",
		OAuth2RedirectURL:  placeholderBaseURL + "/mcp/oauth2/callback",
		OAuth2UserInfoURL:  userInfoURL,
		OAuth2GroupsClaim:  "groups",
		// Grant read and write scopes to users in "mcp-users" group
		MCPReadGroup:  "mcp-users",
		MCPWriteGroup: "mcp-users",
	})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Start server in background
	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Start()
	}()

	// Wait for server to start
	time.Sleep(500 * time.Millisecond)

	// Verify server is listening and get actual address
	actualAddr := server.GetAddr()
	if actualAddr == "" {
		t.Fatal("Server failed to start - no listening address available")
	}
	baseURL := fmt.Sprintf("http://%s", actualAddr)

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(ctx)
	})

	// Check for startup errors
	select {
	case err := <-errChan:
		if err != nil && err != http.ErrServerClosed {
			t.Fatalf("Server error: %v", err)
		}
	default:
		// Server is running
	}

	return tempDir, server, baseURL
}

// Helper functions

func setupTestServer(t *testing.T) (string, *Server, string) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "htcondor-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(tempDir) })

	// Create secure socket directory
	socketDir, err := os.MkdirTemp("/tmp", "htc_sock_*")
	if err != nil {
		t.Fatalf("Failed to create socket directory: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(socketDir) })

	// Generate signing key
	passwordsDir := filepath.Join(tempDir, "passwords.d")
	if err := os.MkdirAll(passwordsDir, 0700); err != nil {
		t.Fatalf("Failed to create passwords.d directory: %v", err)
	}
	// GenerateJWT expects the directory path and key name separately
	poolKeyPath := filepath.Join(passwordsDir, "POOL")
	key, err := GenerateSigningKey()
	if err != nil {
		t.Fatalf("Failed to generate signing key: %v", err)
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

	os.Setenv("CONDOR_CONFIG", configFile)
	t.Cleanup(func() { os.Unsetenv("CONDOR_CONFIG") })

	// Start condor_master
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	condorMaster, err := startCondorMaster(ctx, configFile, tempDir)
	if err != nil {
		t.Fatalf("Failed to start condor_master: %v", err)
	}
	t.Cleanup(func() { stopCondorMaster(condorMaster, t) })

	// Wait for condor
	if err := waitForCondor(tempDir, 60*time.Second, t); err != nil {
		t.Fatalf("Condor failed to start: %v", err)
	}

	// Use dynamic port allocation
	serverAddr := "127.0.0.1:0"
	oauth2DBPath := filepath.Join(tempDir, "oauth2.db")

	// Create server with dynamic port
	// OAuth2Issuer will use placeholder, actual baseURL computed after server starts
	placeholderBaseURL := "http://127.0.0.1:0"
	server, err := NewServer(Config{
		ListenAddr:     serverAddr,
		ScheddName:     "local",
		ScheddAddr:     "127.0.0.1:9618",
		UserHeader:     "X-Test-User",
		SigningKeyPath: passwordsDir, // Pass the directory, GenerateJWT will look for POOL inside
		TrustDomain:    "test.local",
		UIDDomain:      "test.local",
		EnableMCP:      true,
		OAuth2DBPath:   oauth2DBPath,
		OAuth2Issuer:   placeholderBaseURL,
	})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Start server in background
	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Start()
	}()

	// Wait for server to start
	time.Sleep(500 * time.Millisecond)

	// Verify server is listening and get actual address
	actualAddr := server.GetAddr()
	if actualAddr == "" {
		t.Fatal("Server failed to start - no listening address available")
	}
	baseURL := fmt.Sprintf("http://%s", actualAddr)

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(ctx)
	})

	// Check for startup errors
	select {
	case err := <-errChan:
		if err != nil && err != http.ErrServerClosed {
			t.Fatalf("Server error: %v", err)
		}
	default:
		// Server is running
	}

	return tempDir, server, baseURL
}

func shutdownTestServer(t *testing.T, server *Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server.Shutdown(ctx)
}

func getOAuth2TokenAuthCodeForClient(t *testing.T, httpClient *http.Client, baseURL, clientID, clientSecret, username string) string {
	// Similar to getOAuth2TokenAuthCode but works with any client
	authURL := fmt.Sprintf("%s/mcp/oauth2/authorize?response_type=code&client_id=%s&redirect_uri=%s/callback&scope=openid+mcp:read+mcp:write&state=teststate&username=%s",
		baseURL, clientID, baseURL, username)

	req, _ := http.NewRequest("GET", authURL, nil)
	req.Header.Set("X-Test-User", username)

	httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	defer func() { httpClient.CheckRedirect = nil }()

	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to send auth request: %v", err)
	}
	defer resp.Body.Close()

	// Accept both 302 (Found) and 303 (See Other) as valid OAuth2 redirects
	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Authorization failed: status %d, body: %s", resp.StatusCode, string(body))
	}

	location := resp.Header.Get("Location")
	if location == "" {
		t.Fatal("No Location header in redirect response")
	}

	// Check if the redirect contains an error
	if redirectURL, err := url.Parse(location); err == nil {
		if errorCode := redirectURL.Query().Get("error"); errorCode != "" {
			errorDesc := redirectURL.Query().Get("error_description")
			t.Fatalf("OAuth2 error in redirect: %s - %s", errorCode, errorDesc)
		}
	}

	code := extractCodeFromURL(t, location)

	tokenReq, _ := http.NewRequest("POST", baseURL+"/mcp/oauth2/token", bytes.NewBufferString(
		fmt.Sprintf("grant_type=authorization_code&code=%s&redirect_uri=%s/callback&client_id=%s&client_secret=%s",
			code, baseURL, clientID, clientSecret),
	))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	tokenResp, err := httpClient.Do(tokenReq)
	if err != nil {
		t.Fatalf("Failed to send token request: %v", err)
	}
	defer tokenResp.Body.Close()

	var tokenData struct {
		AccessToken string `json:"access_token"`
	}
	json.NewDecoder(tokenResp.Body).Decode(&tokenData)

	return tokenData.AccessToken
}

// Mock SSO Server

func setupMockSSOServer(t *testing.T, tempDir string) (*http.Server, *mockSSOStorage, string) {
	// Create a simple mock SSO server using fosite
	storage := &mockSSOStorage{
		users: map[string]string{
			"ssouser":    "ssopassword",
			"nogroups":   "password",
			"accessonly": "password",
			"reader":     "password",
			"writer":     "password",
		},
		codes:                make(map[string]mockAuthCode),
		pendingAuthorizeReqs: make(map[string]fosite.AuthorizeRequester),
		userInfos:            make(map[string]map[string]interface{}),
	}

	// Use dynamic port allocation
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	actualAddr := listener.Addr().String()
	ssoBaseURL := fmt.Sprintf("http://%s", actualAddr)

	config := &fosite.Config{
		AccessTokenLifespan:   time.Hour,
		AuthorizeCodeLifespan: time.Minute * 10,
		TokenURL:              ssoBaseURL + "/token",
		ScopeStrategy:         fosite.HierarchicScopeStrategy,
		GlobalSecret:          []byte("mock-sso-secret-key-exactly-32!!"), // Exactly 32 bytes for HMAC-SHA512/256
	}

	oauth2Provider := compose.Compose(
		config,
		storage,
		&compose.CommonStrategy{
			CoreStrategy: compose.NewOAuth2HMACStrategy(config),
		},
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OpenIDConnectExplicitFactory,
	)

	mux := http.NewServeMux()

	// Login page
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			username := r.FormValue("username")
			password := r.FormValue("password")

			if storage.users[username] == password {
				// Store current user for userinfo endpoint
				storage.currentUser = username
				// Get original query params that were passed to /login
				q := r.URL.Query()
				// Remove username/password and redirect back to authorize
				redirectURL := fmt.Sprintf("/authorize?%s&authenticated_user=%s", q.Encode(), username)
				http.Redirect(w, r, redirectURL, http.StatusFound)
				return
			}
		}
		// Simple HTML login form - include query params in action URL
		action := "/login"
		if r.URL.RawQuery != "" {
			action = "/login?" + r.URL.RawQuery
		}
		w.Write([]byte(fmt.Sprintf(`<html><body><form method="post" action="%s"><input name="username"/><input name="password" type="password"/><button>Login</button></form></body></html>`, action)))
	})

	// Authorize endpoint
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		authenticatedUser := r.URL.Query().Get("authenticated_user")
		state := r.URL.Query().Get("state")

		t.Logf("[SSO] Authorize request: authenticated_user=%q, state=%q, query=%s", authenticatedUser, state, r.URL.RawQuery)

		if authenticatedUser == "" {
			// First call - create authorize request and store it
			ar, err := oauth2Provider.NewAuthorizeRequest(ctx, r)
			if err != nil {
				t.Logf("[SSO] NewAuthorizeRequest error (first call): %v", err)
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			// Store the authorize request for later retrieval
			if state != "" {
				storage.pendingAuthorizeReqs[state] = ar
				t.Logf("[SSO] Stored authorize request for state=%q", state)
			}

			// Redirect to login
			t.Logf("[SSO] No authenticated_user, redirecting to login")
			http.Redirect(w, r, "/login?"+r.URL.RawQuery, http.StatusFound)
			return
		}

		// Second call - retrieve stored authorize request
		ar, ok := storage.pendingAuthorizeReqs[state]
		if !ok || ar == nil {
			t.Logf("[SSO] No pending authorize request found for state=%q", state)
			http.Error(w, "invalid_state: no pending authorization request", http.StatusBadRequest)
			return
		}

		t.Logf("[SSO] Retrieved stored authorize request for state=%q", state)

		// Grant requested scopes
		for _, scope := range ar.GetRequestedScopes() {
			ar.GrantScope(scope)
		}

		session := &openid.DefaultSession{
			Claims: &jwt.IDTokenClaims{
				Subject: authenticatedUser,
			},
			Subject: authenticatedUser,
		}

		response, err := oauth2Provider.NewAuthorizeResponse(ctx, ar, session)
		if err != nil {
			t.Logf("[SSO] NewAuthorizeResponse error: %v (type: %T)", err, err)
			var fositeErr *fosite.RFC6749Error
			if errors.As(err, &fositeErr) {
				t.Logf("[SSO] Fosite error details: Name=%s, Desc=%s, Hint=%s, Code=%d, Debug=%s",
					fositeErr.ErrorField, fositeErr.DescriptionField, fositeErr.HintField, fositeErr.CodeField, fositeErr.DebugField)
			}
			oauth2Provider.WriteAuthorizeError(ctx, w, ar, err)
			return
		}

		// Clean up stored request
		delete(storage.pendingAuthorizeReqs, state)

		t.Logf("[SSO] Authorize success, writing response")
		oauth2Provider.WriteAuthorizeResponse(ctx, w, ar, response)
	})

	// Token endpoint
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		session := &openid.DefaultSession{}

		accessRequest, err := oauth2Provider.NewAccessRequest(ctx, r, session)
		if err != nil {
			oauth2Provider.WriteAccessError(ctx, w, accessRequest, err)
			return
		}

		response, err := oauth2Provider.NewAccessResponse(ctx, accessRequest)
		if err != nil {
			oauth2Provider.WriteAccessError(ctx, w, accessRequest, err)
			return
		}

		oauth2Provider.WriteAccessResponse(ctx, w, accessRequest, response)
	})

	// User info endpoint - returns groups based on storage config
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		// Extract bearer token
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Extract username from token (mock - just use a stored value)
		// In a real system, we'd validate the token and look up the actual user
		username := storage.currentUser
		if username == "" {
			username = "ssouser"
		}

		// Get user info from storage (allows customization per test)
		userInfo := storage.getUserInfo(username)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(userInfo)
	})

	server := &http.Server{
		Handler: mux,
	}

	go server.Serve(listener)
	time.Sleep(500 * time.Millisecond)

	return server, storage, ssoBaseURL
}

func shutdownMockSSOServer(t *testing.T, server *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server.Shutdown(ctx)
}

func getMockSSOAuthCode(t *testing.T, client *http.Client, ssoBaseURL, clientID, redirectURI, scope, state, username, password string) string {
	// Disable auto-redirects to handle each step manually
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	defer func() { client.CheckRedirect = nil }()

	// Step 1: Start authorization flow - this will redirect to login with query params preserved
	authURL := fmt.Sprintf("%s/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=%s&state=%s",
		ssoBaseURL, url.QueryEscape(clientID), url.QueryEscape(redirectURI), url.QueryEscape(scope), url.QueryEscape(state))

	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("Failed to start auth flow: %v", err)
	}
	defer resp.Body.Close()

	// Should redirect to /login?response_type=code&client_id=...
	loginURL := resp.Header.Get("Location")
	if loginURL == "" {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected redirect to login, got status %d, body: %s", resp.StatusCode, string(body)[:min(200, len(body))])
	}
	// Make it absolute if relative
	if loginURL[0] == '/' {
		loginURL = ssoBaseURL + loginURL
	}

	// Step 2: Submit login form to the URL with query params
	formData := url.Values{}
	formData.Set("username", username)
	formData.Set("password", password)

	loginResp, err := client.PostForm(loginURL, formData)
	if err != nil {
		t.Fatalf("Failed to submit login: %v", err)
	}
	defer loginResp.Body.Close()

	// This should redirect back to /authorize with authenticated_user
	authorizeURL := loginResp.Header.Get("Location")
	if authorizeURL == "" {
		body, _ := io.ReadAll(loginResp.Body)
		t.Fatalf("No redirect after login, status %d, body: %s", loginResp.StatusCode, string(body)[:min(200, len(body))])
	}
	// Make it absolute if relative
	if authorizeURL[0] == '/' {
		authorizeURL = ssoBaseURL + authorizeURL
	}

	// Step 3: Follow redirect to authorize with authenticated_user
	authResp, err := client.Get(authorizeURL)
	if err != nil {
		t.Fatalf("Failed to follow authorize redirect: %v", err)
	}
	defer authResp.Body.Close()

	// This should redirect to callback with code
	location := authResp.Header.Get("Location")
	if location == "" {
		body, _ := io.ReadAll(authResp.Body)
		t.Fatalf("No redirect to callback, status %d, body: %s", authResp.StatusCode, string(body)[:min(200, len(body))])
	}

	code := extractCodeFromURL(t, location)
	if code == "" {
		t.Fatalf("No code found in redirect URL: %s", location)
	}
	return code
}

// Mock SSO Storage

type mockSSOStorage struct {
	users                map[string]string
	codes                map[string]mockAuthCode
	callbackURL          string                               // Dynamic callback URL for the MCP server
	pendingAuthorizeReqs map[string]fosite.AuthorizeRequester // Pending authorize requests keyed by state
	currentUser          string                               // Current authenticated user
	userInfos            map[string]map[string]interface{}    // Custom user info per user
}

// getUserInfo returns user info for the given username
func (s *mockSSOStorage) getUserInfo(username string) map[string]interface{} {
	if info, ok := s.userInfos[username]; ok {
		return info
	}
	// Default user info
	return map[string]interface{}{
		"sub":    username,
		"email":  username + "@example.com",
		"name":   "SSO User",
		"groups": []string{"users", "mcp-users"},
	}
}

type mockAuthCode struct {
	code    string
	request fosite.Requester
}

func (s *mockSSOStorage) GetClient(ctx context.Context, clientID string) (fosite.Client, error) {
	// Hash "mcp-secret" with bcrypt (fosite expects bcrypt-hashed secrets)
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte("mcp-secret"), bcrypt.DefaultCost)

	// Use the dynamically configured callback URL if set, otherwise use defaults
	redirectURIs := []string{"http://127.0.0.1:8080/test-callback", "http://127.0.0.1:8081/test-callback", "http://localhost/test-callback"}
	if s.callbackURL != "" {
		redirectURIs = append([]string{s.callbackURL}, redirectURIs...)
	}

	return &fosite.DefaultClient{
		ID:            "mcp-client",
		Secret:        hashedSecret,
		RedirectURIs:  redirectURIs,
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid", "profile", "email"},
	}, nil
}

func (s *mockSSOStorage) CreateAuthorizeCodeSession(ctx context.Context, signature string, request fosite.Requester) error {
	s.codes[signature] = mockAuthCode{
		code:    signature,
		request: request,
	}
	return nil
}

func (s *mockSSOStorage) GetAuthorizeCodeSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	code, ok := s.codes[signature]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return code.request, nil
}

func (s *mockSSOStorage) InvalidateAuthorizeCodeSession(ctx context.Context, signature string) error {
	delete(s.codes, signature)
	return nil
}

func (s *mockSSOStorage) CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) error {
	return nil
}

func (s *mockSSOStorage) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	return nil
}

func (s *mockSSOStorage) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return nil, fosite.ErrNotFound
}

func (s *mockSSOStorage) CreateRefreshTokenSession(ctx context.Context, signature string, request fosite.Requester) error {
	return nil
}

func (s *mockSSOStorage) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	return nil
}

func (s *mockSSOStorage) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return nil, fosite.ErrNotFound
}

func (s *mockSSOStorage) RevokeRefreshToken(ctx context.Context, requestID string) error {
	return nil
}

func (s *mockSSOStorage) RevokeAccessToken(ctx context.Context, requestID string) error {
	return nil
}

func (s *mockSSOStorage) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	return nil
}

func (s *mockSSOStorage) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	return nil
}

func (s *mockSSOStorage) RevokeRefreshTokenMaybeGracePeriod(ctx context.Context, requestID string, signature string) error {
	return nil
}

func (s *mockSSOStorage) CreateOpenIDConnectSession(ctx context.Context, signature string, requester fosite.Requester) error {
	return nil
}

func (s *mockSSOStorage) GetOpenIDConnectSession(ctx context.Context, signature string, requester fosite.Requester) (fosite.Requester, error) {
	return nil, fosite.ErrNotFound
}

func (s *mockSSOStorage) DeleteOpenIDConnectSession(ctx context.Context, signature string) error {
	return nil
}
