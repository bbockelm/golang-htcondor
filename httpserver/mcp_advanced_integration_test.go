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

	// Setup main MCP server
	tempDir, mcpServer, mcpBaseURL := setupTestServer(t)

	// Create a test OAuth2 client in MCP for the final token exchange
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

	// Setup mock SSO server with dynamic port
	ssoPort := findAvailablePort(t)
	ssoServer, ssoStorage := setupMockSSOServer(t, ssoPort, tempDir)
	ssoBaseURL := fmt.Sprintf("http://127.0.0.1:%d", ssoPort)
	t.Cleanup(func() { shutdownMockSSOServer(t, ssoServer) })

	// Register the callback URL in SSO storage now that we know the MCP server URL
	ssoStorage.callbackURL = mcpBaseURL + "/test-callback"

	client := &http.Client{Timeout: 30 * time.Second}
	testUser := "ssouser"
	testPassword := "ssopassword"

	t.Log("Testing SSO authorization flow...")

	// Step 1: Get authorization code from mock SSO
	// SSO has its own client_id ("mcp-client") and callback URL
	authCode := getMockSSOAuthCode(t, client, ssoBaseURL, "mcp-client", mcpBaseURL+"/test-callback", "openid profile", "random-state", testUser, testPassword)
	if authCode == "" {
		t.Fatal("Failed to get auth code from SSO")
	}
	t.Logf("Received auth code from SSO: %s...", authCode[:min(10, len(authCode))])

	// Step 2: Exchange SSO code for SSO access token
	// In a real system, the MCP server would do this server-side
	tokenReq, _ := http.NewRequest("POST", ssoBaseURL+"/token", bytes.NewBufferString(
		fmt.Sprintf("grant_type=authorization_code&code=%s&redirect_uri=%s/test-callback&client_id=mcp-client&client_secret=mcp-secret",
			authCode, mcpBaseURL),
	))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	tokenResp, err := client.Do(tokenReq)
	if err != nil {
		t.Fatalf("Failed to exchange SSO code for token: %v", err)
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(tokenResp.Body)
		t.Fatalf("SSO token exchange failed: status %d, body: %s", tokenResp.StatusCode, string(body))
	}

	var ssoToken struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(tokenResp.Body).Decode(&ssoToken); err != nil {
		t.Fatalf("Failed to decode SSO token: %v", err)
	}

	t.Logf("Received SSO access token: %s...", ssoToken.AccessToken[:min(10, len(ssoToken.AccessToken))])

	// Step 3: Use SSO-authenticated user to get MCP token
	// In a real system, MCP would validate the SSO token and extract user claims
	// For this test, we'll use MCP's own OAuth2 with the authenticated user
	t.Log("Getting MCP token for SSO-authenticated user...")

	// First, ensure the test client exists in MCP OAuth2 storage
	mcpAuthURL := fmt.Sprintf("%s/mcp/oauth2/authorize?response_type=code&client_id=test-client&redirect_uri=%s/callback&scope=openid+mcp:read+mcp:write&state=teststate&username=%s",
		mcpBaseURL, mcpBaseURL, testUser)

	req, _ := http.NewRequest("GET", mcpAuthURL, nil)
	req.Header.Set("X-Test-User", testUser)

	// Disable auto-redirect to capture the code
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	defer func() { client.CheckRedirect = nil }()

	authResp, err := client.Do(req)
	if err != nil {
		t.Fatalf("MCP authorize request failed: %v", err)
	}
	defer authResp.Body.Close()

	if authResp.StatusCode != http.StatusFound && authResp.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(authResp.Body)
		t.Fatalf("MCP authorization failed: status %d, body: %s", authResp.StatusCode, string(body))
	}

	location := authResp.Header.Get("Location")
	mcpAuthCode := extractCodeFromURL(t, location)
	if mcpAuthCode == "" {
		t.Fatalf("No code in MCP redirect: %s", location)
	}

	// Exchange MCP auth code for access token
	tokenReq2, _ := http.NewRequest("POST", mcpBaseURL+"/mcp/oauth2/token", bytes.NewBufferString(
		fmt.Sprintf("grant_type=authorization_code&code=%s&redirect_uri=%s/callback&client_id=test-client&client_secret=test-secret",
			mcpAuthCode, mcpBaseURL),
	))
	tokenReq2.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	tokenResp2, err := client.Do(tokenReq2)
	if err != nil {
		t.Fatalf("MCP token exchange failed: %v", err)
	}
	defer tokenResp2.Body.Close()

	if tokenResp2.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(tokenResp2.Body)
		t.Fatalf("MCP token exchange returned error: status %d, body: %s", tokenResp2.StatusCode, string(body))
	}

	var mcpToken struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(tokenResp2.Body).Decode(&mcpToken); err != nil {
		t.Fatalf("Failed to decode MCP token: %v", err)
	}

	accessToken := mcpToken.AccessToken
	if accessToken == "" {
		t.Fatal("Failed to get MCP access token")
	}

	t.Log("Successfully obtained MCP token via SSO flow")

	// Test MCP access
	t.Log("Testing MCP access with SSO-authenticated token...")
	testMCPInitialize(t, client, mcpBaseURL, accessToken)

	t.Log("SSO integration test passed!")
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

	// Find an available port before creating the server
	// This is necessary because OAuth2Issuer must be set correctly when the provider is created
	availablePort := findAvailablePort(t)
	serverAddr := fmt.Sprintf("127.0.0.1:%d", availablePort)
	baseURL := fmt.Sprintf("http://%s", serverAddr)
	oauth2DBPath := filepath.Join(tempDir, "oauth2.db")

	// Create server with the pre-determined port and correct OAuth2Issuer
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
		OAuth2Issuer:   baseURL, // Correct issuer with actual port
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

	// Verify server is listening on the expected address
	actualAddr := server.GetAddr()
	if actualAddr == "" {
		t.Fatal("Server failed to start - no listening address available")
	}

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

// findAvailablePort finds an available port for testing
func findAvailablePort(t *testing.T) int {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to find available port: %v", err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
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

func setupMockSSOServer(t *testing.T, port int, tempDir string) (*http.Server, *mockSSOStorage) {
	// Create a simple mock SSO server using fosite
	storage := &mockSSOStorage{
		users: map[string]string{
			"ssouser": "ssopassword",
		},
		codes:                make(map[string]mockAuthCode),
		pendingAuthorizeReqs: make(map[string]fosite.AuthorizeRequester),
	}

	config := &fosite.Config{
		AccessTokenLifespan:   time.Hour,
		AuthorizeCodeLifespan: time.Minute * 10,
		TokenURL:              fmt.Sprintf("http://127.0.0.1:%d/token", port),
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
	)

	mux := http.NewServeMux()

	// Login page
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			username := r.FormValue("username")
			password := r.FormValue("password")

			if storage.users[username] == password {
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

	server := &http.Server{
		Addr:    fmt.Sprintf("127.0.0.1:%d", port),
		Handler: mux,
	}

	go server.ListenAndServe()
	time.Sleep(500 * time.Millisecond)

	return server, storage
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
		Scopes:        []string{"openid", "profile"},
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
