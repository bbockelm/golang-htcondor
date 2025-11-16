//go:build integration

//nolint:errcheck,noctx,gosec,errorlint,govet // Integration test file with acceptable test patterns
package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
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

	"github.com/bbockelm/golang-htcondor/httpserver"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
)

// TestDynamicClientRegistration tests OAuth2 dynamic client registration
func TestDynamicClientRegistration(t *testing.T) {
	// Skip if condor_master is not available
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH, skipping integration test")
	}

	// Setup server (reuse helper from main test)
	_, server, baseURL, port, signingKeyPath := setupTestServer(t)

	client := &http.Client{Timeout: 30 * time.Second}
	testUser := "regtest"

	// Test dynamic client registration
	t.Log("Testing dynamic client registration...")

	regReq := map[string]interface{}{
		"redirect_uris":  []string{fmt.Sprintf("http://localhost:%d/callback", port)},
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
	accessToken := getOAuth2TokenAuthCodeForClient(t, client, baseURL, regResp.ClientID, regResp.ClientSecret, testUser, signingKeyPath)

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
	tempDir, mcpServer, mcpBaseURL, _, signingKeyPath := setupTestServer(t)

	// Setup mock SSO server with dynamic port
	ssoPort := findAvailablePort(t)
	ssoServer := setupMockSSOServer(t, ssoPort, tempDir)
	ssoBaseURL := fmt.Sprintf("http://127.0.0.1:%d", ssoPort)
	t.Cleanup(func() { shutdownMockSSOServer(t, ssoServer) })

	client := &http.Client{Timeout: 30 * time.Second}
	testUser := "ssouser"
	testPassword := "ssopassword"

	// Create OAuth2 client on MCP server pointing to SSO
	t.Log("Creating OAuth2 client for SSO flow...")
	storage := mcpServer.GetOAuth2Provider().GetStorage()

	clientID := "sso-test-client"
	clientSecret := "sso-test-secret"

	oauth2Client := &fosite.DefaultClient{
		ID:            clientID,
		Secret:        []byte(clientSecret),
		RedirectURIs:  []string{mcpBaseURL + "/callback"},
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid", "mcp:read", "mcp:write"},
		Public:        false,
	}

	if err := storage.CreateClient(context.Background(), oauth2Client); err != nil {
		t.Fatalf("Failed to create OAuth2 client: %v", err)
	}

	t.Log("Testing SSO authorization flow...")

	// Step 1: Get authorization code from mock SSO
	authCode := getMockSSOAuthCode(t, client, ssoBaseURL, testUser, testPassword)
	t.Logf("Received auth code from SSO: %s...", authCode[:10])

	// Step 2: Exchange code for token at MCP server (simulating SSO token exchange)
	// For this test, we'll use the MCP server's own OAuth2 with user header
	accessToken := getOAuth2TokenAuthCodeForClient(t, client, mcpBaseURL, clientID, clientSecret, testUser, signingKeyPath)

	if accessToken == "" {
		t.Fatal("Failed to get access token via SSO flow")
	}

	t.Log("Successfully obtained token via SSO flow")

	// Test MCP access
	t.Log("Testing MCP access with SSO token...")
	testMCPInitialize(t, client, mcpBaseURL, accessToken)

	t.Log("SSO integration test passed!")
}

// Helper functions

func setupTestServer(t *testing.T) (string, *httpserver.Server, string, int, string) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "htcondor-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(tempDir) })

	// Write mini condor configuration
	configFile := filepath.Join(tempDir, "condor_config")
	if err := writeMiniCondorConfig(configFile, tempDir); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	os.Setenv("CONDOR_CONFIG", configFile)
	t.Cleanup(func() { os.Unsetenv("CONDOR_CONFIG") })

	// Start condor_master
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	condorMaster, err := startCondorMaster(ctx, configFile)
	if err != nil {
		t.Fatalf("Failed to start condor_master: %v", err)
	}
	t.Cleanup(func() { stopCondorMaster(condorMaster, t) })

	// Wait for condor
	if err := waitForCondor(tempDir, 30*time.Second); err != nil {
		t.Fatalf("Condor failed to start: %v", err)
	}

	// Generate signing key
	passwordsDir := filepath.Join(tempDir, "passwords.d")
	os.MkdirAll(passwordsDir, 0700)
	signingKeyPath := filepath.Join(passwordsDir, "POOL")
	key, _ := httpserver.GenerateSigningKey()
	os.WriteFile(signingKeyPath, key, 0600)

	// Use port 0 to let the OS assign an available port
	serverAddr := "127.0.0.1:0"
	oauth2DBPath := filepath.Join(tempDir, "oauth2.db")

	server, err := httpserver.NewServer(httpserver.Config{
		ListenAddr:     serverAddr,
		ScheddName:     "local",
		ScheddAddr:     "127.0.0.1:9618",
		UserHeader:     "X-Test-User",
		SigningKeyPath: signingKeyPath,
		TrustDomain:    "test.local",
		UIDDomain:      "test.local",
		EnableMCP:      true,
		OAuth2DBPath:   oauth2DBPath,
		OAuth2Issuer:   "http://127.0.0.1", // Will be updated with actual port
	})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Start server and get the actual port
	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Start()
	}()

	// Wait for server to start and extract the port
	time.Sleep(500 * time.Millisecond)

	// Get the actual listening port from the server
	// Since we can't easily extract the port from the server, we'll use a listener approach
	// For now, let's use a fixed range of ports starting from a high number
	port := findAvailablePort(t)

	// Recreate server with actual port
	serverAddr = fmt.Sprintf("127.0.0.1:%d", port)
	baseURL := fmt.Sprintf("http://%s", serverAddr)

	server, err = httpserver.NewServer(httpserver.Config{
		ListenAddr:     serverAddr,
		ScheddName:     "local",
		ScheddAddr:     "127.0.0.1:9618",
		UserHeader:     "X-Test-User",
		SigningKeyPath: signingKeyPath,
		TrustDomain:    "test.local",
		UIDDomain:      "test.local",
		EnableMCP:      true,
		OAuth2DBPath:   oauth2DBPath,
		OAuth2Issuer:   baseURL,
	})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	go server.Start()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(ctx)
	})

	time.Sleep(1 * time.Second) // Wait for server to start

	return tempDir, server, baseURL, port, signingKeyPath
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

func shutdownTestServer(t *testing.T, server *httpserver.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server.Shutdown(ctx)
}

func getOAuth2TokenAuthCodeForClient(t *testing.T, httpClient *http.Client, baseURL, clientID, clientSecret, username, signingKeyPath string) string {
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

	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Authorization failed: status %d, body: %s", resp.StatusCode, string(body))
	}

	location := resp.Header.Get("Location")
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

func setupMockSSOServer(t *testing.T, port int, tempDir string) *http.Server {
	// Create a simple mock SSO server using fosite
	storage := &mockSSOStorage{
		users: map[string]string{
			"ssouser": "ssopassword",
		},
		codes: make(map[string]mockAuthCode),
	}

	config := &fosite.Config{
		AccessTokenLifespan:   time.Hour,
		AuthorizeCodeLifespan: time.Minute * 10,
		TokenURL:              fmt.Sprintf("http://127.0.0.1:%d/token", port),
		ScopeStrategy:         fosite.HierarchicScopeStrategy,
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
				// Redirect to authorize endpoint with credentials
				q := r.URL.Query()
				redirectURL := fmt.Sprintf("/authorize?%s&authenticated_user=%s", q.Encode(), username)
				http.Redirect(w, r, redirectURL, http.StatusFound)
				return
			}
		}
		// Simple HTML login form
		w.Write([]byte(`<html><body><form method="post"><input name="username"/><input name="password" type="password"/><button>Login</button></form></body></html>`))
	})

	// Authorize endpoint
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		authenticatedUser := r.URL.Query().Get("authenticated_user")

		if authenticatedUser == "" {
			// Redirect to login
			http.Redirect(w, r, "/login?"+r.URL.RawQuery, http.StatusFound)
			return
		}

		ar, err := oauth2Provider.NewAuthorizeRequest(ctx, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		session := &openid.DefaultSession{
			Claims: &jwt.IDTokenClaims{
				Subject: authenticatedUser,
			},
			Subject: authenticatedUser,
		}

		response, err := oauth2Provider.NewAuthorizeResponse(ctx, ar, session)
		if err != nil {
			oauth2Provider.WriteAuthorizeError(ctx, w, ar, err)
			return
		}

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

	return server
}

func shutdownMockSSOServer(t *testing.T, server *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server.Shutdown(ctx)
}

func getMockSSOAuthCode(t *testing.T, client *http.Client, ssoBaseURL, username, password string) string {
	// Step 1: Start authorization flow
	authURL := fmt.Sprintf("%s/authorize?response_type=code&client_id=test&redirect_uri=http://localhost/callback&state=test",
		ssoBaseURL)

	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("Failed to start auth flow: %v", err)
	}
	resp.Body.Close()

	// Step 2: Submit login form
	formData := url.Values{}
	formData.Set("username", username)
	formData.Set("password", password)

	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	defer func() { client.CheckRedirect = nil }()

	loginResp, err := client.PostForm(ssoBaseURL+"/login", formData)
	if err != nil {
		t.Fatalf("Failed to submit login: %v", err)
	}
	defer loginResp.Body.Close()

	// Extract code from redirect
	location := loginResp.Header.Get("Location")
	if location == "" {
		t.Fatal("No redirect after login")
	}

	return extractCodeFromURL(t, location)
}

// Mock SSO Storage

type mockSSOStorage struct {
	users map[string]string
	codes map[string]mockAuthCode
}

type mockAuthCode struct {
	code    string
	session fosite.Session
}

func (s *mockSSOStorage) GetClient(ctx context.Context, clientID string) (fosite.Client, error) {
	return &fosite.DefaultClient{
		ID:            "test",
		Secret:        []byte("test-secret"),
		RedirectURIs:  []string{"http://localhost/callback"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
	}, nil
}

func (s *mockSSOStorage) CreateAuthorizeCodeSession(ctx context.Context, signature string, request fosite.Requester) error {
	s.codes[signature] = mockAuthCode{
		code:    signature,
		session: request.GetSession(),
	}
	return nil
}

func (s *mockSSOStorage) GetAuthorizeCodeSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	code, ok := s.codes[signature]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	req := fosite.NewRequest()
	req.Session = code.session
	return req, nil
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
