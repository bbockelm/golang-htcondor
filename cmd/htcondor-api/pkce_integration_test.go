//go:build integration

package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// TestPKCEFlow tests the Authorization Code Flow with PKCE using the swagger-client
func TestPKCEFlow(t *testing.T) {
	// Skip if condor_master is not available
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH, skipping integration test")
	}

	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "htcondor-pkce-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	t.Logf("Using temporary directory: %s", tempDir)

	// Create directories for HTCondor config and tokens
	tokensDir := filepath.Join(tempDir, "tokens.d")
	if err := os.MkdirAll(tokensDir, 0700); err != nil {
		t.Fatalf("Failed to create tokens directory: %v", err)
	}

	passwordsDir := filepath.Join(tempDir, "passwords.d")
	if err := os.MkdirAll(passwordsDir, 0700); err != nil {
		t.Fatalf("Failed to create passwords directory: %v", err)
	}

	// Write a minimal HTCondor config
	configFile := filepath.Join(tempDir, "condor_config")
	configContent := fmt.Sprintf(`
# Test configuration for PKCE flow
LOCAL_DIR = %s
SEC_TOKEN_DIRECTORY = %s
SEC_PASSWORD_DIRECTORY = %s
`, tempDir, tokensDir, passwordsDir)
	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Set CONDOR_CONFIG environment variable
	os.Setenv("CONDOR_CONFIG", configFile)
	defer os.Unsetenv("CONDOR_CONFIG")

	// Step 1: Build the htcondor-api CLI tool
	t.Log("Step 1: Building htcondor-api CLI tool...")
	cliBinary := filepath.Join(tempDir, "htcondor-api")
	buildCmd := exec.Command("go", "build", "-o", cliBinary, ".")
	if output, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to build htcondor-api: %v\nOutput: %s", err, output)
	}
	t.Logf("CLI built successfully: %s", cliBinary)

	// Step 2: Start htcondor-api in demo mode (server)
	t.Log("Step 2: Starting htcondor-api server in demo mode...")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Use a random port for the server
	serverAddr := "127.0.0.1:0"
	serverCmd := exec.CommandContext(ctx, cliBinary, "--demo", "--listen", serverAddr)
	serverCmd.Env = append(os.Environ(), "CONDOR_CONFIG="+configFile)

	// Capture stdout and stderr
	serverStdout, err := serverCmd.StdoutPipe()
	if err != nil {
		t.Fatalf("Failed to create stdout pipe: %v", err)
	}
	serverStderr, err := serverCmd.StderrPipe()
	if err != nil {
		t.Fatalf("Failed to create stderr pipe: %v", err)
	}

	if err := serverCmd.Start(); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer func() {
		cancel()
		serverCmd.Wait()
	}()

	// Monitor logs and extract startup info
	var serverURL, username, password, caPath string
	startupDone := make(chan struct{})
	logCh := make(chan string)

	// Read stdout
	go func() {
		scanner := bufio.NewScanner(serverStdout)
		for scanner.Scan() {
			logCh <- scanner.Text()
		}
	}()

	// Read stderr
	go func() {
		scanner := bufio.NewScanner(serverStderr)
		for scanner.Scan() {
			logCh <- scanner.Text()
		}
	}()

	// Process logs
	go func() {
		// Regex patterns
		addrPattern := regexp.MustCompile(`Listening on.*address=(\S+)`)
		userPattern := regexp.MustCompile(`Username:\s*(\S+)`)
		passPattern := regexp.MustCompile(`Password:\s*(\S+)`)
		caPattern := regexp.MustCompile(`CA Certificate:\s*(\S+)`)

		for line := range logCh {
			t.Logf("[SERVER] %s", line)

			if serverURL == "" {
				if matches := addrPattern.FindStringSubmatch(line); len(matches) > 1 {
					serverURL = "http://" + matches[1]
				} else if strings.Contains(line, "Listening on") && strings.Contains(line, "address=") {
					// Handle structured log format manually if regex fails
					parts := strings.Split(line, "address=")
					if len(parts) > 1 {
						addr := strings.Fields(parts[1])[0]
						addr = strings.Trim(addr, "\"")
						serverURL = "http://" + addr
					}
				}
			}
			if username == "" {
				if matches := userPattern.FindStringSubmatch(line); len(matches) > 1 {
					username = matches[1]
					t.Logf("DEBUG: Matched username: %s", username)
				}
			}
			if password == "" {
				if matches := passPattern.FindStringSubmatch(line); len(matches) > 1 {
					password = matches[1]
					t.Logf("DEBUG: Matched password: %s", password)
				}
			}
			if caPath == "" {
				if matches := caPattern.FindStringSubmatch(line); len(matches) > 1 {
					caPath = matches[1]
					t.Logf("DEBUG: Matched CA path: %s", caPath)
				}
			}

			// Check if we have everything
			if serverURL != "" && username != "" && password != "" && caPath != "" {
				select {
				case <-startupDone:
				default:
					close(startupDone)
				}
			}
		}
	}()

	// Wait for startup
	select {
	case <-startupDone:
		// Success
	case <-time.After(10 * time.Second):
		t.Fatalf("Timeout waiting for server startup")
	}
	t.Logf("Server started at %s with user=%s, pass=%s, ca=%s", serverURL, username, password, caPath)

	// Step 3: Prepare PKCE
	verifier, challenge, err := generatePKCE()
	if err != nil {
		t.Fatalf("Failed to generate PKCE: %v", err)
	}
	t.Logf("PKCE Verifier: %s", verifier)
	t.Logf("PKCE Challenge: %s", challenge)

	// Fix URL scheme to https since demo mode uses TLS
	if strings.HasPrefix(serverURL, "http://") {
		serverURL = strings.Replace(serverURL, "http://", "https://", 1)
		t.Logf("Adjusted server URL to HTTPS: %s", serverURL)
	}

	// Step 4: Initiate Authorization Flow
	t.Log("Step 4: Initiating Authorization Flow...")

	// Create HTTP client
	caCert, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatalf("Failed to read CA certificate: %v", err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		t.Fatalf("Failed to append CA certificate to pool")
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
			},
		},
		Jar:     jar,
		Timeout: 30 * time.Second,
	}

	redirectURI := serverURL + "/docs/oauth2-redirect"

	// Construct Authorize URL
	authURL := fmt.Sprintf("%s/mcp/oauth2/authorize", serverURL)
	params := url.Values{}
	params.Set("client_id", "swagger-client")
	params.Set("response_type", "code")
	params.Set("redirect_uri", redirectURI)
	params.Set("code_challenge", challenge)
	params.Set("code_challenge_method", "S256")
	params.Set("scope", "openid profile email")
	params.Set("state", "test-state-123")

	fullAuthURL := authURL + "?" + params.Encode()
	t.Logf("Visiting Authorize URL: %s", fullAuthURL)

	// GET Authorize URL
	resp, err := client.Get(fullAuthURL)
	if err != nil {
		t.Fatalf("Failed to GET authorize URL: %v", err)
	}
	defer resp.Body.Close()

	// We expect to be redirected to the login page
	// The client follows redirects, so we should be at /idp/login
	t.Logf("Current URL after redirect: %s", resp.Request.URL.String())

	if !strings.Contains(resp.Request.URL.Path, "/idp/login") {
		t.Fatalf("Expected to be at /idp/login, but got: %s", resp.Request.URL.String())
	}

	// Step 5: Perform Login
	t.Log("Step 5: Performing Login...")

	// The login form usually POSTs to the same URL
	loginURL := resp.Request.URL.String()

	loginData := url.Values{}
	loginData.Set("username", username)
	loginData.Set("password", password)

	// We need to handle the redirect to the final callback manually to capture the code
	// because the final redirect might be to a page that doesn't exist or we just want to stop there.
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if strings.HasPrefix(req.URL.String(), redirectURI) {
			return http.ErrUseLastResponse
		}
		return nil
	}

	resp, err = client.PostForm(loginURL, loginData)
	if err != nil {
		t.Fatalf("Failed to POST login: %v", err)
	}
	defer resp.Body.Close()

	// Check if we got the redirect to the callback
	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
		// If we are not redirected, maybe we are at the consent page?
		if strings.Contains(resp.Request.URL.Path, "/idp/consent") {
			t.Log("Hit consent page, approving...")
			// TODO: Handle consent if needed. For now assume swagger-client might skip it or we need to implement it.
			// But let's see what happens.
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("Stopped at consent page (not implemented yet) or error. Status: %d. Body: %s", resp.StatusCode, body)
		}

		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Login failed. Expected redirect, got status %d. URL: %s. Body: %s", resp.StatusCode, resp.Request.URL.String(), body)
	}

	location, err := resp.Location()
	if err != nil {
		t.Fatalf("Failed to get redirect location: %v", err)
	}
	t.Logf("Redirect location: %s", location.String())

	if !strings.HasPrefix(location.String(), redirectURI) {
		t.Fatalf("Expected redirect to %s, got %s", redirectURI, location.String())
	}

	// Extract code
	code := location.Query().Get("code")
	if code == "" {
		t.Fatalf("No code found in redirect URL: %s", location.String())
	}
	t.Logf("Got Authorization Code: %s", code)

	// Step 6: Exchange Code for Token
	t.Log("Step 6: Exchanging Code for Token...")

	tokenURL := serverURL + "/mcp/oauth2/token"
	tokenData := url.Values{}
	tokenData.Set("client_id", "swagger-client")
	tokenData.Set("grant_type", "authorization_code")
	tokenData.Set("code", code)
	tokenData.Set("redirect_uri", redirectURI)
	tokenData.Set("code_verifier", verifier)

	// Reset CheckRedirect
	client.CheckRedirect = nil

	resp, err = client.PostForm(tokenURL, tokenData)
	if err != nil {
		t.Fatalf("Failed to POST token request: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Token exchange failed with status %d. Body: %s", resp.StatusCode, body)
	}

	t.Logf("Token Response: %s", string(body))

	var tokenResp map[string]interface{}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		t.Fatalf("Failed to parse token response: %v", err)
	}

	accessToken, ok := tokenResp["access_token"].(string)
	if !ok || accessToken == "" {
		t.Fatalf("No access_token in response")
	}
	t.Log("Successfully obtained access token!")

	// Step 7: Verify Token works
	t.Log("Step 7: Verifying Token...")

	// Use the token to call the whoami endpoint
	req, err := http.NewRequest("GET", serverURL+"/api/v1/whoami", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("Failed to make protected request: %v", err)
	}
	defer resp.Body.Close()

	body, _ = io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("WhoAmI request failed with status %d. Body: %s", resp.StatusCode, body)
	}

	var whoamiResp struct {
		Authenticated bool   `json:"authenticated"`
		User          string `json:"user"`
	}
	if err := json.Unmarshal(body, &whoamiResp); err != nil {
		t.Fatalf("Failed to parse whoami response: %v", err)
	}

	if !whoamiResp.Authenticated {
		t.Fatalf("WhoAmI response indicates not authenticated: %s", body)
	}

	if whoamiResp.User == "" {
		t.Fatalf("WhoAmI response indicates authenticated but User is empty")
	}
	t.Logf("WhoAmI successful! User: %s", whoamiResp.User)
}

func generatePKCE() (string, string, error) {
	// Generate random verifier
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	verifier := base64.RawURLEncoding.EncodeToString(b)

	// Calculate challenge
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	return verifier, challenge, nil
}
