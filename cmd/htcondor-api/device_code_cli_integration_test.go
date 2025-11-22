//go:build integration

//nolint:errcheck,noctx,gosec,errorlint,govet // Integration test file with acceptable test patterns

// This file contains integration tests for the device code flow using the htcondor-api CLI tool.
//
// The test verifies the complete end-to-end device code authentication flow:
// 1. Builds the htcondor-api CLI binary
// 2. Starts htcondor-api server in demo mode (which starts a mini HTCondor)
// 3. Runs htcondor-api token fetch command to initiate device code flow
// 4. Parses CLI output to extract device code and verification URL
// 5. Simulates browser-based authentication by sending HTTP requests
// 6. Verifies token is saved to configured storage location
// 7. Uses the token to authenticate against the MCP API
//
// Requirements:
// - HTCondor must be installed (condor_master must be in PATH)
// - Test creates isolated temporary directories for all storage
// - Uses CONDOR_CONFIG environment variable for test isolation
//
// To run this test:
//
//	go test -tags=integration -v ./cmd/htcondor-api/ -run TestDeviceCodeCLIFlow
//
// Or use make:
//
//	make test-integration
package main

import (
	"bufio"
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
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestDeviceCodeCLIFlow tests the end-to-end device code flow with the CLI
func TestDeviceCodeCLIFlow(t *testing.T) {
	// Skip if condor_master is not available
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH, skipping integration test")
	}

	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "htcondor-cli-test-*")
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

	// Write a minimal HTCondor config for token storage
	configFile := filepath.Join(tempDir, "condor_config")
	configContent := fmt.Sprintf(`
# Test configuration for device code CLI flow
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
	buildCmd.Dir = "/home/runner/work/golang-htcondor/golang-htcondor/cmd/htcondor-api"
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

	// Wait for server to start and extract the actual listening address and IDP credentials
	t.Log("Waiting for server to start and extract IDP credentials...")
	serverURL, idpUsername, idpPassword, err := waitForServerStartup(serverStdout, serverStderr, 60*time.Second, t)
	if err != nil {
		t.Fatalf("Server failed to start: %v", err)
	}
	t.Logf("Server started at: %s", serverURL)
	t.Logf("IDP Username: %s", idpUsername)
	t.Logf("IDP Password: %s", idpPassword)

	// Give server a moment to fully initialize
	time.Sleep(2 * time.Second)

	// Step 3: Run htcondor-api token fetch
	t.Log("Step 3: Running htcondor-api token fetch...")
	fetchCmd := exec.Command(cliBinary, "token", "fetch", serverURL, "--trust-domain", "test.local")
	fetchCmd.Env = append(os.Environ(), "CONDOR_CONFIG="+configFile)

	// Capture stdout to read device code information
	fetchStdout, err := fetchCmd.StdoutPipe()
	if err != nil {
		t.Fatalf("Failed to create stdout pipe for token fetch: %v", err)
	}

	if err := fetchCmd.Start(); err != nil {
		t.Fatalf("Failed to start token fetch: %v", err)
	}

	// Step 4: Read stdout to get device code URL and user code
	t.Log("Step 4: Reading device code information from CLI output...")
	verificationURL, userCode, err := readDeviceCodeFromOutput(fetchStdout, 30*time.Second, t)
	if err != nil {
		fetchCmd.Wait()
		t.Fatalf("Failed to read device code: %v", err)
	}
	t.Logf("Verification URL: %s", verificationURL)
	t.Logf("User code: %s", userCode)

	// Step 5: Simulate browser authentication using IDP credentials
	t.Log("Step 5: Simulating browser-based authentication with IDP...")
	if err := approveDeviceViaBrowser(verificationURL, userCode, idpUsername, idpPassword); err != nil {
		fetchCmd.Wait()
		t.Fatalf("Failed to approve device: %v", err)
	}
	t.Log("Device approved successfully")

	// Wait for token fetch to complete
	t.Log("Waiting for token fetch to complete...")
	if err := fetchCmd.Wait(); err != nil {
		t.Fatalf("Token fetch command failed: %v", err)
	}
	t.Log("Token fetch completed successfully")

	// Step 6: Verify token was saved
	t.Log("Step 6: Verifying token was saved...")
	tokenFiles, err := os.ReadDir(tokensDir)
	if err != nil {
		t.Fatalf("Failed to read tokens directory: %v", err)
	}
	if len(tokenFiles) == 0 {
		t.Fatal("No token files found in tokens directory")
	}
	t.Logf("Found %d token file(s) in tokens directory", len(tokenFiles))

	// Read the token
	var token string
	for _, file := range tokenFiles {
		if !file.IsDir() {
			tokenPath := filepath.Join(tokensDir, file.Name())
			tokenBytes, err := os.ReadFile(tokenPath)
			if err != nil {
				t.Logf("Warning: failed to read token file %s: %v", file.Name(), err)
				continue
			}
			token = strings.TrimSpace(string(tokenBytes))
			if token != "" {
				t.Logf("Found token in file: %s", file.Name())
				break
			}
		}
	}

	if token == "" {
		t.Fatal("No valid token found in tokens directory")
	}

	// Step 7: Use the token to authenticate against the web API
	t.Log("Step 7: Testing token with protected MCP API endpoint...")
	if err := testMCPAPIWithToken(serverURL, token); err != nil {
		t.Fatalf("Failed to use token with MCP API: %v", err)
	}
	t.Log("Token successfully used to authenticate with MCP API!")

	t.Log("✅ All device code CLI flow tests passed!")
}

// waitForServerStartup waits for the server to start and returns the server URL, IDP username, and password
func waitForServerStartup(stdout, stderr io.Reader, timeout time.Duration, t *testing.T) (string, string, string, error) {
	deadline := time.Now().Add(timeout)

	// Read stdout and stderr concurrently
	urlChan := make(chan string, 1)
	usernameChan := make(chan string, 1)
	passwordChan := make(chan string, 1)
	errChan := make(chan error, 1)

	go func() {
		scanner := bufio.NewScanner(io.MultiReader(stdout, stderr))
		// Look for patterns that indicate server is listening
		// Examples: "HTTP server listening on: http://127.0.0.1:8080" or "Server started on 127.0.0.1:8080"
		listenPattern := regexp.MustCompile(`(?i)(listening|started).*(http://[^\s]+|https://[^\s]+|\d+\.\d+\.\d+\.\d+:\d+)`)
		// Look for IDP credentials: "Username: admin" and "Password: <password>"
		usernamePattern := regexp.MustCompile(`Username:\s*(\S+)`)
		passwordPattern := regexp.MustCompile(`Password:\s*(\S+)`)

		var serverURL, username, password string

		for scanner.Scan() {
			line := scanner.Text()
			t.Logf("[SERVER] %s", line)

			// Look for listening address
			if matches := listenPattern.FindStringSubmatch(line); len(matches) > 0 {
				// Extract the URL or address
				for _, match := range matches[1:] {
					if strings.HasPrefix(match, "http://") || strings.HasPrefix(match, "https://") {
						serverURL = match
						t.Logf("Found server URL: %s", serverURL)
						break
					}
					if strings.Contains(match, ":") && !strings.Contains(match, "//") {
						// It's an address without protocol, add http://
						serverURL = "http://" + match
						t.Logf("Found server address: %s", serverURL)
						break
					}
				}
			}

			// Also check for the demo mode self-signed cert message followed by listen address
			if strings.Contains(line, "HTTP server listening on") || strings.Contains(line, "Server started") {
				parts := strings.Split(line, ":")
				if len(parts) >= 3 {
					// Extract the URL (last part after final ":")
					urlPart := strings.TrimSpace(strings.Join(parts[len(parts)-2:], ":"))
					if strings.HasPrefix(urlPart, "http") {
						serverURL = urlPart
						t.Logf("Found server URL from message: %s", serverURL)
					}
				}
			}

			// Look for IDP username
			if matches := usernamePattern.FindStringSubmatch(line); len(matches) > 1 {
				username = matches[1]
				t.Logf("Found IDP username: %s", username)
			}

			// Look for IDP password
			if matches := passwordPattern.FindStringSubmatch(line); len(matches) > 1 {
				password = matches[1]
				t.Logf("Found IDP password: %s", password)
			}

			// If we have all three, return them
			if serverURL != "" && username != "" && password != "" {
				urlChan <- serverURL
				usernameChan <- username
				passwordChan <- password
				return
			}
		}

		if err := scanner.Err(); err != nil {
			errChan <- err
		} else if serverURL == "" {
			errChan <- fmt.Errorf("server output ended without finding listen address")
		} else if username == "" || password == "" {
			errChan <- fmt.Errorf("server output ended without finding IDP credentials (username: %q, password: %q)", username, password)
		}
	}()

	var serverURL, username, password string
	for time.Now().Before(deadline) {
		select {
		case url := <-urlChan:
			serverURL = url
			if username != "" && password != "" {
				return serverURL, username, password, nil
			}
		case user := <-usernameChan:
			username = user
			if serverURL != "" && password != "" {
				return serverURL, username, password, nil
			}
		case pass := <-passwordChan:
			password = pass
			if serverURL != "" && username != "" {
				return serverURL, username, password, nil
			}
		case err := <-errChan:
			return "", "", "", err
		case <-time.After(500 * time.Millisecond):
			// Continue waiting
		}
	}

	return "", "", "", fmt.Errorf("timeout waiting for server to start")
}

// readDeviceCodeFromOutput reads the device code information from CLI output
func readDeviceCodeFromOutput(stdout io.Reader, timeout time.Duration, t *testing.T) (string, string, error) {
	deadline := time.Now().Add(timeout)

	urlChan := make(chan string, 1)
	codeChan := make(chan string, 1)
	errChan := make(chan error, 1)

	go func() {
		scanner := bufio.NewScanner(stdout)
		// Look for patterns like:
		// "Please visit: http://127.0.0.1:8080/mcp/oauth2/device/verify?user_code=ABCD1234"
		// "(Code: ABCD1234)"
		urlPattern := regexp.MustCompile(`Please visit:\s*(https?://[^\s]+)`)
		codePattern := regexp.MustCompile(`\(Code:\s*([A-Z0-9-]+)\)`)

		var verificationURL, userCode string

		for scanner.Scan() {
			line := scanner.Text()
			t.Logf("[TOKEN FETCH] %s", line)

			// Look for verification URL
			if matches := urlPattern.FindStringSubmatch(line); len(matches) > 1 {
				verificationURL = matches[1]
				t.Logf("Found verification URL: %s", verificationURL)
			}

			// Look for user code
			if matches := codePattern.FindStringSubmatch(line); len(matches) > 1 {
				userCode = matches[1]
				t.Logf("Found user code: %s", userCode)
			}

			// If we have both, return them
			if verificationURL != "" && userCode != "" {
				urlChan <- verificationURL
				codeChan <- userCode
				return
			}
		}

		if err := scanner.Err(); err != nil {
			errChan <- err
		} else if verificationURL == "" || userCode == "" {
			errChan <- fmt.Errorf("incomplete device code information (URL: %q, Code: %q)", verificationURL, userCode)
		}
	}()

	var verificationURL, userCode string
	for time.Now().Before(deadline) {
		select {
		case url := <-urlChan:
			verificationURL = url
			if userCode != "" {
				return verificationURL, userCode, nil
			}
		case code := <-codeChan:
			userCode = code
			if verificationURL != "" {
				return verificationURL, userCode, nil
			}
		case err := <-errChan:
			return "", "", err
		case <-time.After(500 * time.Millisecond):
			// Continue waiting
		}
	}

	return "", "", fmt.Errorf("timeout waiting for device code information")
}

// approveDeviceViaBrowser simulates a browser approval by logging in to IDP and approving the device
func approveDeviceViaBrowser(verificationURL, userCode, username, password string) error {
	// Create an HTTP client that handles cookies (for session management)
	jar := &cookieJar{cookies: make(map[string][]*http.Cookie)}
	client := &http.Client{
		Timeout: 30 * time.Second,
		Jar:     jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Allow up to 10 redirects
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			return nil
		},
	}

	// Step 1: GET the verification URL to get the login form and any session cookies
	req, err := http.NewRequest("GET", verificationURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create verification request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to get verification page: %w", err)
	}
	resp.Body.Close()

	// Step 2: Submit login credentials to the IDP login endpoint
	// The IDP login endpoint is /idp/login
	baseURL := verificationURL[:strings.Index(verificationURL[8:], "/")+8] // Extract base URL
	loginURL := baseURL + "/idp/login?redirect_uri=" + verificationURL

	loginData := fmt.Sprintf("username=%s&password=%s", username, password)
	req, err = http.NewRequest("POST", loginURL, strings.NewReader(loginData))
	if err != nil {
		return fmt.Errorf("failed to create login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err = client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to submit login: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("login failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Step 3: After login, approve the device by submitting the device verification form
	// The form should be at the verification URL
	approvalData := fmt.Sprintf("user_code=%s&action=approve", userCode)
	req, err = http.NewRequest("POST", verificationURL, strings.NewReader(approvalData))
	if err != nil {
		return fmt.Errorf("failed to create approval request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err = client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send approval request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("approval request failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// cookieJar implements http.CookieJar for session management
type cookieJar struct {
	cookies map[string][]*http.Cookie
	mu      sync.Mutex
}

func (j *cookieJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.cookies[u.Host] = cookies
}

func (j *cookieJar) Cookies(u *url.URL) []*http.Cookie {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.cookies[u.Host]
}

// testMCPAPIWithToken tests using the token with a protected MCP API endpoint
func testMCPAPIWithToken(serverURL, token string) error {
	client := &http.Client{Timeout: 30 * time.Second}

	// Test MCP initialize endpoint
	mcpRequest := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]interface{}{},
			"clientInfo": map[string]interface{}{
				"name":    "device-cli-test",
				"version": "1.0",
			},
		},
	}

	reqBody, err := json.Marshal(mcpRequest)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", serverURL+"/mcp/message", bytes.NewBuffer(reqBody))
	if err != nil {
		return fmt.Errorf("failed to create MCP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send MCP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("MCP request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var mcpResponse map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&mcpResponse); err != nil {
		return fmt.Errorf("failed to decode MCP response: %w", err)
	}

	if mcpResponse["error"] != nil {
		return fmt.Errorf("MCP request returned error: %v", mcpResponse["error"])
	}

	result, ok := mcpResponse["result"].(map[string]interface{})
	if !ok || result["protocolVersion"] == nil {
		return fmt.Errorf("MCP initialize result missing protocolVersion")
	}

	return nil
}
