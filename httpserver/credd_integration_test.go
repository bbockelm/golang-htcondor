//go:build integration

//nolint:errcheck,noctx,gosec,errorlint,govet // Integration test file with acceptable test patterns
package httpserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// TestCreddHTTPIntegration exercises the credential endpoints against a running HTTP server
// with a live mini-HTCondor instance. Uses the CEDAR-based credd client.
func TestCreddHTTPIntegration(t *testing.T) {
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH, skipping integration test")
	}

	tempDir, err := os.MkdirTemp("", "htcondor-credd-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer func() {
		if !t.Failed() {
			os.RemoveAll(tempDir)
		} else {
			t.Logf("Test failed, preserving logs in: %s", tempDir)
		}
	}()

	socketDir, err := os.MkdirTemp("/tmp", "htc_sock_*")
	if err != nil {
		t.Fatalf("Failed to create socket directory: %v", err)
	}
	defer os.RemoveAll(socketDir)

	passwordsDir := filepath.Join(tempDir, "passwords.d")
	if err := os.MkdirAll(passwordsDir, 0700); err != nil {
		t.Fatalf("Failed to create passwords.d directory: %v", err)
	}

	// Create OAuth credential directory for credd
	oauthCredsDir := filepath.Join(tempDir, "oauth_credentials")
	if err := os.MkdirAll(oauthCredsDir, 0700); err != nil {
		t.Fatalf("Failed to create oauth credentials directory: %v", err)
	}
	signingKeyPath := filepath.Join(passwordsDir, "POOL")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	if err := os.WriteFile(signingKeyPath, key, 0600); err != nil {
		t.Fatalf("Failed to write signing key: %v", err)
	}

	// Create RSA keys for local credmon using Go's crypto library
	privKeyPath := filepath.Join(tempDir, "credmon_privkey.pem")
	pubKeyPath := filepath.Join(tempDir, "credmon_pubkey.pem")

	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// Encode private key to PEM format
	privKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privKeyBytes,
	})
	if err := os.WriteFile(privKeyPath, privKeyPEM, 0600); err != nil {
		t.Fatalf("Failed to write private key: %v", err)
	}

	// Encode public key to PEM format
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})
	if err := os.WriteFile(pubKeyPath, pubKeyPEM, 0644); err != nil {
		t.Fatalf("Failed to write public key: %v", err)
	}

	// Build localcredmon daemon binary
	localCredmonBin := filepath.Join(tempDir, "htcondor-localcredmon")
	buildCmd := exec.Command("go", "build", "-buildvcs=false", "-o", localCredmonBin, "./cmd/htcondor-localcredmon")
	buildCmd.Dir = ".." // Build from project root
	if output, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to build localcredmon: %v, output: %s", err, string(output))
	}

	trustDomain := "test.htcondor.org"
	configFile := filepath.Join(tempDir, "condor_config")
	extraConfig := fmt.Sprintf(`
# Enable credd daemon and local credmon (single instance handling multiple providers)
DAEMON_LIST = $(DAEMON_LIST), CREDD, LOCAL_CREDMON
CREDD_ADDRESS_FILE = $(LOG)/.credd_address
CREDD_USE_SHARED_PORT = FALSE
SEC_CREDENTIAL_DIRECTORY_OAUTH = %s

# Enable full debug logging for credd
CREDD_DEBUG = D_FULLDEBUG D_SECURITY:2
MAX_CREDD_LOG = 0

# Allow authenticated user to store credentials for any user (for testing)
CRED_SUPER_USERS = *

# Require encryption for credd
SEC_CREDD_AUTHENTICATION = REQUIRED
SEC_CREDD_ENCRYPTION = REQUIRED

# Trust the credential directory (for Go credmon)
TRUST_CREDENTIAL_DIRECTORY = True

# Allow daemons to communicate with master (for keepalive/ready signals)
ALLOW_DAEMON = *

# Configure local credmon daemon (handles multiple providers)
LOCAL_CREDMON = %s
LOCAL_CREDMON_NAME = LOCAL_CREDMON
LOCAL_CREDMON_LOG = $(LOG)/LocalCredmonLog
LOCAL_CREDMON_DEBUG = D_FULLDEBUG

# Local credmon configuration parameters (shared by all providers)
LOCAL_CREDMON_PROVIDERS = github,gitlab
LOCAL_CREDMON_KEY_FILE = %s
LOCAL_CREDMON_ISSUER = https://test.htcondor.org
LOCAL_CREDMON_AUDIENCE = https://github.com https://gitlab.com
LOCAL_CREDMON_LIFETIME = 20m
LOCAL_CREDMON_SCAN_INTERVAL = 2s
`, oauthCredsDir, localCredmonBin, privKeyPath)
	if err := writeMiniCondorConfig(configFile, tempDir, socketDir, passwordsDir, trustDomain, t); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}
	// Append credd-specific config
	f, err := os.OpenFile(configFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("Failed to open config file: %v", err)
	}
	if _, err := f.WriteString(extraConfig); err != nil {
		f.Close()
		t.Fatalf("Failed to write extra config: %v", err)
	}
	f.Close()

	t.Setenv("CONDOR_CONFIG", configFile)
	htcondor.ReloadDefaultConfig()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	condorMaster, err := startCondorMaster(ctx, configFile, tempDir)
	if err != nil {
		t.Fatalf("Failed to start condor_master: %v", err)
	}
	defer stopCondorMaster(condorMaster, t)

	if err := waitForCondor(tempDir, 60*time.Second, t); err != nil {
		t.Fatalf("Condor failed to start: %v", err)
	}

	scheddAddr, err := getScheddAddress(tempDir, 10*time.Second)
	if err != nil {
		t.Fatalf("Failed to get schedd address: %v", err)
	}

	// Wait for credd to start and get address
	creddAddr, err := getCreddAddress(tempDir, 10*time.Second)
	if err != nil {
		t.Fatalf("Failed to get credd address: %v", err)
	}
	t.Logf("Credd address: %s", creddAddr)

	// Create CedarCredd client
	creddClient := htcondor.NewCedarCredd(creddAddr)

	server, baseURL := startTestHTTPServerWithCredd(ctx, tempDir, scheddAddr, passwordsDir, creddClient, t)
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	apiBase := strings.TrimRight(baseURL, "/") + deriveAPIPrefix(t, baseURL)

	client := &http.Client{Timeout: 30 * time.Second}
	// Use Unix username for authenticated user - since the credd is running
	// unprivileged, the Unix username used for the job will be the same as
	// the one used to run condor_master.
	currentUserInfo, err := user.Current()
	if err != nil {
		t.Fatalf("Failed to get current user: %v", err)
	}
	currentUsername := currentUserInfo.Username + "@test.htcondor.org" // Must include domain for store_cred handler

	// Wait for localcredmon daemon to signal readiness (launched by condor_master)
	// The daemon will automatically process .top files every 2 seconds
	if err := waitForLocalCredmonReady(tempDir, 10*time.Second); err != nil {
		t.Fatalf("LOCAL_CREDMON daemon failed to become ready: %v", err)
	}
	t.Logf("✅ LOCAL_CREDMON daemon is ready")

	// Add service credential with refresh=true to create .top file for credmon
	addBody := map[string]any{
		"cred_type":  "OAuth",
		"credential": "oauth-token",
		"refresh":    true, // This creates .top file for credmon to process
	}
	addBytes, _ := json.Marshal(addBody)
	addReq, _ := http.NewRequest(http.MethodPost, apiBase+"/creds/service/github", bytes.NewReader(addBytes))
	addReq.Header.Set("Content-Type", "application/json")
	addReq.Header.Set("X-Test-User", currentUsername)
	addResp, err := client.Do(addReq)
	if err != nil {
		t.Fatalf("failed to add credential: %v", err)
	}
	defer addResp.Body.Close()
	if addResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(addResp.Body)
		t.Fatalf("expected 201 created, got %d: %s", addResp.StatusCode, string(body))
	}

	// Fetch credential payload
	var credPayload struct {
		Credential string `json:"credential"`
	}

	// First attempt should return 404 (file doesn't exist yet)
	getReq1, _ := http.NewRequest(http.MethodGet, apiBase+"/creds/service/github/credential", nil)
	getReq1.Header.Set("X-Test-User", currentUsername)
	getResp1, err := client.Do(getReq1)
	if err != nil {
		t.Fatalf("failed to fetch credential: %v", err)
	}
	body1, _ := io.ReadAll(getResp1.Body)
	getResp1.Body.Close()

	if getResp1.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 before credmon processes, got %d: %s", getResp1.StatusCode, string(body1))
	}
	t.Logf("✅ Correctly received 404 for credential before .use file exists")

	// Wait for credmon daemon to process the .top file (scans every 2s)
	// Poll for .use file to appear
	var credPayloadBytes []byte
	maxWait := 10 * time.Second
	waitStart := time.Now()
	for time.Since(waitStart) < maxWait {
		getReq2, _ := http.NewRequest(http.MethodGet, apiBase+"/creds/service/github/credential", nil)
		getReq2.Header.Set("X-Test-User", currentUsername)
		getResp2, err := client.Do(getReq2)
		if err != nil {
			t.Fatalf("failed to fetch credential: %v", err)
		}

		if getResp2.StatusCode == http.StatusOK {
			credPayloadBytes, _ = io.ReadAll(getResp2.Body)
			getResp2.Body.Close()
			break
		}

		getResp2.Body.Close()
		time.Sleep(500 * time.Millisecond)
	}

	if credPayloadBytes == nil {
		t.Fatalf("credmon did not process .top file within %v", maxWait)
	}
	t.Logf("✅ Local credmon processed .top file")

	// Parse and validate credential
	if err := json.Unmarshal(credPayloadBytes, &credPayload); err != nil {
		t.Fatalf("failed to decode credential response: %v", err)
	}

	if credPayload.Credential == "" {
		t.Fatalf("expected non-empty credential")
	}
	t.Logf("✅ Successfully fetched credential from .use file (len=%d)", len(credPayload.Credential))

	// List credentials - should show only github
	listReq, _ := http.NewRequest(http.MethodGet, apiBase+"/creds/service", nil)
	listReq.Header.Set("X-Test-User", currentUsername)
	listResp, err := client.Do(listReq)
	if err != nil {
		t.Fatalf("failed to list credentials: %v", err)
	}
	defer listResp.Body.Close()
	if listResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(listResp.Body)
		t.Fatalf("expected 200 on list, got %d: %s", listResp.StatusCode, string(body))
	}
	var listPayload []serviceStatusResponse
	if err := json.NewDecoder(listResp.Body).Decode(&listPayload); err != nil {
		t.Fatalf("failed to decode list response: %v", err)
	}
	if len(listPayload) != 1 || listPayload[0].Service != "github" || !listPayload[0].Exists {
		t.Fatalf("unexpected list payload (expected 1 github credential): %+v", listPayload)
	}
	t.Logf("✅ List shows 1 credential: github")

	// Add gitlab credential with refresh=true
	addBody2 := map[string]any{
		"cred_type":  "OAuth",
		"credential": "gitlab-oauth-token",
		"refresh":    true,
	}
	addBytes2, _ := json.Marshal(addBody2)
	addReq2, _ := http.NewRequest(http.MethodPost, apiBase+"/creds/service/gitlab", bytes.NewReader(addBytes2))
	addReq2.Header.Set("Content-Type", "application/json")
	addReq2.Header.Set("X-Test-User", currentUsername)
	addResp2, err := client.Do(addReq2)
	if err != nil {
		t.Fatalf("failed to add gitlab credential: %v", err)
	}
	defer addResp2.Body.Close()
	if addResp2.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(addResp2.Body)
		t.Fatalf("expected 201 created for gitlab, got %d: %s", addResp2.StatusCode, string(body))
	}
	t.Logf("✅ Added gitlab credential")

	// Wait for gitlab credmon to process the .top file
	var gitlabCredBytes []byte
	waitStart2 := time.Now()
	for time.Since(waitStart2) < maxWait {
		getReq3, _ := http.NewRequest(http.MethodGet, apiBase+"/creds/service/gitlab/credential", nil)
		getReq3.Header.Set("X-Test-User", currentUsername)
		getResp3, err := client.Do(getReq3)
		if err != nil {
			t.Fatalf("failed to fetch gitlab credential: %v", err)
		}

		if getResp3.StatusCode == http.StatusOK {
			gitlabCredBytes, _ = io.ReadAll(getResp3.Body)
			getResp3.Body.Close()
			break
		}

		getResp3.Body.Close()
		time.Sleep(500 * time.Millisecond)
	}

	if gitlabCredBytes == nil {
		t.Fatalf("credmon did not process gitlab .top file within %v", maxWait)
	}
	t.Logf("✅ Local credmon processed gitlab .top file")

	var gitlabCred struct {
		Credential string `json:"credential"`
	}
	if err := json.Unmarshal(gitlabCredBytes, &gitlabCred); err != nil {
		t.Fatalf("failed to decode gitlab credential response: %v", err)
	}
	if gitlabCred.Credential == "" {
		t.Fatalf("expected non-empty gitlab credential")
	}
	t.Logf("✅ Successfully fetched gitlab credential from .use file (len=%d)", len(gitlabCred.Credential))

	// List credentials - should now show both github and gitlab
	listReq2, _ := http.NewRequest(http.MethodGet, apiBase+"/creds/service", nil)
	listReq2.Header.Set("X-Test-User", currentUsername)
	listResp2, err := client.Do(listReq2)
	if err != nil {
		t.Fatalf("failed to list credentials after gitlab: %v", err)
	}
	defer listResp2.Body.Close()
	if listResp2.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(listResp2.Body)
		t.Fatalf("expected 200 on second list, got %d: %s", listResp2.StatusCode, string(body))
	}
	var listPayload2 []serviceStatusResponse
	if err := json.NewDecoder(listResp2.Body).Decode(&listPayload2); err != nil {
		t.Fatalf("failed to decode second list response: %v", err)
	}
	if len(listPayload2) != 2 {
		t.Fatalf("expected 2 credentials in list, got %d: %+v", len(listPayload2), listPayload2)
	}

	// Verify both services are present
	services := make(map[string]bool)
	for _, item := range listPayload2 {
		if !item.Exists {
			t.Fatalf("expected credential %s to exist", item.Service)
		}
		services[item.Service] = true
	}
	if !services["github"] || !services["gitlab"] {
		t.Fatalf("expected both 'github' and 'gitlab' in list, got: %+v", listPayload2)
	}
	t.Logf("✅ List shows 2 credentials: github and gitlab")

	// Delete credential
	deleteReq, _ := http.NewRequest(http.MethodDelete, apiBase+"/creds/service/github", nil)
	deleteReq.Header.Set("X-Test-User", currentUsername)
	deleteResp, err := client.Do(deleteReq)
	if err != nil {
		t.Fatalf("failed to delete credential: %v", err)
	}
	defer deleteResp.Body.Close()
	if deleteResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(deleteResp.Body)
		t.Fatalf("expected 200 on delete, got %d: %s", deleteResp.StatusCode, string(body))
	}

	// Verify credential no longer exists
	statusReq, _ := http.NewRequest(http.MethodGet, apiBase+"/creds/service/github", nil)
	statusReq.Header.Set("X-Test-User", currentUsername)
	statusResp, err := client.Do(statusReq)
	if err != nil {
		t.Fatalf("failed to query credential after delete: %v", err)
	}
	defer statusResp.Body.Close()
	if statusResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(statusResp.Body)
		t.Fatalf("expected 200 on status after delete, got %d: %s", statusResp.StatusCode, string(body))
	}
	var status credentialStatusResponse
	if err := json.NewDecoder(statusResp.Body).Decode(&status); err != nil {
		t.Fatalf("failed to decode status response: %v", err)
	}
	if status.Exists {
		t.Fatalf("expected credential to be deleted")
	}
}

// waitForLocalCredmonReady waits for LOCAL_CREDMON daemon to signal readiness to condor_master
func waitForLocalCredmonReady(tempDir string, timeout time.Duration) error {
	masterLog := filepath.Join(tempDir, "log", "MasterLog")
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for LOCAL_CREDMON ready signal")
		case <-ticker.C:
			data, err := os.ReadFile(masterLog)
			if err != nil {
				continue
			}
			logContent := string(data)
			// Look for ready signal acknowledgment from master
			if strings.Contains(logContent, "LOCAL_CREDMON") &&
				(strings.Contains(logContent, "ready") || strings.Contains(logContent, "Ready")) {
				return nil
			}
		}
	}
}

// getCreddAddress waits for credd to write its address file and returns the address
func getCreddAddress(tempDir string, timeout time.Duration) (string, error) {
	addressFile := filepath.Join(tempDir, "log", ".credd_address")
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("timeout waiting for credd address file")
		case <-ticker.C:
			data, err := os.ReadFile(addressFile)
			if err != nil {
				continue
			}
			// Only take the first line (address), ignore version info
			lines := strings.Split(string(data), "\n")
			address := strings.TrimSpace(lines[0])
			if address != "" && !strings.Contains(address, "(null)") {
				return address, nil
			}
		}
	}
}

// startTestHTTPServerWithCredd starts HTTP server with custom credd client
func startTestHTTPServerWithCredd(ctx context.Context, tempDir, scheddAddr, passwordsDir string, creddClient htcondor.CreddClient, t *testing.T) (*Server, string) {
	t.Helper()

	signingKeyPath := filepath.Join(passwordsDir, "POOL")
	trustDomain := "test.htcondor.org"

	// Use dynamic port for HTTP server
	serverAddr := "127.0.0.1:0"

	// Create HTTP server with collector for collector tests
	collector := htcondor.NewCollector(scheddAddr) // Use schedd address (shared port)

	// Create a directory for the DB to avoid any interference from Condor
	dbDir := filepath.Join(tempDir, "db")
	if err := os.MkdirAll(dbDir, 0700); err != nil {
		t.Fatalf("Failed to create db directory: %v", err)
	}
	// Set OAuth2DBPath to tempDir to avoid permission issues
	oauth2DBPath := filepath.Join(dbDir, "sessions.db")

	server, err := NewServer(Config{
		ListenAddr:     serverAddr,
		ScheddName:     "local",
		ScheddAddr:     scheddAddr,
		UserHeader:     "X-Test-User",
		SigningKeyPath: signingKeyPath,
		TrustDomain:    trustDomain,
		UIDDomain:      "test.htcondor.org",
		Collector:      collector,
		OAuth2DBPath:   oauth2DBPath,
		Credd:          creddClient,
	})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Start server in background
	go func() {
		_ = server.Start()
	}()

	// Wait for server to start
	time.Sleep(500 * time.Millisecond)

	// Get actual server address using GetAddr() method
	actualAddr := server.GetAddr()
	if actualAddr == "" {
		t.Fatalf("Failed to get server address")
	}

	baseURL := fmt.Sprintf("http://%s", actualAddr)
	t.Logf("HTTP server listening on: %s", baseURL)

	// Wait for server to be fully ready
	if err := waitForServer(baseURL, 10*time.Second); err != nil {
		t.Fatalf("Server not ready: %v", err)
	}

	return server, baseURL
}

// deriveAPIPrefix fetches /openapi.json and returns the first server URL (defaults to /api/v1).
func deriveAPIPrefix(t *testing.T, baseURL string) string {
	t.Helper()

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(baseURL + "/openapi.json")
	if err != nil {
		t.Logf("failed to fetch openapi.json, defaulting prefix to /api/v1: %v", err)
		return "/api/v1"
	}
	defer resp.Body.Close()

	var schema struct {
		Servers []struct {
			URL string `json:"url"`
		} `json:"servers"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&schema); err != nil {
		t.Logf("failed to decode openapi.json, defaulting prefix to /api/v1: %v", err)
		return "/api/v1"
	}

	for _, srv := range schema.Servers {
		if srv.URL != "" {
			if !strings.HasPrefix(srv.URL, "/") {
				return "/" + srv.URL
			}
			return srv.URL
		}
	}

	return "/api/v1"
}
