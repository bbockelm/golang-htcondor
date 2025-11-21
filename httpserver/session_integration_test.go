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
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// TestHTTPSessionIntegration tests that session cookies work with HTCondor daemon
func TestHTTPSessionIntegration(t *testing.T) {
	// Skip if condor_master is not available
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH, skipping integration test")
	}

	// Create temporary directory for mini condor
	tempDir, err := os.MkdirTemp("", "htcondor-session-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create secure socket directory in /tmp to avoid path length issues
	socketDir, err := os.MkdirTemp("/tmp", "htc_sock_*")
	if err != nil {
		t.Fatalf("Failed to create socket directory: %v", err)
	}
	defer os.RemoveAll(socketDir)

	t.Logf("Using temporary directory: %s", tempDir)
	t.Logf("Using socket directory: %s", socketDir)

	// Generate signing key for demo authentication in passwords.d directory
	passwordsDir := filepath.Join(tempDir, "passwords.d")
	if err := os.MkdirAll(passwordsDir, 0700); err != nil {
		t.Fatalf("Failed to create passwords.d directory: %v", err)
	}
	signingKeyPath := filepath.Join(passwordsDir, "POOL")
	// Generate a simple signing key for testing
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	if err := os.WriteFile(signingKeyPath, key, 0600); err != nil {
		t.Fatalf("Failed to write signing key: %v", err)
	}

	trustDomain := "test.htcondor.org"

	// Write mini condor configuration
	configFile := filepath.Join(tempDir, "condor_config")
	if err := writeMiniCondorConfig(configFile, tempDir, socketDir, passwordsDir, trustDomain, t); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

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

	// Use dynamic port for HTTP server
	serverAddr := "127.0.0.1:0"

	// Create a directory for the DB to avoid any interference from Condor
	dbDir := filepath.Join(tempDir, "db")
	if err := os.Mkdir(dbDir, 0700); err != nil {
		t.Fatalf("Failed to create db directory: %v", err)
	}
	// Set OAuth2DBPath to tempDir to avoid permission issues
	oauth2DBPath := filepath.Join(dbDir, "sessions.db")

	// Create HTTP server with session support and signing key for token generation
	collector := htcondor.NewCollector(scheddAddr) // Use schedd address (shared port)
	serverCfg := Config{
		ListenAddr:     serverAddr,
		ScheddAddr:     scheddAddr,
		ScheddName:     "local",
		Collector:      collector,
		EnableMetrics:  false,
		SessionTTL:     1 * time.Hour,
		SigningKeyPath: signingKeyPath,
		TrustDomain:    trustDomain,
		UIDDomain:      trustDomain,
		OAuth2DBPath:   oauth2DBPath,
	}

	server, err := NewServer(serverCfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Start server in background
	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- server.Start()
	}()

	// Wait for server to be ready
	time.Sleep(500 * time.Millisecond)

	// Get actual server address
	actualAddr := server.GetAddr()
	if actualAddr == "" {
		t.Fatal("Failed to get server address")
	}
	t.Logf("Server listening on: %s", actualAddr)

	baseURL := fmt.Sprintf("http://%s", actualAddr)

	// Test 1: Create a session for a test user
	username := "testuser@" + trustDomain
	sessionID, sessionData, err := server.sessionStore.Create(username)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}
	t.Logf("Created session for user: %s (session_id: %s...)", username, sessionID[:8])

	// Test 2: Submit a job using session cookie (no bearer token)
	submitReq := map[string]string{
		"submit_file": "executable = /bin/echo\narguments = Hello from session\nqueue",
	}
	submitBody, _ := json.Marshal(submitReq)

	req, err := http.NewRequest("POST", baseURL+"/api/v1/jobs", bytes.NewReader(submitBody))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{
		Name:  sessionCookieName,
		Value: sessionID,
	})

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to submit job: %v", err)
	}
	defer resp.Body.Close()

	// Job submission returns 201 Created on success
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Job submission failed with status %d: %s", resp.StatusCode, string(body))
	}

	var submitResp JobSubmitResponse
	if err := json.NewDecoder(resp.Body).Decode(&submitResp); err != nil {
		t.Fatalf("Failed to decode submit response: %v", err)
	}

	t.Logf("Job submitted with cluster ID: %d, Job IDs: %v", submitResp.ClusterID, submitResp.JobIDs)

	if len(submitResp.JobIDs) == 0 {
		t.Fatal("Expected at least one job ID")
	}

	// Test 3: Query jobs using session cookie
	req, err = http.NewRequest("GET", baseURL+"/api/v1/jobs?constraint=ClusterId=="+fmt.Sprint(submitResp.ClusterID), nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.AddCookie(&http.Cookie{
		Name:  sessionCookieName,
		Value: sessionID,
	})

	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("Failed to query jobs: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Job query failed with status %d: %s", resp.StatusCode, string(body))
	}

	var listResp JobListResponse
	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		t.Fatalf("Failed to decode list response: %v", err)
	}

	t.Logf("Found %d jobs", len(listResp.Jobs))

	if len(listResp.Jobs) == 0 {
		t.Fatal("Expected at least one job in query results")
	}

	// Verify that the job owner matches the session username
	if len(listResp.Jobs) > 0 {
		ownerExpr, ok := listResp.Jobs[0].Lookup("Owner")
		if !ok {
			t.Fatal("Job missing Owner attribute")
		}
		owner := ownerExpr.String()
		// ClassAd strings are quoted
		owner = owner[1 : len(owner)-1] // Remove quotes

		t.Logf("Job owner: %s", owner)

		// The owner should match the session username
		// Note: HTCondor may strip the @domain part in some cases
		expectedOwner := "testuser" // Without domain
		if owner != expectedOwner && owner != username {
			t.Errorf("Expected job owner to be '%s' or '%s', got '%s'", expectedOwner, username, owner)
		}
	}

	// Test 4: Verify session cookie is included in subsequent responses
	// (just check that we can still use it)
	// Add small delay to avoid rate limiting
	time.Sleep(200 * time.Millisecond)

	req, err = http.NewRequest("GET", baseURL+"/api/v1/jobs", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.AddCookie(&http.Cookie{
		Name:  sessionCookieName,
		Value: sessionID,
	})

	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("Failed to query jobs: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Job query failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Test 5: Verify invalid session cookie is rejected
	req, err = http.NewRequest("GET", baseURL+"/api/v1/jobs", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.AddCookie(&http.Cookie{
		Name:  sessionCookieName,
		Value: "invalid-session-id",
	})

	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("Failed to query jobs: %v", err)
	}
	defer resp.Body.Close()

	// Should get unauthorized without valid auth
	if resp.StatusCode == http.StatusOK {
		t.Error("Expected unauthorized status with invalid session cookie")
	}

	// Test 6: Verify session expiration
	t.Log("Verifying session data is correct")
	if sessionData.Username != username {
		t.Errorf("Expected session username '%s', got '%s'", username, sessionData.Username)
	}
	if sessionData.ExpiresAt.Before(time.Now()) {
		t.Error("Session should not be expired immediately after creation")
	}

	// Shutdown server
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		t.Logf("Server shutdown error: %v", err)
	}

	// Check if server exited cleanly
	select {
	case err := <-serverErrCh:
		if err != nil && err != http.ErrServerClosed {
			t.Logf("Server error: %v", err)
		}
	case <-time.After(1 * time.Second):
		// Server didn't exit, that's okay
	}
}
