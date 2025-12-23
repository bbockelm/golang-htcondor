//go:build integration

//nolint:errcheck,noctx,gosec,errorlint,govet // Integration test file with acceptable test patterns
package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// TestCreddHTTPIntegration exercises the credential endpoints against a running HTTP server
// with a live mini-HTCondor instance. Uses the default (in-memory) credd backend.
func TestCreddHTTPIntegration(t *testing.T) {
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH, skipping integration test")
	}

	tempDir, err := os.MkdirTemp("", "htcondor-credd-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	socketDir, err := os.MkdirTemp("/tmp", "htc_sock_*")
	if err != nil {
		t.Fatalf("Failed to create socket directory: %v", err)
	}
	defer os.RemoveAll(socketDir)

	passwordsDir := filepath.Join(tempDir, "passwords.d")
	if err := os.MkdirAll(passwordsDir, 0700); err != nil {
		t.Fatalf("Failed to create passwords.d directory: %v", err)
	}
	signingKeyPath := filepath.Join(passwordsDir, "POOL")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	if err := os.WriteFile(signingKeyPath, key, 0600); err != nil {
		t.Fatalf("Failed to write signing key: %v", err)
	}

	trustDomain := "test.htcondor.org"
	configFile := filepath.Join(tempDir, "condor_config")
	if err := writeMiniCondorConfig(configFile, tempDir, socketDir, passwordsDir, trustDomain, t); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

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

	server, baseURL := startTestHTTPServer(ctx, tempDir, scheddAddr, passwordsDir, t)
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	client := &http.Client{Timeout: 30 * time.Second}
	user := "credd-integration"

	// Add service credential
	addBody := map[string]any{
		"cred_type":  "OAuth",
		"credential": "oauth-token",
		"refresh":    false,
	}
	addBytes, _ := json.Marshal(addBody)
	addReq, _ := http.NewRequest(http.MethodPost, baseURL+"/api/v1/creds/service/github", bytes.NewReader(addBytes))
	addReq.Header.Set("Content-Type", "application/json")
	addReq.Header.Set("X-Test-User", user)
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
	getReq, _ := http.NewRequest(http.MethodGet, baseURL+"/api/v1/creds/service/github/credential", nil)
	getReq.Header.Set("X-Test-User", user)
	getResp, err := client.Do(getReq)
	if err != nil {
		t.Fatalf("failed to fetch credential: %v", err)
	}
	defer getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(getResp.Body)
		t.Fatalf("expected 200 on credential fetch, got %d: %s", getResp.StatusCode, string(body))
	}
	var credPayload struct {
		Credential string `json:"credential"`
	}
	if err := json.NewDecoder(getResp.Body).Decode(&credPayload); err != nil {
		t.Fatalf("failed to decode credential response: %v", err)
	}
	if credPayload.Credential != "oauth-token" {
		t.Fatalf("unexpected credential payload: %s", credPayload.Credential)
	}

	// List credentials
	listReq, _ := http.NewRequest(http.MethodGet, baseURL+"/api/v1/creds/service", nil)
	listReq.Header.Set("X-Test-User", user)
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
		t.Fatalf("unexpected list payload: %+v", listPayload)
	}

	// Delete credential
	deleteReq, _ := http.NewRequest(http.MethodDelete, baseURL+"/api/v1/creds/service/github", nil)
	deleteReq.Header.Set("X-Test-User", user)
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
	statusReq, _ := http.NewRequest(http.MethodGet, baseURL+"/api/v1/creds/service/github", nil)
	statusReq.Header.Set("X-Test-User", user)
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
