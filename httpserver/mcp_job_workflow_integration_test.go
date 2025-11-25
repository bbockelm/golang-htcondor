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

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/mcpserver"
	"github.com/ory/fosite"
	"golang.org/x/crypto/bcrypt"
)

// TestMCPJobWorkflowIntegration tests the complete MCP job workflow:
// 1. Submit a job
// 2. Upload input files
// 3. Wait for job to complete
// 4. Retrieve output files
func TestMCPJobWorkflowIntegration(t *testing.T) {
	// Skip if condor_master is not available
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH, skipping integration test")
	}

	// Create temporary directory for mini condor
	tempDir, err := os.MkdirTemp("", "htcondor-mcp-workflow-*")
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

	// Set CONDOR_CONFIG environment variable and reload configuration
	t.Setenv("CONDOR_CONFIG", configFile)
	htcondor.ReloadDefaultConfig()

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

	// Use dynamic port for HTTP server (bind to :0)
	serverAddr := "127.0.0.1:0"

	// OAuth2 database path
	oauth2DBPath := filepath.Join(tempDir, "oauth2.db")

	// Create HTTP server with MCP enabled
	// Note: We'll update HTTPBaseURL after getting the actual port
	server, err := NewServer(Config{
		ListenAddr:     serverAddr,
		ScheddName:     "local",
		ScheddAddr:     scheddAddr,
		UserHeader:     "X-Test-User",
		SigningKeyPath: poolKeyPath,
		TrustDomain:    trustDomain,
		UIDDomain:      trustDomain,
		EnableMCP:      true,
		OAuth2DBPath:   oauth2DBPath,
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

	actualAddr := server.GetAddr()
	if actualAddr == "" {
		t.Fatalf("Failed to get server address")
	}
	baseURL := fmt.Sprintf("http://%s", actualAddr)
	t.Logf("HTTP server listening on: %s", baseURL)

	// Wait for server to be fully ready
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

	// Step 1: Create an OAuth2 client and get access token
	t.Log("Step 1: Setting up OAuth2 authentication...")
	clientID, clientSecret := createWorkflowOAuth2Client(t, server, baseURL, testUser)
	accessToken := getWorkflowOAuth2Token(t, client, baseURL, clientID, clientSecret, testUser)
	t.Logf("Access token obtained: %s...", accessToken[:min(20, len(accessToken))])

	// Step 2: Submit a job that uses a custom script
	t.Log("Step 2: Submitting job...")
	clusterID, jobID := submitWorkflowJob(t, client, baseURL, accessToken)
	t.Logf("Job submitted: cluster %d, job ID %s", clusterID, jobID)

	// Step 3: Upload input files
	// When files are uploaded via upload_job_input, the schedd automatically
	// releases the job from HELD status (HoldReasonCode=16) to IDLE status.
	t.Log("Step 3: Uploading input files...")
	uploadInputFiles(t, client, baseURL, accessToken, jobID)
	t.Log("Input files uploaded successfully - job should now be released to IDLE")

	// Step 4: Wait for job to complete
	t.Log("Step 4: Waiting for job to complete...")
	waitForWorkflowJobCompletion(t, client, baseURL, accessToken, clusterID, 120*time.Second)
	t.Log("Job completed!")

	// Step 5: Retrieve output files
	t.Log("Step 5: Retrieving output files...")
	outputFiles := getJobOutputFiles(t, client, baseURL, accessToken, jobID)
	t.Logf("Retrieved %d output file(s)", len(outputFiles))

	// Verify output content
	verifyOutputFiles(t, outputFiles)
	t.Log("Output files verified successfully!")

	t.Log("All MCP job workflow integration tests passed!")
}

// createWorkflowOAuth2Client creates a new OAuth2 client for the workflow test
func createWorkflowOAuth2Client(t *testing.T, server *Server, baseURL, username string) (string, string) {
	storage := server.GetOAuth2Provider().GetStorage()

	clientID := "workflow-test-client"
	clientSecret := "workflow-test-secret"
	redirectURI := baseURL + "/callback"

	hashedSecret, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash client secret: %v", err)
	}

	client := &fosite.DefaultClient{
		ID:            clientID,
		Secret:        hashedSecret,
		RedirectURIs:  []string{redirectURI},
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid", "profile", "email", "mcp:read", "mcp:write"},
		Public:        false,
	}

	if err := storage.CreateClient(context.Background(), client); err != nil {
		t.Fatalf("Failed to create OAuth2 client: %v", err)
	}

	return clientID, clientSecret
}

// getWorkflowOAuth2Token obtains an OAuth2 access token
func getWorkflowOAuth2Token(t *testing.T, httpClient *http.Client, baseURL, clientID, clientSecret, username string) string {
	// Use the same flow as the main MCP integration test
	redirectURI := url.QueryEscape(baseURL + "/callback")
	authURL := fmt.Sprintf("%s/mcp/oauth2/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=openid+profile+email+mcp:read+mcp:write&state=teststate&username=%s",
		baseURL, clientID, redirectURI, username)

	req, err := http.NewRequest("GET", authURL, nil)
	if err != nil {
		t.Fatalf("Failed to create auth request: %v", err)
	}
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

	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Authorization request failed: status %d, body: %s", resp.StatusCode, string(body))
	}

	location := resp.Header.Get("Location")
	if location == "" {
		t.Fatal("No redirect location in authorization response")
	}

	// Handle consent page if needed
	if strings.Contains(location, "/mcp/oauth2/consent") {
		u, _ := url.Parse(location)
		state := u.Query().Get("state")

		consentForm := url.Values{}
		consentForm.Set("action", "approve")
		consentForm.Set("state", state)
		consentForm.Set("scope", "openid profile email mcp:read mcp:write")

		consentReq, _ := http.NewRequest("POST", baseURL+"/mcp/oauth2/consent", strings.NewReader(consentForm.Encode()))
		consentReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		consentReq.Header.Set("X-Test-User", username)

		consentResp, err := httpClient.Do(consentReq)
		if err != nil {
			t.Fatalf("Failed to send consent request: %v", err)
		}
		defer consentResp.Body.Close()

		location = consentResp.Header.Get("Location")
	}

	// Extract authorization code
	redirectURL, _ := url.Parse(location)
	code := redirectURL.Query().Get("code")
	if code == "" {
		t.Fatalf("No authorization code in redirect: %s", location)
	}

	// Exchange code for token
	tokenForm := url.Values{}
	tokenForm.Set("grant_type", "authorization_code")
	tokenForm.Set("code", code)
	tokenForm.Set("redirect_uri", baseURL+"/callback")
	tokenForm.Set("client_id", clientID)
	tokenForm.Set("client_secret", clientSecret)

	tokenReq, _ := http.NewRequest("POST", baseURL+"/mcp/oauth2/token", strings.NewReader(tokenForm.Encode()))
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

	var tokenData struct {
		AccessToken string `json:"access_token"`
	}
	json.NewDecoder(tokenResp.Body).Decode(&tokenData)

	if tokenData.AccessToken == "" {
		t.Fatal("Empty access token received")
	}

	return tokenData.AccessToken
}

// submitWorkflowJob submits a job that uses a custom script
func submitWorkflowJob(t *testing.T, client *http.Client, baseURL, accessToken string) (int, string) {
	// Submit a job that will run our custom script
	// The script will read from input.txt and write to output.txt
	// Note: submit_job uses SubmitRemote which automatically holds the job
	// with HoldReasonCode=16 (SpoolingInput) until input files are uploaded.
	// After uploading files via upload_job_input, the job is automatically released.
	submitFile := `executable = run_script.sh
transfer_input_files = input.txt
transfer_output_files = output.txt
output = job.out
error = job.err
log = job.log
should_transfer_files = YES
when_to_transfer_output = ON_EXIT
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
		ID:      1,
		Method:  "tools/call",
		Params:  json.RawMessage(paramsBytes),
	}

	mcpResp := sendWorkflowMCPRequest(t, client, baseURL, accessToken, mcpReq)

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

	jobIDs, ok := metadata["job_ids"].([]interface{})
	if !ok || len(jobIDs) == 0 {
		t.Fatal("submit_job result missing job_ids")
	}

	jobID := jobIDs[0].(string)

	return int(clusterID), jobID
}

// uploadInputFiles uploads the input files for the job
func uploadInputFiles(t *testing.T, client *http.Client, baseURL, accessToken, jobID string) {
	// Create the script that will be executed
	scriptContent := `#!/bin/bash
# Read input and transform it
echo "Processing input file..."
cat input.txt > output.txt
echo "" >> output.txt
echo "Processed by MCP integration test at $(date)" >> output.txt
echo "Script completed successfully"
`

	// Create the input data file
	inputContent := "Hello from MCP integration test!\nThis is test data line 2.\nThis is test data line 3."

	// Upload both files using the upload_job_input tool
	params := map[string]interface{}{
		"name": "upload_job_input",
		"arguments": map[string]interface{}{
			"job_id": jobID,
			"files": []map[string]interface{}{
				{
					"filename":      "run_script.sh",
					"data":          scriptContent,
					"is_executable": true,
				},
				{
					"filename": "input.txt",
					"data":     inputContent,
				},
			},
		},
	}

	paramsBytes, _ := json.Marshal(params)

	mcpReq := mcpserver.MCPMessage{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "tools/call",
		Params:  json.RawMessage(paramsBytes),
	}

	mcpResp := sendWorkflowMCPRequest(t, client, baseURL, accessToken, mcpReq)

	if mcpResp.Error != nil {
		t.Fatalf("MCP upload_job_input failed: %v", mcpResp.Error.Message)
	}

	result, ok := mcpResp.Result.(map[string]interface{})
	if !ok {
		t.Fatal("upload_job_input result is not a map")
	}

	// Check that files were uploaded
	metadata, ok := result["metadata"].(map[string]interface{})
	if !ok {
		t.Fatal("upload_job_input result missing metadata")
	}

	fileCount, ok := metadata["file_count"].(float64)
	if !ok || int(fileCount) != 2 {
		t.Fatalf("Expected 2 files uploaded, got %v", metadata["file_count"])
	}

	t.Logf("Uploaded %d files to job %s", int(fileCount), jobID)
}

// waitForWorkflowJobCompletion polls the job status until it completes or times out
func waitForWorkflowJobCompletion(t *testing.T, client *http.Client, baseURL, accessToken string, clusterID int, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	pollInterval := 5 * time.Second

	for time.Now().Before(deadline) {
		params := map[string]interface{}{
			"name": "query_jobs",
			"arguments": map[string]interface{}{
				"constraint": fmt.Sprintf("ClusterId == %d", clusterID),
				"projection": []string{"ClusterId", "ProcId", "JobStatus", "HoldReason"},
			},
		}

		paramsBytes, _ := json.Marshal(params)

		mcpReq := mcpserver.MCPMessage{
			JSONRPC: "2.0",
			ID:      3,
			Method:  "tools/call",
			Params:  json.RawMessage(paramsBytes),
		}

		mcpResp := sendWorkflowMCPRequest(t, client, baseURL, accessToken, mcpReq)

		if mcpResp.Error != nil {
			t.Logf("Warning: query_jobs failed: %v", mcpResp.Error.Message)
			time.Sleep(pollInterval)
			continue
		}

		result, ok := mcpResp.Result.(map[string]interface{})
		if !ok {
			time.Sleep(pollInterval)
			continue
		}

		metadata, ok := result["metadata"].(map[string]interface{})
		if !ok {
			time.Sleep(pollInterval)
			continue
		}

		count, ok := metadata["count"].(float64)
		if !ok || int(count) == 0 {
			// Job might have completed and left the queue
			t.Log("Job no longer in queue (likely completed)")
			return
		}

		// Parse the content to get job status
		content, ok := result["content"].([]interface{})
		if !ok || len(content) == 0 {
			time.Sleep(pollInterval)
			continue
		}

		contentItem, ok := content[0].(map[string]interface{})
		if !ok {
			time.Sleep(pollInterval)
			continue
		}

		text, ok := contentItem["text"].(string)
		if !ok {
			time.Sleep(pollInterval)
			continue
		}

		// Check job status from the response
		// JobStatus: 1=Idle, 2=Running, 3=Removed, 4=Completed, 5=Held
		if strings.Contains(text, `"JobStatus":4`) || strings.Contains(text, `"JobStatus": 4`) {
			t.Log("Job completed (JobStatus=4)")
			return
		}
		if strings.Contains(text, `"JobStatus":3`) || strings.Contains(text, `"JobStatus": 3`) {
			t.Fatal("Job was removed (JobStatus=3)")
		}
		if strings.Contains(text, `"JobStatus":5`) || strings.Contains(text, `"JobStatus": 5`) {
			// Job is held - this might be expected before input upload
			if strings.Contains(text, "HoldReason") {
				t.Logf("Job is held, waiting... (text sample: %s)", text[:min(200, len(text))])
			}
		}
		if strings.Contains(text, `"JobStatus":2`) || strings.Contains(text, `"JobStatus": 2`) {
			t.Log("Job is running...")
		}
		if strings.Contains(text, `"JobStatus":1`) || strings.Contains(text, `"JobStatus": 1`) {
			t.Log("Job is idle, waiting for resources...")
		}

		time.Sleep(pollInterval)
	}

	t.Fatalf("Job did not complete within %v", timeout)
}

// OutputFileData represents a file from the job output
type OutputFileData struct {
	Filename    string `json:"filename"`
	Data        string `json:"data"`
	IsTruncated bool   `json:"is_truncated"`
	URL         string `json:"url"`
	IsBase64    bool   `json:"is_base64"`
	Size        int64  `json:"size"`
}

// getJobOutputFiles retrieves output files from the job using the MCP tool
func getJobOutputFiles(t *testing.T, client *http.Client, baseURL, accessToken, jobID string) []OutputFileData {
	params := map[string]interface{}{
		"name": "get_job_output",
		"arguments": map[string]interface{}{
			"job_id": jobID,
		},
	}

	paramsBytes, _ := json.Marshal(params)

	mcpReq := mcpserver.MCPMessage{
		JSONRPC: "2.0",
		ID:      4,
		Method:  "tools/call",
		Params:  json.RawMessage(paramsBytes),
	}

	mcpResp := sendWorkflowMCPRequest(t, client, baseURL, accessToken, mcpReq)

	if mcpResp.Error != nil {
		t.Fatalf("MCP get_job_output failed: %v", mcpResp.Error.Message)
	}

	result, ok := mcpResp.Result.(map[string]interface{})
	if !ok {
		t.Fatal("get_job_output result is not a map")
	}

	metadata, ok := result["metadata"].(map[string]interface{})
	if !ok {
		t.Fatal("get_job_output result missing metadata")
	}

	filesData, ok := metadata["files"].([]interface{})
	if !ok {
		t.Fatalf("get_job_output result missing files in metadata: %+v", metadata)
	}

	var files []OutputFileData
	for _, f := range filesData {
		fileMap, ok := f.(map[string]interface{})
		if !ok {
			continue
		}

		file := OutputFileData{
			Filename: getString(fileMap, "filename"),
			Data:     getString(fileMap, "data"),
			URL:      getString(fileMap, "url"),
		}

		if val, ok := fileMap["is_truncated"].(bool); ok {
			file.IsTruncated = val
		}
		if val, ok := fileMap["is_base64"].(bool); ok {
			file.IsBase64 = val
		}
		if val, ok := fileMap["size"].(float64); ok {
			file.Size = int64(val)
		}

		files = append(files, file)
	}

	return files
}

// verifyOutputFiles verifies the output files contain expected content
func verifyOutputFiles(t *testing.T, files []OutputFileData) {
	if len(files) == 0 {
		t.Fatal("No output files received")
	}

	// Look for our expected output file
	foundOutput := false
	foundJobOut := false

	for _, f := range files {
		t.Logf("Output file: %s (size=%d, base64=%v, truncated=%v)",
			f.Filename, f.Size, f.IsBase64, f.IsTruncated)

		if f.Filename == "output.txt" {
			foundOutput = true
			if !strings.Contains(f.Data, "Hello from MCP integration test!") {
				t.Errorf("output.txt missing expected content. Got: %s", f.Data)
			}
			if !strings.Contains(f.Data, "Processed by MCP integration test") {
				t.Errorf("output.txt missing processing marker. Got: %s", f.Data)
			}
			t.Logf("output.txt content verified: %s", f.Data[:min(100, len(f.Data))])
		}

		if f.Filename == "job.out" {
			foundJobOut = true
			if !strings.Contains(f.Data, "Script completed successfully") {
				t.Logf("Warning: job.out may not contain expected output. Got: %s", f.Data)
			}
			t.Logf("job.out content: %s", f.Data[:min(100, len(f.Data))])
		}

		// Check that URL is present if HTTPBaseURL was configured
		if f.URL != "" {
			t.Logf("  Download URL: %s", f.URL)
		}
	}

	if !foundOutput {
		t.Error("output.txt not found in output files")
	}
	if !foundJobOut {
		t.Log("Warning: job.out not found (job may still be processing)")
	}
}

// sendWorkflowMCPRequest sends an MCP request and returns the response
func sendWorkflowMCPRequest(t *testing.T, client *http.Client, baseURL, accessToken string, mcpReq mcpserver.MCPMessage) *mcpserver.MCPMessage {
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

// getString safely extracts a string from a map
func getString(m map[string]interface{}, key string) string {
	if val, ok := m[key].(string); ok {
		return val
	}
	return ""
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
