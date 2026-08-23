package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
)

// TestMCPServerInitialize tests the MCP initialize message
func TestMCPServerInitialize(t *testing.T) {
	// Create a mock stdin/stdout
	stdin := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{}}}` + "\n")
	stdout := &bytes.Buffer{}

	// Create logger
	logger, err := logging.New(&logging.Config{
		OutputPath: "stderr",
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Create server with mock I/O
	server := &Server{
		schedd: htcondor.NewSchedd("test_schedd", "localhost:9618"),
		logger: logger,
		stdin:  stdin,
		stdout: stdout,
	}

	// Run server in background with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Run(ctx)
	}()

	// Wait for completion or timeout
	select {
	case err := <-errChan:
		if err != nil && !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Server error: %v", err)
		}
	case <-ctx.Done():
		// Expected timeout
	}

	// Check the response
	response := stdout.String()
	if !strings.Contains(response, "htcondor-mcp") {
		t.Errorf("Expected response to contain 'htcondor-mcp', got: %s", response)
	}
	if !strings.Contains(response, "protocolVersion") {
		t.Errorf("Expected response to contain 'protocolVersion', got: %s", response)
	}
}

// TestMCPServerInitializeWithInstructions verifies the instructions field appears in the initialize response
func TestMCPServerInitializeWithInstructions(t *testing.T) {
	stdin := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{}}}` + "\n")
	stdout := &bytes.Buffer{}

	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	server := &Server{
		schedd:       htcondor.NewSchedd("test_schedd", "localhost:9618"),
		logger:       logger,
		instructions: "Always submit jobs to the accounting group for physics.",
		stdin:        stdin,
		stdout:       stdout,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Run(ctx)
	}()

	select {
	case err := <-errChan:
		if err != nil && !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Server error: %v", err)
		}
	case <-ctx.Done():
	}

	response := stdout.String()

	// Parse the JSON-RPC response and check the instructions field
	var resp struct {
		Result struct {
			Instructions string `json:"instructions"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(response), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v\nResponse: %s", err, response)
	}
	if resp.Result.Instructions != "Always submit jobs to the accounting group for physics." {
		t.Errorf("Expected instructions to be set, got: %q", resp.Result.Instructions)
	}
}

// TestMCPServerInitializeWithoutInstructions verifies instructions is omitted when empty
func TestMCPServerInitializeWithoutInstructions(t *testing.T) {
	stdin := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{}}}` + "\n")
	stdout := &bytes.Buffer{}

	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	server := &Server{
		schedd: htcondor.NewSchedd("test_schedd", "localhost:9618"),
		logger: logger,
		stdin:  stdin,
		stdout: stdout,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Run(ctx)
	}()

	select {
	case err := <-errChan:
		if err != nil && !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Server error: %v", err)
		}
	case <-ctx.Done():
	}

	response := stdout.String()
	if strings.Contains(response, "instructions") {
		t.Errorf("Expected response to NOT contain 'instructions' when empty, got: %s", response)
	}
}

// TestMCPServerListTools tests listing available tools
func TestMCPServerListTools(t *testing.T) {
	// Create a mock stdin/stdout
	stdin := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}` + "\n")
	stdout := &bytes.Buffer{}

	// Create logger
	logger, err := logging.New(&logging.Config{
		OutputPath: "stderr",
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Create server with mock I/O
	server := &Server{
		schedd: htcondor.NewSchedd("test_schedd", "localhost:9618"),
		logger: logger,
		stdin:  stdin,
		stdout: stdout,
	}

	// Run server in background with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Run(ctx)
	}()

	// Wait for completion or timeout
	select {
	case err := <-errChan:
		if err != nil && !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Server error: %v", err)
		}
	case <-ctx.Done():
		// Expected timeout
	}

	// Parse and check the response
	response := stdout.String()
	var msg MCPMessage
	if err := json.Unmarshal([]byte(response), &msg); err != nil {
		t.Fatalf("Failed to parse response: %v\nResponse: %s", err, response)
	}

	if msg.Error != nil {
		t.Errorf("Expected no error, got: %+v", msg.Error)
	}

	// Check that tools are listed
	resultJSON, err := json.Marshal(msg.Result)
	if err != nil {
		t.Fatalf("Failed to marshal result: %v", err)
	}
	resultStr := string(resultJSON)

	expectedTools := []string{"submit_job", "query_jobs", "get_job", "remove_job", "edit_job", "hold_job", "release_job"}
	for _, tool := range expectedTools {
		if !strings.Contains(resultStr, tool) {
			t.Errorf("Expected tools list to contain '%s', got: %s", tool, resultStr)
		}
	}
}

// TestParseJobID tests the parseJobID helper function
func TestParseJobID(t *testing.T) {
	tests := []struct {
		name        string
		jobID       string
		wantCluster int
		wantProc    int
		wantErr     bool
	}{
		{
			name:        "Valid job ID",
			jobID:       "123.456",
			wantCluster: 123,
			wantProc:    456,
			wantErr:     false,
		},
		{
			name:        "Valid job ID with zeros",
			jobID:       "0.0",
			wantCluster: 0,
			wantProc:    0,
			wantErr:     false,
		},
		{
			name:    "Invalid format - no dot",
			jobID:   "123",
			wantErr: true,
		},
		{
			name:    "Invalid format - too many dots",
			jobID:   "123.456.789",
			wantErr: true,
		},
		{
			name:    "Invalid cluster ID",
			jobID:   "abc.456",
			wantErr: true,
		},
		{
			name:    "Invalid proc ID",
			jobID:   "123.xyz",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cluster, proc, err := parseJobID(tt.jobID)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseJobID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if cluster != tt.wantCluster {
					t.Errorf("parseJobID() cluster = %v, want %v", cluster, tt.wantCluster)
				}
				if proc != tt.wantProc {
					t.Errorf("parseJobID() proc = %v, want %v", proc, tt.wantProc)
				}
			}
		})
	}
}

// TestNoToolAdvertisesATokenArgument is the contract from issue #192: a
// credential must never be a tool argument. Advertising one invites an
// LLM client to ask its user for a token, and honoring one would let a
// call switch identity away from the caller the transport
// authenticated.
func TestNoToolAdvertisesATokenArgument(t *testing.T) {
	s := &Server{}
	result := s.handleListTools(context.Background(), nil)

	payload, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal tools/list: %v", err)
	}
	var listing struct {
		Tools []struct {
			Name        string `json:"name"`
			InputSchema struct {
				Properties map[string]interface{} `json:"properties"`
				Required   []string               `json:"required"`
			} `json:"inputSchema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(payload, &listing); err != nil {
		t.Fatalf("tools/list is not the documented shape: %v", err)
	}
	if len(listing.Tools) == 0 {
		t.Fatal("no tools advertised; the assertion below would be vacuous")
	}

	for _, tool := range listing.Tools {
		if _, ok := tool.InputSchema.Properties["token"]; ok {
			t.Errorf("%s advertises a token argument", tool.Name)
		}
		for _, req := range tool.InputSchema.Required {
			if req == "token" {
				t.Errorf("%s requires a token argument", tool.Name)
			}
		}
	}

	// Nested schemas too: a token property one level down is just as
	// visible to a client as a top-level one.
	if bytes.Contains(payload, []byte(`"token"`)) {
		t.Errorf("a token property survives somewhere in the tool schemas: %s", payload)
	}
}

// TestTokenArgumentIsIgnored checks the other half: a caller that sends
// one anyway does not get an identity from it. The server has no schedd,
// so a tool that reached the schedd would fail differently — this
// asserts on the owner-scoped refusal, which is what an unauthenticated
// caller gets.
func TestTokenArgumentIsIgnored(t *testing.T) {
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	s := &Server{schedd: htcondor.NewSchedd("test", "127.0.0.1:1"), logger: logger}

	// A syntactically valid JWT whose sub claims to be someone.
	const forged = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJzdWIiOiJhbGljZUB1aWQuZG9tYWluIiwiZXhwIjo0MTAyNDQ0ODAwfQ.sig"

	params, _ := json.Marshal(map[string]interface{}{
		"name":      "get_job",
		"arguments": map[string]interface{}{"job_id": "1.0", "token": forged},
	})
	_, err = s.handleCallTool(context.Background(), params)
	if err == nil {
		t.Fatal("expected the call to be refused for want of an authenticated caller")
	}
	if !strings.Contains(err.Error(), "authentication required") {
		t.Errorf("expected the owner-scope refusal, got: %v", err)
	}
}
