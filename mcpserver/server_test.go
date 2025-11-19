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
