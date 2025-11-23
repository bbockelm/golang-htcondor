//go:build integration

package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
)

// TestMCPEditJobIntegration tests editing a job via MCP tool
func TestMCPEditJobIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Check if condor_master is available
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH - skipping integration test")
	}

	// Set up mini HTCondor environment
	harness := htcondor.SetupCondorHarness(t)

	// Wait for daemons to start
	if err := harness.WaitForDaemons(); err != nil {
		t.Fatalf("Daemons failed to start: %v", err)
	}

	// Discover schedd address
	addr := discoverScheddForTest(t, harness)

	// Create Schedd instance
	schedd := htcondor.NewSchedd("local", addr)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Setup MCP server
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	server := &Server{
		schedd: schedd,
		logger: logger,
	}

	// Submit a test job first
	submitFile := `
universe = vanilla
executable = /bin/sleep
arguments = 300
log = test_mcp_edit.log
request_memory = 128
queue
`
	clusterID, err := schedd.Submit(ctx, submitFile)
	if err != nil {
		t.Fatalf("Failed to submit test job: %v", err)
	}

	jobID := fmt.Sprintf("%s.0", clusterID)
	t.Logf("Submitted test job: %s", jobID)

	// Clean up job at the end
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_, _ = schedd.RemoveJobsByID(cleanupCtx, []string{jobID}, "Test cleanup")
	}()

	// Wait a bit for job to settle
	time.Sleep(2 * time.Second)

	// Test editing job via MCP tool
	t.Run("MCPEditJobTool", func(t *testing.T) {
		args := map[string]interface{}{
			"job_id": jobID,
			"attributes": map[string]interface{}{
				"RequestMemory": "256",
				"MyMCPAttr":     "\"mcp_test\"",
			},
		}

		result, err := server.toolEditJob(ctx, args)
		if err != nil {
			t.Fatalf("MCP edit_job tool failed: %v", err)
		}

		// Verify result structure
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatalf("Result is not a map: %T", result)
		}

		success, ok := resultMap["success"].(bool)
		if !ok || !success {
			t.Errorf("Result success = %v, want true", resultMap["success"])
		}

		t.Logf("✓ MCP edit_job tool returned success")

		// Verify the changes in HTCondor
		ads, err := schedd.Query(ctx, fmt.Sprintf("ClusterId == %s", clusterID), []string{"RequestMemory", "MyMCPAttr"})
		if err != nil {
			t.Fatalf("Failed to query job: %v", err)
		}

		if len(ads) == 0 {
			t.Fatal("Job not found after MCP edit")
		}

		memory, ok := ads[0].EvaluateAttrInt("RequestMemory")
		if !ok {
			t.Fatal("RequestMemory attribute not found")
		}
		if memory != 256 {
			t.Errorf("RequestMemory = %d, want 256", memory)
		}

		mcpAttr, ok := ads[0].EvaluateAttrString("MyMCPAttr")
		if !ok {
			t.Fatal("MyMCPAttr attribute not found")
		}
		if mcpAttr != "mcp_test" {
			t.Errorf("MyMCPAttr = %q, want %q", mcpAttr, "mcp_test")
		}

		t.Logf("✓ Successfully edited job via MCP tool")
	})

	// Test editing with invalid job ID via MCP
	t.Run("MCPEditJobInvalidID", func(t *testing.T) {
		args := map[string]interface{}{
			"job_id": "999999.0",
			"attributes": map[string]interface{}{
				"RequestMemory": "512",
			},
		}

		_, err := server.toolEditJob(ctx, args)
		if err == nil {
			t.Fatal("Expected error for invalid job ID, got nil")
		}

		t.Logf("✓ Correctly rejected invalid job ID via MCP: %v", err)
	})

	// Test editing immutable attribute via MCP
	t.Run("MCPEditJobImmutable", func(t *testing.T) {
		args := map[string]interface{}{
			"job_id": jobID,
			"attributes": map[string]interface{}{
				"ClusterId": "99999",
			},
		}

		_, err := server.toolEditJob(ctx, args)
		if err == nil {
			t.Fatal("Expected error for immutable attribute, got nil")
		}

		if !strings.Contains(err.Error(), "immutable") {
			t.Errorf("Expected error about immutable attribute, got: %v", err)
		}

		t.Logf("✓ Correctly rejected immutable attribute via MCP: %v", err)
	})

	// Test editing with missing job_id parameter
	t.Run("MCPEditJobMissingJobID", func(t *testing.T) {
		args := map[string]interface{}{
			"attributes": map[string]interface{}{
				"RequestMemory": "512",
			},
		}

		_, err := server.toolEditJob(ctx, args)
		if err == nil {
			t.Fatal("Expected error for missing job_id, got nil")
		}

		t.Logf("✓ Correctly rejected missing job_id parameter: %v", err)
	})

	// Test editing with missing attributes parameter
	t.Run("MCPEditJobMissingAttributes", func(t *testing.T) {
		args := map[string]interface{}{
			"job_id": jobID,
		}

		_, err := server.toolEditJob(ctx, args)
		if err == nil {
			t.Fatal("Expected error for missing attributes, got nil")
		}

		t.Logf("✓ Correctly rejected missing attributes parameter: %v", err)
	})
}

// TestMCPEditJobToolListedInTools tests that edit_job tool is listed in available tools
func TestMCPEditJobToolListedInTools(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Check if condor_master is available
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH - skipping integration test")
	}

	// Set up mini HTCondor environment
	harness := htcondor.SetupCondorHarness(t)

	// Wait for daemons to start
	if err := harness.WaitForDaemons(); err != nil {
		t.Fatalf("Daemons failed to start: %v", err)
	}

	// Discover schedd address
	addr := discoverScheddForTest(t, harness)

	// Create Schedd instance
	schedd := htcondor.NewSchedd("local", addr)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Setup MCP server
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	server := &Server{
		schedd: schedd,
		logger: logger,
	}

	// Get available tools via handleListTools
	result := server.handleListTools(ctx, nil)

	// Extract tools array from result
	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("Result is not a map: %T", result)
	}

	toolsData, ok := resultMap["tools"].([]interface{})
	if !ok {
		t.Fatalf("Tools is not an array: %T", resultMap["tools"])
	}

	// Check if edit_job is in the list
	tools := toolsData

	// Check if edit_job is in the list
	editToolFound := false
	for _, tool := range tools {
		toolMap, ok := tool.(map[string]interface{})
		if !ok {
			continue
		}

		name, ok := toolMap["name"].(string)
		if !ok {
			continue
		}

		if name == "edit_job" {
			editToolFound = true

			// Verify the tool has proper schema
			inputSchema, ok := toolMap["inputSchema"].(map[string]interface{})
			if !ok {
				t.Error("edit_job tool missing inputSchema")
			} else {
				// Verify required parameters
				required, ok := inputSchema["required"].([]interface{})
				if !ok {
					t.Error("edit_job tool missing required parameters")
				} else {
					hasJobID := false
					hasAttributes := false
					for _, req := range required {
						if reqStr, ok := req.(string); ok {
							if reqStr == "job_id" {
								hasJobID = true
							}
							if reqStr == "attributes" {
								hasAttributes = true
							}
						}
					}
					if !hasJobID {
						t.Error("edit_job tool missing job_id in required parameters")
					}
					if !hasAttributes {
						t.Error("edit_job tool missing attributes in required parameters")
					}
				}
			}

			// Log tool details
			toolJSON, _ := json.MarshalIndent(tool, "", "  ")
			t.Logf("Found edit_job tool:\n%s", string(toolJSON))
			break
		}
	}

	if !editToolFound {
		t.Error("edit_job tool not found in available tools")
		t.Logf("Available tools:")
		for _, tool := range tools {
			if toolMap, ok := tool.(map[string]interface{}); ok {
				if name, ok := toolMap["name"].(string); ok {
					t.Logf("  - %s", name)
				}
			}
		}
	} else {
		t.Log("✓ edit_job tool is properly listed in available tools")
	}
}

// Helper function to discover schedd address from harness
func discoverScheddForTest(t *testing.T, harness *htcondor.CondorTestHarness) string {
	addr := harness.GetCollectorAddr()
	addr = strings.TrimPrefix(addr, "<")
	if idx := strings.Index(addr, "?"); idx > 0 {
		addr = addr[:idx]
	}
	addr = strings.TrimSuffix(addr, ">")
	return addr
}
