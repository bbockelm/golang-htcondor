//go:build integration

package mcpserver

import (
	"context"
	"fmt"
	"os/exec"
	"slices"
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
	schedd := locateSchedd(t, harness)

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
				// A stringified number on purpose: this is what an
				// agent sends, and it used to be written as the STRING
				// "256", which leaves the job unmatchable.
				"RequestMemory": "256",
				"MyMCPAttr":     "mcp_test",
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

		// The tool returns the MCP content/metadata shape, like every
		// other tool here; it has never had a "success" field. Asserting
		// one meant this subtest failed against a working edit, and the
		// build tag kept it out of the default CI job so nobody saw it.
		//
		// What the result must carry is a human-readable confirmation;
		// whether the edit took is checked against the queue below,
		// which is the stronger claim anyway.
		content, ok := resultMap["content"].([]map[string]interface{})
		if !ok || len(content) == 0 {
			t.Fatalf("no content in edit result: %+v", resultMap)
		}
		if text, _ := content[0]["text"].(string); text == "" {
			t.Errorf("edit result carries no text: %+v", content[0])
		}

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
	schedd := locateSchedd(t, harness)

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

	// handleListTools returns Go values, not decoded JSON: tools is a
	// []Tool and a schema's "required" is a []string. Asserting
	// []interface{} here failed on every run, and the integration build
	// tag kept the failure out of CI.
	tools, ok := resultMap["tools"].([]Tool)
	if !ok {
		t.Fatalf("tools is not a []Tool: %T", resultMap["tools"])
	}

	var editTool *Tool
	for i := range tools {
		if tools[i].Name == "edit_job" {
			editTool = &tools[i]
			break
		}
	}
	if editTool == nil {
		names := make([]string, 0, len(tools))
		for _, tool := range tools {
			names = append(names, tool.Name)
		}
		t.Fatalf("edit_job is not in the tool list; got %v", names)
	}

	required, ok := editTool.InputSchema["required"].([]string)
	if !ok {
		t.Fatalf("edit_job's required parameters are not a []string: %T",
			editTool.InputSchema["required"])
	}
	for _, want := range []string{"job_id", "attributes"} {
		if !slices.Contains(required, want) {
			t.Errorf("edit_job does not require %s: %v", want, required)
		}
	}

	// The description has to tell an agent how a value is typed, or it
	// will send "256" for RequestMemory and get an unmatchable job.
	desc, _ := editTool.InputSchema["properties"].(map[string]interface{})
	if desc != nil {
		attrs, _ := desc["attributes"].(map[string]interface{})
		text, _ := attrs["description"].(string)
		if !strings.Contains(text, "number") {
			t.Errorf("edit_job's attributes description does not mention typing: %q", text)
		}
	}
}

// Helper function to discover schedd address from harness
