//go:build integration

package htcondor

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestCommitTransactionWithSubmitRequirement tests that job commit failures
// due to submit requirements return the error reason from the schedd
func TestCommitTransactionWithSubmitRequirement(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Set up mini HTCondor with submit requirement
	h := SetupCondorHarnessWithConfig(t, getSubmitRequirementConfig())

	// Get schedd connection info
	scheddAddr := getScheddAddressFromHarness(t, h)
	t.Logf("Schedd discovered at: %s", scheddAddr)

	// Create schedd instance
	schedd := NewSchedd(h.scheddName, scheddAddr)

	// Try to submit a job that violates the requirement
	// Request less than 1024 MB of memory
	submitFile := `
universe = vanilla
executable = /bin/sleep
arguments = 1
request_memory = 512
output = test.out
error = test.err
log = test.log
queue
`

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Log("Attempting to submit job that violates submit requirement...")
	_, err := schedd.Submit(ctx, submitFile)

	// We expect this to fail
	if err == nil {
		t.Fatal("Expected job submission to fail due to submit requirement, but it succeeded")
	}

	t.Logf("Got expected error: %v", err)

	// Check that the error message contains the reason from the submit requirement
	errMsg := err.Error()

	// The error should contain details about the memory requirement
	if !strings.Contains(errMsg, "512") {
		t.Errorf("Error message should mention the requested memory (512 MB)")
		t.Errorf("Got: %s", errMsg)
	}

	if !strings.Contains(errMsg, "1024") || !strings.Contains(errMsg, "minimum") {
		t.Errorf("Error message should mention the minimum requirement (1024 MB)")
		t.Errorf("Got: %s", errMsg)
	}

	// Verify we got a meaningful error, not just an error code
	if strings.Contains(errMsg, "CommitTransaction failed with error code") &&
		!strings.Contains(errMsg, "minimum") {
		t.Errorf("Got basic error code without detailed reason - ClassAd parsing may have failed")
		t.Errorf("Got: %s", errMsg)
	}

	t.Log("Successfully verified that error message includes submit requirement details!")
}

// getSubmitRequirementConfig returns HTCondor configuration with a submit requirement
func getSubmitRequirementConfig() string {
	return `
# Submit requirement for testing error message parsing
SUBMIT_REQUIREMENT_NAMES = MinimalRequestMemory
SUBMIT_REQUIREMENT_MinimalRequestMemory = (TARGET.RequestMemory >= 1024)
SUBMIT_REQUIREMENT_MinimalRequestMemory_REASON = strcat("Job requested ", TARGET.RequestMemory, " MB, but the minimum is 1024 MB")
`
}

// getScheddAddressFromHarness queries the collector to get the schedd address
func getScheddAddressFromHarness(t *testing.T, harness *CondorTestHarness) string {
	t.Helper()

	// Parse collector address
	addr := harness.GetCollectorAddr()

	t.Logf("Querying collector at %s for schedd location", addr)

	collector := NewCollector(addr)
	ctx := context.Background()
	scheddAds, err := collector.QueryAds(ctx, "ScheddAd", "")
	if err != nil {
		t.Fatalf("Failed to query collector for schedd ads: %v", err)
	}

	if len(scheddAds) == 0 {
		t.Fatal("No schedd ads found in collector")
	}

	// Extract schedd address from ad
	scheddAd := scheddAds[0]

	// Get MyAddress attribute
	myAddressExpr, ok := scheddAd.Lookup("MyAddress")
	if !ok {
		t.Fatal("ScheddAd missing MyAddress attribute")
	}

	// Evaluate as string
	myAddress := myAddressExpr.String()
	if myAddress == "" {
		t.Fatal("MyAddress evaluated to empty string")
	}

	// Remove quotes if present (ClassAd strings include quotes)
	myAddress = strings.Trim(myAddress, "\"")

	// Parse sinful string to extract host:port
	return myAddress
}
