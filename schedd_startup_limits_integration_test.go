package htcondor

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestScheddStartupLimitsIntegration tests the startup limits functionality
//
// Note: This test requires HTCondor v25.6.0 or later with startup limits support.
// If the schedd doesn't support startup limits commands (559/560), the test will
// skip gracefully after verifying that validation and error handling work correctly.
//
//nolint:gocyclo // Integration test with multiple subtests is acceptable
func TestScheddStartupLimitsIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Check if condor_master is available
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH - skipping integration test")
	}

	// Set up mini HTCondor environment
	harness := SetupCondorHarness(t)

	// Wait for daemons to start
	if err := harness.WaitForDaemons(); err != nil {
		t.Fatalf("Daemons failed to start: %v", err)
	}

	collectorAddr := harness.GetCollectorAddr()

	// Locate schedd using collector
	collector := NewCollector(collectorAddr)
	locateCtx, locateCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer locateCancel()

	location, err := collector.LocateDaemon(locateCtx, "Schedd", "")
	if err != nil {
		t.Fatalf("Failed to locate schedd: %v", err)
	}

	t.Logf("Found schedd: %s at %s", location.Name, location.Address)

	// Create Schedd instance
	schedd := NewSchedd(location.Name, location.Address)

	// Track if server supports startup limits
	serverSupportsStartupLimits := true

	t.Run("CreateBasicStartupLimit", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Create a basic startup limit
		request := &StartupLimitRequest{
			Tag:        "test_basic_limit",
			Name:       "Test Basic Limit",
			Expression: "Owner == \"testuser\"",
			RateCount:  10,
			RateWindow: 60,
		}

		uuid, err := schedd.CreateStartupLimit(ctx, request)
		if err != nil {
			// Check if server doesn't support startup limits
			if strings.Contains(err.Error(), "EOF") || strings.Contains(err.Error(), "authentication handshake failed") {
				serverSupportsStartupLimits = false
				t.Skipf("Schedd does not support startup limits (requires HTCondor v25.6.0+): %v", err)
			}
			t.Fatalf("Failed to create startup limit: %v", err)
		}

		t.Logf("Created startup limit: UUID=%s", uuid)

		// Verify UUID was returned
		if uuid == "" {
			t.Error("Expected UUID to be set")
		}

		// Query to verify the limit was created with correct attributes
		limits, err := schedd.QueryStartupLimits(ctx, uuid, "")
		if err != nil {
			t.Fatalf("Failed to query created limit: %v", err)
		}

		if len(limits) != 1 {
			t.Fatalf("Expected exactly 1 limit with UUID=%s, got %d", uuid, len(limits))
		}

		limit := limits[0]
		if limit.Tag != "test_basic_limit" {
			t.Errorf("Expected Tag='test_basic_limit', got '%s'", limit.Tag)
		}
		if limit.Name != "Test Basic Limit" {
			t.Errorf("Expected Name='Test Basic Limit', got '%s'", limit.Name)
		}
		if limit.Expression != "Owner == \"testuser\"" {
			t.Errorf("Expected Expression='Owner == \"testuser\"', got '%s'", limit.Expression)
		}
		if limit.RateCount != 10 {
			t.Errorf("Expected RateCount=10, got %d", limit.RateCount)
		}
		if limit.RateWindow != 60 {
			t.Errorf("Expected RateWindow=60, got %d", limit.RateWindow)
		}
	})

	t.Run("CreateLimitWithCostExpression", func(t *testing.T) {
		if !serverSupportsStartupLimits {
			t.Skip("Schedd does not support startup limits")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Create a limit with cost expression
		request := &StartupLimitRequest{
			Tag:            "test_cost_limit",
			Name:           "Test Cost Limit",
			Expression:     "JobUniverse == 5",
			CostExpression: "RequestCpus",
			RateCount:      100,
			RateWindow:     60,
			Burst:          20,
		}

		uuid, err := schedd.CreateStartupLimit(ctx, request)
		if err != nil {
			t.Fatalf("Failed to create startup limit with cost expression: %v", err)
		}

		t.Logf("Created cost-based limit: UUID=%s", uuid)

		// Query to verify attributes
		limits, err := schedd.QueryStartupLimits(ctx, uuid, "")
		if err != nil {
			t.Fatalf("Failed to query created limit: %v", err)
		}

		if len(limits) != 1 {
			t.Fatalf("Expected exactly 1 limit, got %d", len(limits))
		}

		limit := limits[0]
		if limit.CostExpression != "RequestCpus" {
			t.Errorf("Expected CostExpression='RequestCpus', got '%s'", limit.CostExpression)
		}
		if limit.Burst != 20 {
			t.Errorf("Expected Burst=20, got %d", limit.Burst)
		}
	})

	t.Run("QueryAllStartupLimits", func(t *testing.T) {
		if !serverSupportsStartupLimits {
			t.Skip("Schedd does not support startup limits")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Query all startup limits
		limits, err := schedd.QueryStartupLimits(ctx, "", "")
		if err != nil {
			t.Fatalf("Failed to query startup limits: %v", err)
		}

		t.Logf("Found %d startup limit(s)", len(limits))

		// Should have at least the two we just created
		if len(limits) < 2 {
			t.Errorf("Expected at least 2 limits, got %d", len(limits))
		}

		// Verify we can find our test limits
		foundBasic := false
		foundCost := false
		for _, limit := range limits {
			t.Logf("Limit: UUID=%s, Tag=%s, Name=%s, RateCount=%d, RateWindow=%d",
				limit.UUID, limit.Tag, limit.Name, limit.RateCount, limit.RateWindow)

			if limit.Tag == "test_basic_limit" {
				foundBasic = true
			}
			if limit.Tag == "test_cost_limit" {
				foundCost = true
			}
		}

		if !foundBasic {
			t.Error("Did not find 'test_basic_limit' in query results")
		}
		if !foundCost {
			t.Error("Did not find 'test_cost_limit' in query results")
		}
	})

	t.Run("QueryStartupLimitByTag", func(t *testing.T) {
		if !serverSupportsStartupLimits {
			t.Skip("Schedd does not support startup limits")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Query by specific tag
		limits, err := schedd.QueryStartupLimits(ctx, "", "test_basic_limit")
		if err != nil {
			t.Fatalf("Failed to query startup limits by tag: %v", err)
		}

		if len(limits) != 1 {
			t.Fatalf("Expected exactly 1 limit with tag 'test_basic_limit', got %d", len(limits))
		}

		limit := limits[0]
		if limit.Tag != "test_basic_limit" {
			t.Errorf("Expected Tag='test_basic_limit', got '%s'", limit.Tag)
		}

		t.Logf("Found limit by tag: UUID=%s, Name=%s", limit.UUID, limit.Name)
	})

	t.Run("UpdateExistingLimit", func(t *testing.T) {
		if !serverSupportsStartupLimits {
			t.Skip("Schedd does not support startup limits")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// First query to get the UUID
		limits, err := schedd.QueryStartupLimits(ctx, "", "test_basic_limit")
		if err != nil {
			t.Fatalf("Failed to query for existing limit: %v", err)
		}
		if len(limits) == 0 {
			t.Fatal("Expected to find 'test_basic_limit' for update test")
		}

		existingLimit := limits[0]
		t.Logf("Updating limit with UUID=%s", existingLimit.UUID)

		// Update the limit with new rate
		request := &StartupLimitRequest{
			UUID:       existingLimit.UUID,
			Tag:        "test_basic_limit",
			Name:       "Test Basic Limit - Updated",
			Expression: "Owner == \"testuser\"",
			RateCount:  20, // Changed from 10
			RateWindow: 60,
		}

		updatedUUID, err := schedd.CreateStartupLimit(ctx, request)
		if err != nil {
			t.Fatalf("Failed to update startup limit: %v", err)
		}

		t.Logf("Updated limit: UUID=%s", updatedUUID)

		// Verify update - UUID should stay the same
		if updatedUUID != existingLimit.UUID {
			t.Errorf("UUID changed during update: %s -> %s", existingLimit.UUID, updatedUUID)
		}

		// Query updated limit to verify changes
		updatedLimits, err := schedd.QueryStartupLimits(ctx, updatedUUID, "")
		if err != nil {
			t.Fatalf("Failed to query updated limit: %v", err)
		}

		if len(updatedLimits) != 1 {
			t.Fatalf("Expected exactly 1 updated limit, got %d", len(updatedLimits))
		}

		updatedLimit := updatedLimits[0]
		if updatedLimit.Name != "Test Basic Limit - Updated" {
			t.Errorf("Name not updated: got '%s'", updatedLimit.Name)
		}
		if updatedLimit.RateCount != 20 {
			t.Errorf("RateCount not updated: expected 20, got %d", updatedLimit.RateCount)
		}
	})

	t.Run("CreateLimitWithExpiration", func(t *testing.T) {
		if !serverSupportsStartupLimits {
			t.Skip("Schedd does not support startup limits")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Create a limit with expiration
		request := &StartupLimitRequest{
			Tag:        "test_expiring_limit",
			Name:       "Test Expiring Limit",
			Expression: "true",
			RateCount:  5,
			RateWindow: 60,
			Expiration: 3600, // 1 hour
		}

		uuid, err := schedd.CreateStartupLimit(ctx, request)
		if err != nil {
			t.Fatalf("Failed to create startup limit with expiration: %v", err)
		}

		t.Logf("Created expiring limit: UUID=%s", uuid)

		// Query to verify expiration attributes
		limits, err := schedd.QueryStartupLimits(ctx, uuid, "")
		if err != nil {
			t.Fatalf("Failed to query created limit: %v", err)
		}

		if len(limits) != 1 {
			t.Fatalf("Expected exactly 1 limit, got %d", len(limits))
		}

		limit := limits[0]
		if limit.Expiration != 3600 {
			t.Errorf("Expected Expiration=3600, got %d", limit.Expiration)
		}
		if limit.ExpiresAt == 0 {
			t.Error("Expected ExpiresAt to be set (non-zero)")
		}
	})

	t.Run("InvalidRequests", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		tests := []struct {
			name    string
			request *StartupLimitRequest
		}{
			{
				name:    "MissingTag",
				request: &StartupLimitRequest{Expression: "true", RateCount: 10, RateWindow: 60},
			},
			{
				name:    "MissingExpression",
				request: &StartupLimitRequest{Tag: "test", RateCount: 10, RateWindow: 60},
			},
			{
				name:    "NegativeRateCount",
				request: &StartupLimitRequest{Tag: "test", Expression: "true", RateCount: -1, RateWindow: 60},
			},
			{
				name:    "ZeroRateWindow",
				request: &StartupLimitRequest{Tag: "test", Expression: "true", RateCount: 10, RateWindow: 0},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				_, err := schedd.CreateStartupLimit(ctx, tt.request)
				if err == nil {
					t.Error("Expected error for invalid request, but got none")
				} else {
					t.Logf("Got expected error: %v", err)
				}
			})
		}
	})
}
