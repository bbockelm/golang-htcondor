package htcondor

import (
	"context"
	"strings"
	"testing"
	"time"
)

//
//nolint:gocyclo // Complex test with multiple subtests is acceptable
func TestCollectorQueryIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Setup mini HTCondor instance
	harness := SetupCondorHarness(t)

	t.Logf("HTCondor instance started with collector at: %s", harness.GetCollectorAddr())

	// Parse collector address - HTCondor uses "sinful strings" like <127.0.0.1:9618?addrs=...>
	// Extract the host:port from within the angle brackets
	addr := harness.GetCollectorAddr()
	addr = strings.TrimPrefix(addr, "<")
	if idx := strings.Index(addr, "?"); idx > 0 {
		addr = addr[:idx] // Remove query parameters
	}
	addr = strings.TrimSuffix(addr, ">")

	// Create a Collector client
	collector := NewCollector(addr)

	// Test 1: Query for collector daemon ad
	t.Run("QueryCollectorAd", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		ads, err := collector.QueryAds(ctx, "Collector", "")
		if err != nil {
			t.Fatalf("Failed to query collector: %v", err)
		}

		if len(ads) == 0 {
			t.Fatal("Expected at least one collector ad, got none")
		}

		t.Logf("Found %d collector ad(s)", len(ads))

		// Verify the collector ad has expected attributes
		collectorAd := ads[0]
		if name := collectorAd.EvaluateAttr("Name"); name.IsError() {
			t.Error("Collector ad missing Name attribute")
		} else {
			t.Logf("Collector Name: %v", name)
		}

		if myType := collectorAd.EvaluateAttr("MyType"); myType.IsError() {
			t.Error("Collector ad missing MyType attribute")
		} else if str, _ := myType.StringValue(); str != "Collector" {
			t.Errorf("Expected MyType='Collector', got '%s'", str)
		}
	})

	// Test 2: Query for schedd daemon ads
	t.Run("QueryScheddAd", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		ads, err := collector.QueryAds(ctx, "Schedd", "")
		if err != nil {
			t.Fatalf("Failed to query schedd: %v", err)
		}

		if len(ads) == 0 {
			t.Fatal("Expected at least one schedd ad, got none")
		}

		t.Logf("Found %d schedd ad(s)", len(ads))

		scheddAd := ads[0]
		if name := scheddAd.EvaluateAttr("Name"); name.IsError() {
			t.Error("Schedd ad missing Name attribute")
		} else {
			t.Logf("Schedd Name: %v", name)
		}

		if myType := scheddAd.EvaluateAttr("MyType"); myType.IsError() {
			t.Error("Schedd ad missing MyType attribute")
		} else if str, _ := myType.StringValue(); str != "Scheduler" {
			t.Errorf("Expected MyType='Scheduler', got '%s'", str)
		}
	})

	// Test 3: Query for startd daemon ads
	t.Run("QueryStartdAd", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		ads, err := collector.QueryAds(ctx, "Startd", "")
		if err != nil {
			t.Fatalf("Failed to query startd: %v", err)
		}

		if len(ads) == 0 {
			t.Skip("No startd ads found - startd may not have started successfully")
		}

		t.Logf("Found %d startd ad(s)", len(ads))

		startdAd := ads[0]
		if name := startdAd.EvaluateAttr("Name"); name.IsError() {
			t.Error("Startd ad missing Name attribute")
		} else {
			t.Logf("Startd Name: %v", name)
		}

		if myType := startdAd.EvaluateAttr("MyType"); myType.IsError() {
			t.Error("Startd ad missing MyType attribute")
		} else if str, _ := myType.StringValue(); str != "Machine" {
			t.Errorf("Expected MyType='Machine', got '%s'", str)
		}

		// Check for resource attributes
		if cpus := startdAd.EvaluateAttr("Cpus"); cpus.IsError() {
			t.Error("Startd ad missing Cpus attribute")
		} else {
			t.Logf("Startd Cpus: %v", cpus)
		}

		if memory := startdAd.EvaluateAttr("Memory"); memory.IsError() {
			t.Error("Startd ad missing Memory attribute")
		} else {
			t.Logf("Startd Memory: %v", memory)
		}
	})

	// Test 4: Query with constraint
	t.Run("QueryWithConstraint", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Query for machines with at least 1 CPU
		ads, err := collector.QueryAds(ctx, "Startd", "Cpus >= 1")
		if err != nil {
			t.Fatalf("Failed to query with constraint: %v", err)
		}

		if len(ads) == 0 {
			t.Skip("No startd ads found - startd may not have started successfully")
		}

		t.Logf("Found %d machine(s) matching constraint", len(ads))

		// Verify constraint is satisfied
		for i, ad := range ads {
			if cpus := ad.EvaluateAttr("Cpus"); cpus.IsError() {
				t.Errorf("Ad %d missing Cpus attribute", i)
			} else if val, err := cpus.IntValue(); err != nil || val < 1 {
				t.Errorf("Ad %d does not satisfy constraint: Cpus = %v", i, val)
			}
		}
	})

	// Test 5: Query non-existent daemon type (should return error)
	t.Run("QueryNonExistentType", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		ads, err := collector.QueryAds(ctx, "NonExistentDaemon", "")
		if err == nil {
			t.Errorf("Expected error for non-existent daemon type, but query succeeded with %d ads", len(ads))
			// Print the unexpected ad(s) for debugging
			for i, ad := range ads {
				t.Logf("Unexpected ad %d:", i)
				if myType := ad.EvaluateAttr("MyType"); !myType.IsError() {
					t.Logf("  MyType: %v", myType)
				}
				if name := ad.EvaluateAttr("Name"); !name.IsError() {
					t.Logf("  Name: %v", name)
				}
			}
		} else {
			t.Logf("Got expected error: %v", err)
		}
	})
}
