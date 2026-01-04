package htcondor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
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

		ads, err := collector.QueryAds(ctx, "Machine", "")
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

	// Test 5: Advertise and query for custom/generic ad type (verifies QUERY_GENERIC_ADS is used)
	t.Run("AdvertiseAndQueryCustomAdType", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Configure authentication by setting CONDOR_CONFIG to use harness config
		// This allows cedar to generate tokens for authentication
		cfg, err := harness.GetConfig()
		if err != nil {
			t.Fatalf("Failed to get config from harness: %v", err)
		}

		// Get LOCAL_DIR and use it to find condor_config
		localDir, _ := cfg.Get("LOCAL_DIR")
		configPath := filepath.Join(filepath.Dir(localDir), "condor_config")

		// Set CONDOR_CONFIG environment variable
		oldConfig := os.Getenv("CONDOR_CONFIG")
		if err := os.Setenv("CONDOR_CONFIG", configPath); err != nil {
			t.Fatalf("Failed to set CONDOR_CONFIG: %v", err)
		}
		defer func() {
			if oldConfig != "" {
				_ = os.Setenv("CONDOR_CONFIG", oldConfig)
			} else {
				_ = os.Unsetenv("CONDOR_CONFIG")
			}
		}()

		// Reload global config to pick up the test harness configuration
		ReloadDefaultConfig()
		defer ReloadDefaultConfig() // Restore original config after test

		// First, advertise a custom ad
		customAd := classad.New()
		if err := customAd.Set("MyType", "CustomServiceAd"); err != nil {
			t.Fatalf("Failed to set MyType: %v", err)
		}
		if err := customAd.Set("Name", "test-custom-service"); err != nil {
			t.Fatalf("Failed to set Name: %v", err)
		}
		if err := customAd.Set("CustomAttribute", "test-value"); err != nil {
			t.Fatalf("Failed to set CustomAttribute: %v", err)
		}

		// Advertise the custom ad (uses UPDATE_AD_GENERIC command 58)
		err = collector.Advertise(ctx, customAd, nil)
		if err != nil {
			t.Fatalf("Failed to advertise custom ad: %v", err)
		}
		t.Logf("Successfully advertised custom ad")

		// Query immediately - generic ads should be available right away
		// Give just a moment for the advertise to complete
		time.Sleep(10 * time.Millisecond)

		// Now query for the custom ad type - should use QUERY_GENERIC_ADS command (74)
		// Query with a constraint to find our specific ad
		ads, err := collector.QueryAds(ctx, "CustomServiceAd", `Name == "test-custom-service"`)
		if err != nil {
			t.Fatalf("Failed to query custom ad type: %v", err)
		}

		// We should find at least our advertised ad
		if len(ads) == 0 {
			t.Fatal("Expected to find at least one custom ad, got none")
		}

		t.Logf("Query for custom ad type succeeded with %d ads", len(ads))

		// Verify we can find our advertised ad
		foundOurAd := false
		for _, ad := range ads {
			if name := ad.EvaluateAttr("Name"); !name.IsError() {
				if nameStr, err := name.StringValue(); err == nil && nameStr == "test-custom-service" {
					foundOurAd = true
					t.Logf("Found our advertised custom ad: %s", nameStr)

					// Verify the custom attribute
					if customAttr := ad.EvaluateAttr("CustomAttribute"); customAttr.IsError() {
						t.Error("Custom ad missing CustomAttribute")
					} else if val, err := customAttr.StringValue(); err != nil || val != "test-value" {
						t.Errorf("Expected CustomAttribute='test-value', got '%s' (err=%v)", val, err)
					}
					break
				}
			}
		}

		if !foundOurAd {
			t.Error("Did not find our advertised custom ad in query results")
		}
	})
}
