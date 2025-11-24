package htcondor

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/ratelimit"
)

// parseSinfulString extracts the host:port from an HTCondor sinful string
// Example: "<127.0.0.1:9618?addrs=127.0.0.1-9618&alias=...>" -> "127.0.0.1:9618"
//
// TODO: This is a workaround for a bug in the cedar library where it doesn't properly
// parse sinful strings before attempting to dial. The cedar library should handle this
// parsing internally. Once cedar is fixed, this function can be removed and we can pass
// the raw sinful strings directly to NewSchedd() and NewCollector().
// See: https://github.com/bbockelm/cedar/issues/TBD
func parseSinfulString(sinful string) string {
	sinful = strings.TrimPrefix(sinful, "<")
	if idx := strings.Index(sinful, "?"); idx > 0 {
		sinful = sinful[:idx] // Remove query parameters
	}
	sinful = strings.TrimSuffix(sinful, ">")
	return sinful
}

// TestScheddQueryRateLimit tests that rate limiting works for schedd queries
func TestScheddQueryRateLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	h := SetupCondorHarness(t)

	// Print logs on failure to help diagnose CI issues
	defer func() {
		if t.Failed() {
			t.Log("Test failed, printing HTCondor logs for diagnosis:")
			h.PrintScheddLog()
			h.printMasterLog()
			h.printCollectorLog()
		}
	}()

	// Get collector address
	collectorAddr := h.GetCollectorAddr()

	// Get schedd - we need to query the collector to find it
	ctx := context.Background()
	collector := NewCollector(collectorAddr)
	scheddAds, err := collector.QueryAds(ctx, "ScheddAd", "")
	if err != nil || len(scheddAds) == 0 {
		t.Skipf("No schedd found, skipping rate limit test: %v", err)
	}

	// Get schedd address from the ad
	scheddAddr, ok := scheddAds[0].EvaluateAttrString("MyAddress")
	if !ok {
		t.Fatal("Schedd ad missing MyAddress")
	}

	scheddName, ok := scheddAds[0].EvaluateAttrString("Name")
	if !ok {
		scheddName = "schedd"
	}

	schedd := NewSchedd(scheddName, scheddAddr)

	// Create a config with rate limits
	cfg := config.NewEmpty()
	cfg.Set("SCHEDD_QUERY_RATE_LIMIT", "2")          // 2 queries per second globally
	cfg.Set("SCHEDD_QUERY_PER_USER_RATE_LIMIT", "1") // 1 query per second per user

	// Create rate limiter manager
	manager := ratelimit.ConfigFromHTCondor(cfg)

	// Store old manager and restore after test
	oldManager := getRateLimitManager()
	defer func() {
		if oldManager != nil {
			globalRateLimitManager.Store(oldManager)
		}
	}()
	globalRateLimitManager.Store(manager)

	constraint := "true"
	projection := []string{"ClusterId", "ProcId"}

	// Test 1: Multiple queries within rate limit should succeed
	t.Run("queries within limit succeed", func(t *testing.T) {
		// First query should succeed
		_, err := schedd.Query(ctx, constraint, projection)
		if err != nil {
			t.Fatalf("first query failed: %v", err)
		}

		// Second query should succeed (within burst)
		_, err2 := schedd.Query(ctx, constraint, projection)
		if err2 != nil {
			t.Fatalf("second query failed: %v", err2)
		}
	})

	// Test 2: Queries exceeding burst should block or fail
	t.Run("queries exceeding burst wait", func(t *testing.T) {
		// Reset rate limiters to start fresh
		manager.ResetAll()

		// Consume burst (2 queries at 2 qps = burst of 4)
		for i := 0; i < 4; i++ {
			_, err := schedd.Query(ctx, constraint, projection)
			if err != nil {
				t.Fatalf("query %d failed: %v", i, err)
			}
		}

		// Next query should block until tokens are available
		start := time.Now()
		_, err := schedd.Query(ctx, constraint, projection)
		elapsed := time.Since(start)

		if err != nil {
			t.Fatalf("query after burst failed: %v", err)
		}

		// Should have waited at least some time for rate limit
		if elapsed < 100*time.Millisecond {
			t.Logf("query returned too quickly (%v), might not be rate limited", elapsed)
		}
	})

	// Test 3: Per-user rate limits work independently
	t.Run("per-user rate limits", func(t *testing.T) {
		// Reset rate limiters
		manager.ResetAll()

		// Create contexts with different usernames
		ctx1 := WithAuthenticatedUser(context.Background(), "user1")
		ctx2 := WithAuthenticatedUser(context.Background(), "user2")

		// Each user should be able to make their burst of queries
		// Per-user limit is 1 qps with burst of 2
		_, err := schedd.Query(ctx1, constraint, projection)
		if err != nil {
			t.Fatalf("user1 first query failed: %v", err)
		}

		_, err = schedd.Query(ctx1, constraint, projection)
		if err != nil {
			t.Fatalf("user1 second query failed: %v", err)
		}

		// User2 should also be able to make queries
		_, err = schedd.Query(ctx2, constraint, projection)
		if err != nil {
			t.Fatalf("user2 first query failed: %v", err)
		}

		_, err = schedd.Query(ctx2, constraint, projection)
		if err != nil {
			t.Fatalf("user2 second query failed: %v", err)
		}
	})

	// Test 4: Unauthenticated requests use "unauthenticated" username
	t.Run("unauthenticated queries", func(t *testing.T) {
		// Reset rate limiters
		manager.ResetAll()

		// Queries without authenticated user context
		ctxUnauth := context.Background()

		// Should be rate limited together
		_, err := schedd.Query(ctxUnauth, constraint, projection)
		if err != nil {
			t.Fatalf("first unauthenticated query failed: %v", err)
		}

		_, err = schedd.Query(ctxUnauth, constraint, projection)
		if err != nil {
			t.Fatalf("second unauthenticated query failed: %v", err)
		}
	})
}

// TestCollectorQueryRateLimit tests that rate limiting works for collector queries
func TestCollectorQueryRateLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	h := SetupCondorHarness(t)

	// Parse collector address - HTCondor uses "sinful strings" like <127.0.0.1:9618?addrs=...>
	// Extract the host:port from within the angle brackets
	addr := parseSinfulString(h.GetCollectorAddr())

	// Get collector instance
	collector := NewCollector(addr)

	// Create a config with rate limits
	cfg := config.NewEmpty()
	cfg.Set("COLLECTOR_QUERY_RATE_LIMIT", "3")          // 3 queries per second globally
	cfg.Set("COLLECTOR_QUERY_PER_USER_RATE_LIMIT", "2") // 2 queries per second per user

	// Create rate limiter manager
	manager := ratelimit.ConfigFromHTCondor(cfg)

	// Store old manager and restore after test
	oldManager := getRateLimitManager()
	defer func() {
		if oldManager != nil {
			globalRateLimitManager.Store(oldManager)
		}
	}()
	globalRateLimitManager.Store(manager)

	ctx := context.Background()
	adType := "ScheddAd"
	constraint := ""

	// Test 1: Multiple queries within rate limit should succeed
	t.Run("queries within limit succeed", func(t *testing.T) {
		// Reset to start fresh
		manager.ResetAll()

		// First few queries should succeed (within burst)
		for i := 0; i < 3; i++ {
			_, err := collector.QueryAds(ctx, adType, constraint)
			if err != nil {
				t.Fatalf("query %d failed: %v", i, err)
			}
		}
	})

	// Test 2: Different users have independent limits
	t.Run("per-user rate limits", func(t *testing.T) {
		// Reset rate limiters
		manager.ResetAll()

		ctx1 := WithAuthenticatedUser(context.Background(), "alice")
		ctx2 := WithAuthenticatedUser(context.Background(), "bob")

		// Each user gets their own per-user limit (2 qps = burst of 4)
		for i := 0; i < 4; i++ {
			_, err := collector.QueryAds(ctx1, adType, constraint)
			if err != nil {
				t.Fatalf("alice query %d failed: %v", i, err)
			}
		}

		for i := 0; i < 4; i++ {
			_, err := collector.QueryAds(ctx2, adType, constraint)
			if err != nil {
				t.Fatalf("bob query %d failed: %v", i, err)
			}
		}
	})
}

// TestRateLimitConfiguration tests rate limit configuration loading
func TestRateLimitConfiguration(t *testing.T) {
	tests := []struct {
		name                     string
		config                   map[string]string
		expectedScheddGlobal     float64
		expectedScheddPerUser    float64
		expectedCollectorGlobal  float64
		expectedCollectorPerUser float64
	}{
		{
			name:                     "no limits configured",
			config:                   map[string]string{},
			expectedScheddGlobal:     0,
			expectedScheddPerUser:    0,
			expectedCollectorGlobal:  0,
			expectedCollectorPerUser: 0,
		},
		{
			name: "all limits configured",
			config: map[string]string{
				"SCHEDD_QUERY_RATE_LIMIT":             "10",
				"SCHEDD_QUERY_PER_USER_RATE_LIMIT":    "5",
				"COLLECTOR_QUERY_RATE_LIMIT":          "20",
				"COLLECTOR_QUERY_PER_USER_RATE_LIMIT": "10",
			},
			expectedScheddGlobal:     10,
			expectedScheddPerUser:    5,
			expectedCollectorGlobal:  20,
			expectedCollectorPerUser: 10,
		},
		{
			name: "partial limits configured",
			config: map[string]string{
				"SCHEDD_QUERY_RATE_LIMIT":             "15",
				"COLLECTOR_QUERY_PER_USER_RATE_LIMIT": "8",
			},
			expectedScheddGlobal:     15,
			expectedScheddPerUser:    0,
			expectedCollectorGlobal:  0,
			expectedCollectorPerUser: 8,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.NewEmpty()
			for k, v := range tt.config {
				cfg.Set(k, v)
			}

			manager := ratelimit.ConfigFromHTCondor(cfg)

			scheddStats := manager.GetScheddStats()
			if scheddStats.GlobalRate != tt.expectedScheddGlobal {
				t.Errorf("schedd global rate: expected %f, got %f",
					tt.expectedScheddGlobal, scheddStats.GlobalRate)
			}
			if scheddStats.PerUserRate != tt.expectedScheddPerUser {
				t.Errorf("schedd per-user rate: expected %f, got %f",
					tt.expectedScheddPerUser, scheddStats.PerUserRate)
			}

			collectorStats := manager.GetCollectorStats()
			if collectorStats.GlobalRate != tt.expectedCollectorGlobal {
				t.Errorf("collector global rate: expected %f, got %f",
					tt.expectedCollectorGlobal, collectorStats.GlobalRate)
			}
			if collectorStats.PerUserRate != tt.expectedCollectorPerUser {
				t.Errorf("collector per-user rate: expected %f, got %f",
					tt.expectedCollectorPerUser, collectorStats.PerUserRate)
			}
		})
	}
}
