package ratelimit

import (
	"context"
	"testing"
	"time"
)

func TestNewLimiter(t *testing.T) {
	tests := []struct {
		name          string
		globalRate    float64
		perUserRate   float64
		expectGlobal  bool
		expectPerUser bool
	}{
		{
			name:          "unlimited",
			globalRate:    0,
			perUserRate:   0,
			expectGlobal:  false,
			expectPerUser: false,
		},
		{
			name:          "global only",
			globalRate:    10,
			perUserRate:   0,
			expectGlobal:  true,
			expectPerUser: false,
		},
		{
			name:          "per-user only",
			globalRate:    0,
			perUserRate:   5,
			expectGlobal:  false,
			expectPerUser: true,
		},
		{
			name:          "both limits",
			globalRate:    20,
			perUserRate:   5,
			expectGlobal:  true,
			expectPerUser: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limiter := NewLimiter(tt.globalRate, tt.perUserRate)

			if tt.expectGlobal && limiter.globalLimiter == nil {
				t.Error("expected global limiter, got nil")
			}
			if !tt.expectGlobal && limiter.globalLimiter != nil {
				t.Error("expected no global limiter, got one")
			}

			if tt.expectPerUser && limiter.perUserRate <= 0 {
				t.Error("expected per-user rate, got 0")
			}
			if !tt.expectPerUser && limiter.perUserRate > 0 {
				t.Error("expected no per-user rate, got one")
			}
		})
	}
}

func TestLimiterAllow(t *testing.T) {
	tests := []struct {
		name        string
		globalRate  float64
		perUserRate float64
		requests    []string // usernames for sequential requests
		expectError []bool   // whether each request should error
	}{
		{
			name:        "unlimited allows all",
			globalRate:  0,
			perUserRate: 0,
			requests:    []string{"user1", "user1", "user2", "user2"},
			expectError: []bool{false, false, false, false},
		},
		{
			name:        "global limit blocks after burst",
			globalRate:  1, // 1 req/sec with burst of 2
			perUserRate: 0,
			requests:    []string{"user1", "user1", "user1"}, // 3 requests should hit limit
			expectError: []bool{false, false, true},
		},
		{
			name:        "per-user limit blocks user",
			globalRate:  0,
			perUserRate: 1, // 1 req/sec per user with burst of 2
			requests:    []string{"user1", "user1", "user1", "user2", "user2"},
			expectError: []bool{false, false, true, false, false}, // user1 blocked, user2 ok
		},
		{
			name:        "unauthenticated user",
			globalRate:  0,
			perUserRate: 1,
			requests:    []string{"", "", ""}, // empty username = unauthenticated
			expectError: []bool{false, false, true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limiter := NewLimiter(tt.globalRate, tt.perUserRate)

			for i, username := range tt.requests {
				err := limiter.Allow(username)
				gotError := err != nil

				if gotError != tt.expectError[i] {
					t.Errorf("request %d (user=%s): expected error=%v, got error=%v (%v)",
						i, username, tt.expectError[i], gotError, err)
				}
			}
		})
	}
}

func TestLimiterWait(t *testing.T) {
	limiter := NewLimiter(10, 5) // 10 global, 5 per user

	ctx := context.Background()

	// First request should succeed immediately
	err := limiter.Wait(ctx, "testuser")
	if err != nil {
		t.Errorf("first Wait failed: %v", err)
	}

	// Test context cancellation
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel() // Cancel immediately

	err = limiter.Wait(cancelCtx, "testuser")
	if err == nil {
		t.Error("expected error from cancelled context, got nil")
	}
}

func TestLimiterWaitWithDeadline(t *testing.T) {
	// Very low rate to ensure blocking
	limiter := NewLimiter(0.1, 0.1) // 0.1 req/sec = 10 seconds between requests

	// Consume the burst
	_ = limiter.Allow("testuser")
	_ = limiter.Allow("testuser")

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// This should timeout
	err := limiter.Wait(ctx, "testuser")
	if err == nil {
		t.Error("expected timeout error, got nil")
	}
}

func TestLimiterReset(t *testing.T) {
	limiter := NewLimiter(0, 1) // per-user only

	// Create limiters for multiple users
	_ = limiter.Allow("user1")
	_ = limiter.Allow("user2")
	_ = limiter.Allow("user3")

	stats := limiter.GetStats()
	if stats.UserCount != 3 {
		t.Errorf("expected 3 users, got %d", stats.UserCount)
	}

	limiter.Reset()

	stats = limiter.GetStats()
	if stats.UserCount != 0 {
		t.Errorf("expected 0 users after reset, got %d", stats.UserCount)
	}
}

func TestLimiterGetStats(t *testing.T) {
	globalRate := 10.0
	perUserRate := 5.0
	limiter := NewLimiter(globalRate, perUserRate)

	// Create a few user limiters
	_ = limiter.Allow("user1")
	_ = limiter.Allow("user2")

	stats := limiter.GetStats()

	if stats.GlobalRate != globalRate {
		t.Errorf("expected global rate %f, got %f", globalRate, stats.GlobalRate)
	}

	if stats.PerUserRate != perUserRate {
		t.Errorf("expected per-user rate %f, got %f", perUserRate, stats.PerUserRate)
	}

	if stats.UserCount != 2 {
		t.Errorf("expected 2 users, got %d", stats.UserCount)
	}

	if stats.GlobalBurst != 20 { // 2x rate
		t.Errorf("expected global burst 20, got %d", stats.GlobalBurst)
	}

	if stats.PerUserBurst != 10 { // 2x rate
		t.Errorf("expected per-user burst 10, got %d", stats.PerUserBurst)
	}
}

func TestManager(t *testing.T) {
	manager := NewManager(10, 5, 20, 10)

	// Test schedd limiter
	err := manager.AllowSchedd("testuser")
	if err != nil {
		t.Errorf("schedd AllowSchedd failed: %v", err)
	}

	// Test collector limiter
	err = manager.AllowCollector("testuser")
	if err != nil {
		t.Errorf("collector AllowCollector failed: %v", err)
	}

	// Test wait methods
	ctx := context.Background()

	err = manager.WaitSchedd(ctx, "testuser")
	if err != nil {
		t.Errorf("schedd WaitSchedd failed: %v", err)
	}

	err = manager.WaitCollector(ctx, "testuser")
	if err != nil {
		t.Errorf("collector WaitCollector failed: %v", err)
	}

	// Test stats
	scheddStats := manager.GetScheddStats()
	if scheddStats.GlobalRate != 10 {
		t.Errorf("expected schedd global rate 10, got %f", scheddStats.GlobalRate)
	}

	collectorStats := manager.GetCollectorStats()
	if collectorStats.GlobalRate != 20 {
		t.Errorf("expected collector global rate 20, got %f", collectorStats.GlobalRate)
	}
}

func TestManagerResetAll(t *testing.T) {
	manager := NewManager(0, 5, 0, 5)

	// Create user limiters
	_ = manager.AllowSchedd("user1")
	_ = manager.AllowCollector("user2")

	scheddStats := manager.GetScheddStats()
	collectorStats := manager.GetCollectorStats()

	if scheddStats.UserCount != 1 {
		t.Errorf("expected 1 schedd user, got %d", scheddStats.UserCount)
	}
	if collectorStats.UserCount != 1 {
		t.Errorf("expected 1 collector user, got %d", collectorStats.UserCount)
	}

	manager.ResetAll()

	scheddStats = manager.GetScheddStats()
	collectorStats = manager.GetCollectorStats()

	if scheddStats.UserCount != 0 {
		t.Errorf("expected 0 schedd users after reset, got %d", scheddStats.UserCount)
	}
	if collectorStats.UserCount != 0 {
		t.Errorf("expected 0 collector users after reset, got %d", collectorStats.UserCount)
	}
}

func TestConcurrentAccess(t *testing.T) {
	limiter := NewLimiter(100, 50)

	const numGoroutines = 10
	const numRequests = 100

	done := make(chan bool)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			username := "user1"
			if id%2 == 0 {
				username = "user2"
			}

			for j := 0; j < numRequests; j++ {
				_ = limiter.Allow(username)
			}
			done <- true
		}(i)
	}

	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	stats := limiter.GetStats()
	if stats.UserCount != 2 {
		t.Errorf("expected 2 users after concurrent access, got %d", stats.UserCount)
	}
}
