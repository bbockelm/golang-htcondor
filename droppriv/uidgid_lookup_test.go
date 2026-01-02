package droppriv

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestGoFallbackLookup(t *testing.T) {
	strategy, err := NewGoLookup()
	if err != nil {
		t.Fatalf("NewGoLookup failed: %v", err)
	}

	// Look up root user
	info, err := strategy.LookupUser(context.Background(), "root")
	if err != nil {
		t.Fatalf("LookupUser(root) failed: %v", err)
	}

	if info.UID != 0 {
		t.Errorf("Expected UID 0 for root, got %d", info.UID)
	}

	if info.Username != "root" {
		t.Errorf("Expected username 'root', got %s", info.Username)
	}

	t.Logf("Strategy: %s", strategy.Name())
	t.Logf("Root user: UID=%d GID=%d HomeDir=%s", info.UID, info.GID, info.HomeDir)
}

func TestGoFallbackLookupNotFound(t *testing.T) {
	strategy, err := NewGoLookup()
	if err != nil {
		t.Fatalf("NewGoLookup failed: %v", err)
	}

	// Try to look up a non-existent user
	_, err = strategy.LookupUser(context.Background(), "nonexistentuser12345")
	if err == nil {
		t.Fatal("Expected error for non-existent user")
	}

	var notFoundErr *ErrUserNotFound
	if !errors.As(err, &notFoundErr) {
		t.Errorf("Expected ErrUserNotFound, got %T: %v", err, err)
	}
}

func TestCachedLookup(t *testing.T) {
	strategy, err := NewGoLookup()
	if err != nil {
		t.Fatalf("NewGoLookup failed: %v", err)
	}

	cached := NewCachedLookup(strategy, 100*time.Millisecond)

	// First lookup
	info1, err := cached.LookupUser(context.Background(), "root")
	if err != nil {
		t.Fatalf("First lookup failed: %v", err)
	}

	// Second lookup (should be cached)
	info2, err := cached.LookupUser(context.Background(), "root")
	if err != nil {
		t.Fatalf("Second lookup failed: %v", err)
	}

	if info1.UID != info2.UID {
		t.Errorf("Cached lookup returned different UID: %d vs %d", info1.UID, info2.UID)
	}

	// Wait for cache to expire
	time.Sleep(150 * time.Millisecond)

	// Third lookup (cache expired)
	info3, err := cached.LookupUser(context.Background(), "root")
	if err != nil {
		t.Fatalf("Third lookup failed: %v", err)
	}

	if info1.UID != info3.UID {
		t.Errorf("Expired cache lookup returned different UID: %d vs %d", info1.UID, info3.UID)
	}

	t.Logf("Cache test passed, strategy: %s", cached.Name())
}

func TestDefaultLookup(t *testing.T) {
	lookup := DefaultLookup()
	if lookup == nil {
		t.Fatal("DefaultLookup returned nil")
	}

	t.Logf("Default lookup strategy: %s", lookup.Name())

	// Test lookup
	info, err := lookup.LookupUser(context.Background(), "root")
	if err != nil {
		t.Fatalf("DefaultLookup.LookupUser(root) failed: %v", err)
	}

	if info.UID != 0 {
		t.Errorf("Expected UID 0 for root, got %d", info.UID)
	}

	t.Logf("Root user via default lookup: UID=%d GID=%d", info.UID, info.GID)
}

func TestLookupUserConvenience(t *testing.T) {
	info, err := LookupUser(context.Background(), "root")
	if err != nil {
		t.Fatalf("LookupUser(root) failed: %v", err)
	}

	if info.UID != 0 {
		t.Errorf("Expected UID 0 for root, got %d", info.UID)
	}

	t.Logf("Convenience function lookup successful: UID=%d GID=%d", info.UID, info.GID)
}

func TestCacheClear(t *testing.T) {
	strategy, err := NewGoLookup()
	if err != nil {
		t.Fatalf("NewGoLookup failed: %v", err)
	}

	cached := NewCachedLookup(strategy, time.Minute)

	// Populate cache
	_, err = cached.LookupUser(context.Background(), "root")
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}

	// Clear cache
	cached.ClearCache()

	// Lookup again (cache cleared, so fresh lookup)
	info, err := cached.LookupUser(context.Background(), "root")
	if err != nil {
		t.Fatalf("Lookup after clear failed: %v", err)
	}

	if info.UID != 0 {
		t.Errorf("Expected UID 0 for root, got %d", info.UID)
	}

	t.Log("Cache clear test passed")
}
