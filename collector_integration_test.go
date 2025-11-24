//go:build integration

package htcondor

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestCollectorLocateDaemonIntegration tests the Collector.LocateDaemon method against a real HTCondor instance
func TestCollectorLocateDaemonIntegration(t *testing.T) {
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

	// Test locating the schedd daemon
	t.Run("LocateSchedd", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		location, err := collector.LocateDaemon(ctx, "Schedd", "")
		if err != nil {
			t.Fatalf("Failed to locate schedd: %v", err)
		}

		// Verify we got a result
		if location == nil {
			t.Fatal("Expected non-nil daemon location")
		}

		// Verify the location has required fields
		if location.Address == "" {
			t.Error("Expected non-empty Address in daemon location")
		}
		if location.Pool != addr {
			t.Errorf("Expected Pool to be collector address %s, got %s", addr, location.Pool)
		}

		// Log the result
		t.Logf("Schedd Location:")
		t.Logf("  Name: %s", location.Name)
		t.Logf("  Address: %s", location.Address)
		t.Logf("  Pool: %s", location.Pool)
	})

	// Test locating the schedd daemon by name
	t.Run("LocateScheddByName", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Get the schedd name from the harness
		scheddName := harness.GetScheddName()
		t.Logf("Looking for schedd with base name: %s", scheddName)

		// First, locate any schedd to get its full name with hostname suffix
		location, err := collector.LocateDaemon(ctx, "Schedd", "")
		if err != nil {
			t.Fatalf("Failed to locate any schedd: %v", err)
		}

		// Use the full name from the located schedd
		fullScheddName := location.Name
		t.Logf("Found schedd with full name: %s", fullScheddName)

		// Now locate it by its full name
		location2, err := collector.LocateDaemon(ctx, "Schedd", fullScheddName)
		if err != nil {
			t.Fatalf("Failed to locate schedd by full name: %v", err)
		}

		// Verify we got a result
		if location2 == nil {
			t.Fatal("Expected non-nil daemon location")
		}

		// Verify the name matches
		if location2.Name != fullScheddName {
			t.Errorf("Expected Name to be %s, got %s", fullScheddName, location2.Name)
		}

		// Verify the location has required fields
		if location2.Address == "" {
			t.Error("Expected non-empty Address in daemon location")
		}
		if location2.Pool != addr {
			t.Errorf("Expected Pool to be collector address %s, got %s", addr, location2.Pool)
		}

		// Log the result
		t.Logf("Schedd Location (by full name):")
		t.Logf("  Name: %s", location2.Name)
		t.Logf("  Address: %s", location2.Address)
		t.Logf("  Pool: %s", location2.Pool)
	})

	// Test locating a non-existent daemon
	t.Run("LocateNonExistentDaemon", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		_, err := collector.LocateDaemon(ctx, "Schedd", "nonexistent_schedd_name")
		if err == nil {
			t.Error("Expected error when locating non-existent daemon")
		}
		t.Logf("Got expected error: %v", err)
	})

	// Test locating the collector daemon
	t.Run("LocateCollector", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		location, err := collector.LocateDaemon(ctx, "Collector", "")
		if err != nil {
			t.Fatalf("Failed to locate collector: %v", err)
		}

		// Verify we got a result
		if location == nil {
			t.Fatal("Expected non-nil daemon location")
		}

		// Verify the location has required fields
		if location.Address == "" {
			t.Error("Expected non-empty Address in daemon location")
		}

		// Log the result
		t.Logf("Collector Location:")
		t.Logf("  Name: %s", location.Name)
		t.Logf("  Address: %s", location.Address)
		t.Logf("  Pool: %s", location.Pool)
	})

	// Test locating the startd daemon
	t.Run("LocateStartd", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		location, err := collector.LocateDaemon(ctx, "Startd", "")
		if err != nil {
			t.Fatalf("Failed to locate startd: %v", err)
		}

		// Verify we got a result
		if location == nil {
			t.Fatal("Expected non-nil daemon location")
		}

		// Verify the location has required fields
		if location.Address == "" {
			t.Error("Expected non-empty Address in daemon location")
		}

		// Log the result
		t.Logf("Startd Location:")
		t.Logf("  Name: %s", location.Name)
		t.Logf("  Address: %s", location.Address)
		t.Logf("  Pool: %s", location.Pool)
	})
}
