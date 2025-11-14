package htcondor

import (
	"context"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

func TestNewCollector(t *testing.T) {
	collector := NewCollector("collector.example.com:9618")
	if collector == nil {
		t.Fatal("NewCollector returned nil")
	}
	if collector.address != "collector.example.com:9618" {
		t.Errorf("Expected address 'collector.example.com:9618', got '%s'", collector.address)
	}
}

func TestCollectorQueryAds(t *testing.T) {
	t.Skip("Skipping integration test - requires live collector")
	collector := NewCollector("collector.example.com:9618")
	ctx := context.Background()

	// This would require a live collector to test
	_, err := collector.QueryAds(ctx, "ScheddAd", "")
	if err != nil {
		t.Logf("Query failed (expected without live collector): %v", err)
	}
}

func TestCollectorAdvertise(t *testing.T) {
	collector := NewCollector("collector.example.com:9618")
	ctx := context.Background()

	ad := classad.New()
	_ = ad.Set("Name", "test")
	err := collector.Advertise(ctx, ad, "UPDATE_AD")
	if err == nil {
		t.Error("Expected error for unimplemented method")
	}
}

func TestCollectorLocateDaemon(t *testing.T) {
	collector := NewCollector("collector.example.com:9618")
	ctx := context.Background()

	_, err := collector.LocateDaemon(ctx, "Schedd", "test_schedd")
	if err == nil {
		t.Error("Expected error for unimplemented method")
	}
}
