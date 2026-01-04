package htcondor

import (
	"context"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/commands"
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
	// This test verifies that Advertise can be called with valid parameters
	// It won't succeed without a real collector, but should not panic
	collector := NewCollector("collector.example.com:9618")
	ctx := context.Background()

	ad := classad.New()
	_ = ad.Set("MyType", "Generic")
	_ = ad.Set("Name", "test")

	// This will fail to connect, but that's expected in unit tests
	err := collector.Advertise(ctx, ad, nil)
	if err == nil {
		t.Error("Expected error when connecting to non-existent collector")
	}

	// Test with nil ad
	err = collector.Advertise(ctx, nil, nil)
	if err == nil {
		t.Error("Expected error for nil ad")
	}
}

func TestCollectorLocateDaemon(t *testing.T) {
	collector := NewCollector("collector.example.com:9618")
	ctx := context.Background()

	_, err := collector.LocateDaemon(ctx, "Schedd", "test_schedd")
	if err == nil {
		t.Error("Expected error when connecting to non-existent collector")
	}
}

func TestGetCommandForAdType(t *testing.T) {
	tests := []struct {
		name        string
		adType      string
		wantCommand commands.CommandType
	}{
		{
			name:        "StartdAd",
			adType:      "StartdAd",
			wantCommand: commands.QUERY_STARTD_ADS,
		},
		{
			name:        "Machine",
			adType:      "Machine",
			wantCommand: commands.QUERY_STARTD_ADS,
		},
		{
			name:        "ScheddAd",
			adType:      "ScheddAd",
			wantCommand: commands.QUERY_SCHEDD_ADS,
		},
		{
			name:        "Collector",
			adType:      "Collector",
			wantCommand: commands.QUERY_COLLECTOR_ADS,
		},
		{
			name:        "Custom ad type",
			adType:      "MyCustomType",
			wantCommand: commands.QUERY_GENERIC_ADS,
		},
		{
			name:        "Another custom type",
			adType:      "ServiceAd",
			wantCommand: commands.QUERY_GENERIC_ADS,
		},
		{
			name:        "Empty string uses generic",
			adType:      "",
			wantCommand: commands.QUERY_GENERIC_ADS,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCommand := getCommandForAdType(tt.adType)
			if gotCommand != tt.wantCommand {
				t.Errorf("getCommandForAdType() = %v, want %v", gotCommand, tt.wantCommand)
			}
		})
	}
}
