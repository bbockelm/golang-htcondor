package httpserver

import (
	"testing"
)

// TestParseJobID tests the parseJobID helper function
func TestParseJobID(t *testing.T) {
	tests := []struct {
		name        string
		jobID       string
		wantCluster int
		wantProc    int
		wantErr     bool
	}{
		{"valid job ID", "123.0", 123, 0, false},
		{"valid job ID with proc", "456.7", 456, 7, false},
		{"invalid format - no dot", "123", 0, 0, true},
		{"invalid format - multiple dots", "123.4.5", 0, 0, true},
		{"invalid cluster", "abc.0", 0, 0, true},
		{"invalid proc", "123.xyz", 0, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cluster, proc, err := parseJobID(tt.jobID)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseJobID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if cluster != tt.wantCluster {
					t.Errorf("parseJobID() cluster = %v, want %v", cluster, tt.wantCluster)
				}
				if proc != tt.wantProc {
					t.Errorf("parseJobID() proc = %v, want %v", proc, tt.wantProc)
				}
			}
		})
	}
}

// TestCollectorAdsResponse verifies the response structure for collector ads
func TestCollectorAdsResponse(t *testing.T) {
	response := CollectorAdsResponse{
		Ads: nil,
	}

	if response.Ads != nil {
		t.Error("Expected nil ads in empty response")
	}
}
