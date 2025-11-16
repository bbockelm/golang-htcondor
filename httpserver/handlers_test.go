package httpserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

// testHealthEndpoint is a helper function to test health check endpoints
func testHealthEndpoint(t *testing.T, handlerFunc func(http.ResponseWriter, *http.Request), path string, expectedStatus string) {
	t.Helper()

	tests := []struct {
		name           string
		method         string
		wantStatusCode int
		wantStatus     string
	}{
		{
			name:           "GET " + path + " returns " + expectedStatus,
			method:         http.MethodGet,
			wantStatusCode: http.StatusOK,
			wantStatus:     expectedStatus,
		},
		{
			name:           "POST " + path + " returns Method Not Allowed",
			method:         http.MethodPost,
			wantStatusCode: http.StatusMethodNotAllowed,
			wantStatus:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, path, nil)
			w := httptest.NewRecorder()

			handlerFunc(w, req)

			resp := w.Result()
			defer func() {
				if err := resp.Body.Close(); err != nil {
					t.Errorf("Failed to close response body: %v", err)
				}
			}()

			if resp.StatusCode != tt.wantStatusCode {
				t.Errorf("handler status = %v, want %v", resp.StatusCode, tt.wantStatusCode)
			}

			if tt.wantStatus != "" {
				var response map[string]string
				if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
					t.Fatalf("Failed to decode response: %v", err)
				}
				if response["status"] != tt.wantStatus {
					t.Errorf("handler response status = %v, want %v", response["status"], tt.wantStatus)
				}
			}
		})
	}
}

// TestHealthzEndpoint verifies the /healthz endpoint returns OK
func TestHealthzEndpoint(t *testing.T) {
	testHealthEndpoint(t, (&Server{}).handleHealthz, "/healthz", "ok")
}

// TestReadyzEndpoint verifies the /readyz endpoint returns ready status
func TestReadyzEndpoint(t *testing.T) {
	testHealthEndpoint(t, (&Server{}).handleReadyz, "/readyz", "ready")
}
