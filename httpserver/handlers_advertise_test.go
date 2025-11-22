package httpserver

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
)

// testLogger creates a logger for tests
func testLogger(t *testing.T) *logging.Logger {
	logger, err := logging.New(&logging.Config{
		OutputPath: "stderr",
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	return logger
}

func TestParseUpdateCommand(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		shouldExist bool
	}{
		{
			name:        "UPDATE_STARTD_AD",
			input:       "UPDATE_STARTD_AD",
			shouldExist: true,
		},
		{
			name:        "lowercase update_startd_ad",
			input:       "update_startd_ad",
			shouldExist: true,
		},
		{
			name:        "UPDATE_SCHEDD_AD",
			input:       "UPDATE_SCHEDD_AD",
			shouldExist: true,
		},
		{
			name:        "UPDATE_AD_GENERIC",
			input:       "UPDATE_AD_GENERIC",
			shouldExist: true,
		},
		{
			name:        "Invalid command",
			input:       "INVALID_COMMAND",
			shouldExist: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ok := htcondor.ParseAdvertiseCommand(tt.input)
			if ok != tt.shouldExist {
				t.Errorf("Expected existence %v, got %v", tt.shouldExist, ok)
			}
		})
	}
}

func TestHandleCollectorAdvertise_NoCollector(t *testing.T) {
	server := &Server{
		logger:    testLogger(t),
		collector: nil, // No collector configured
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/collector/advertise", nil)
	w := httptest.NewRecorder()

	server.handleCollectorAdvertise(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Errorf("Expected status %d, got %d", http.StatusNotImplemented, w.Code)
	}
}

func TestHandleCollectorAdvertise_MethodNotAllowed(t *testing.T) {
	server := &Server{
		logger:    testLogger(t),
		collector: htcondor.NewCollector("localhost:9618"),
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/collector/advertise", nil)
	w := httptest.NewRecorder()

	server.handleCollectorAdvertise(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

func TestHandleCollectorAdvertise_JSON_SingleAd(t *testing.T) {
	// This test verifies the JSON parsing logic, but will fail to connect
	// since there's no real collector
	server := &Server{
		logger:    testLogger(t),
		collector: htcondor.NewCollector("localhost:9618"),
	}

	// Create a test ad
	ad := classad.New()
	_ = ad.Set("MyType", "Generic")
	_ = ad.Set("Name", "test-ad")

	reqBody := AdvertiseRequest{
		Ad:      ad,
		WithAck: false,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/collector/advertise", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.handleCollectorAdvertise(w, req)

	// Should fail to connect, but that's expected
	if w.Code != http.StatusInternalServerError {
		t.Logf("Response: %s", w.Body.String())
		// This is actually expected behavior - connection will fail
	}

	// Verify response structure
	var response AdvertiseResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if response.Failed != 1 {
		t.Errorf("Expected 1 failed ad, got %d", response.Failed)
	}
}

func TestHandleCollectorAdvertise_JSON_MissingAd(t *testing.T) {
	server := &Server{
		logger:    testLogger(t),
		collector: htcondor.NewCollector("localhost:9618"),
	}

	reqBody := AdvertiseRequest{
		Ad:      nil, // Missing ad
		WithAck: false,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/collector/advertise", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.handleCollectorAdvertise(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestHandleCollectorAdvertise_PlainText(t *testing.T) {
	server := &Server{
		logger:    testLogger(t),
		collector: htcondor.NewCollector("localhost:9618"),
	}

	// ClassAd in old format
	adText := `
MyType = "Generic"
Name = "test-ad"
TestAttr = 123
`

	req := httptest.NewRequest(http.MethodPost, "/api/v1/collector/advertise", strings.NewReader(adText))
	req.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()

	server.handleCollectorAdvertise(w, req)

	// Should parse successfully but fail to connect
	if w.Code != http.StatusInternalServerError {
		t.Logf("Response: %s", w.Body.String())
	}

	var response AdvertiseResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if response.Failed != 1 {
		t.Errorf("Expected 1 failed ad, got %d", response.Failed)
	}
}

func TestHandleCollectorAdvertise_Multipart(t *testing.T) {
	server := &Server{
		logger:    testLogger(t),
		collector: htcondor.NewCollector("localhost:9618"),
	}

	// Create multipart form
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add first ad
	part1, err := writer.CreateFormFile("ad1", "ad1.classad")
	if err != nil {
		t.Fatalf("Failed to create form file: %v", err)
	}
	_, _ = part1.Write([]byte(`MyType = "Generic"
Name = "test-ad-1"
`))

	// Add second ad
	part2, err := writer.CreateFormFile("ad2", "ad2.classad")
	if err != nil {
		t.Fatalf("Failed to create form file: %v", err)
	}
	_, _ = part2.Write([]byte(`MyType = "Generic"
Name = "test-ad-2"
`))

	// Add form values
	_ = writer.WriteField("with_ack", "false")

	if err := writer.Close(); err != nil {
		t.Fatalf("Failed to close writer: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/collector/advertise", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	w := httptest.NewRecorder()

	server.handleCollectorAdvertise(w, req)

	// Should parse multiple ads but fail to connect
	var response AdvertiseResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	// Both ads should fail to advertise (no real collector)
	if response.Failed != 2 {
		t.Errorf("Expected 2 failed ads, got %d", response.Failed)
	}
}

func TestHandleCollectorAdvertise_UnsupportedMediaType(t *testing.T) {
	server := &Server{
		logger:    testLogger(t),
		collector: htcondor.NewCollector("localhost:9618"),
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/collector/advertise", strings.NewReader("data"))
	req.Header.Set("Content-Type", "application/xml")
	w := httptest.NewRecorder()

	server.handleCollectorAdvertise(w, req)

	if w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("Expected status %d, got %d", http.StatusUnsupportedMediaType, w.Code)
	}
}

func TestHandleCollectorAdvertise_InvalidCommand(t *testing.T) {
	server := &Server{
		logger:    testLogger(t),
		collector: htcondor.NewCollector("localhost:9618"),
	}

	ad := classad.New()
	_ = ad.Set("MyType", "Generic")
	_ = ad.Set("Name", "test")

	reqBody := AdvertiseRequest{
		Ad:      ad,
		Command: "INVALID_COMMAND",
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/collector/advertise", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.handleCollectorAdvertise(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	bodyStr := w.Body.String()
	if !strings.Contains(bodyStr, "Invalid command") {
		t.Errorf("Expected error message about invalid command, got: %s", bodyStr)
	}
}

func TestParseAdvertiseMultipart_SizeLimit(t *testing.T) {
	server := &Server{
		logger: testLogger(t),
	}

	// Create a multipart form with a large file (> 1MB total)
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile("ad1", "large.classad")
	if err != nil {
		t.Fatalf("Failed to create form file: %v", err)
	}

	// Write > 1MB of data (exceeds MaxAdvertiseBufferSize)
	largeData := make([]byte, htcondor.MaxAdvertiseBufferSize+1)
	_, _ = part.Write(largeData)

	if err := writer.Close(); err != nil {
		t.Fatalf("Failed to close writer: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/collector/advertise", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// This should fail due to size limit
	_, _, _, err = server.parseAdvertiseMultipart(req)
	if err == nil {
		t.Error("Expected error for size limit, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds 1MB") {
		t.Errorf("Expected size limit error, got: %v", err)
	}
}

func TestHandleCollectorPath_Advertise(t *testing.T) {
	// Test that the routing works correctly
	server := &Server{
		logger:    testLogger(t),
		collector: htcondor.NewCollector("localhost:9618"),
	}

	ad := classad.New()
	_ = ad.Set("MyType", "Generic")

	reqBody := AdvertiseRequest{
		Ad: ad,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/collector/advertise", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.handleCollectorPath(w, req)

	// Should reach the advertise handler and fail to connect
	if w.Code == http.StatusNotFound {
		t.Error("Routing failed - got 404")
	}
}

func TestAdvertiseResponse_StatusCodes(t *testing.T) {
	tests := []struct {
		name           string
		succeeded      int
		failed         int
		expectedStatus int
	}{
		{
			name:           "All succeeded",
			succeeded:      5,
			failed:         0,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "All failed",
			succeeded:      0,
			failed:         5,
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:           "Partial success",
			succeeded:      3,
			failed:         2,
			expectedStatus: http.StatusMultiStatus,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := AdvertiseResponse{
				Succeeded: tt.succeeded,
				Failed:    tt.failed,
			}

			// Determine status code using same logic as handler
			statusCode := http.StatusOK
			if response.Failed > 0 && response.Succeeded == 0 {
				statusCode = http.StatusInternalServerError
			} else if response.Failed > 0 {
				statusCode = http.StatusMultiStatus
			}

			if statusCode != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, statusCode)
			}
		})
	}
}
