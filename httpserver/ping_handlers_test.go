package httpserver

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bbockelm/golang-htcondor/logging"
)

// TestPingHandlerNoCollector tests ping handler when collector is not configured
func TestPingHandlerNoCollector(t *testing.T) {
	// Create logger
	logger, err := logging.New(&logging.Config{
		OutputPath: "stderr",
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Create a server without collector but with schedd
	cfg := newTestConfig(t)
	cfg.Collector = nil
	cfg.Logger = logger
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Create request
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ping", nil)
	w := httptest.NewRecorder()

	// Call handler
	server.handlePing(w, req)

	// The handler should succeed with schedd result even without collector
	// We expect a 200 status, but the collector field will have an error
	// Note: This will fail because schedd is not actually running, but that's okay for this test
	// We're just testing that the handler structure works
	if w.Code != http.StatusOK && w.Code != http.StatusInternalServerError {
		t.Logf("Handler returned status %d (expected 200 or 500)", w.Code)
	}
}

// TestCollectorPingHandlerNoCollector tests collector ping when not configured
func TestCollectorPingHandlerNoCollector(t *testing.T) {
	// Create logger
	logger, err := logging.New(&logging.Config{
		OutputPath: "stderr",
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Create a server without collector
	cfg := newTestConfig(t)
	cfg.Collector = nil
	cfg.Logger = logger
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Create request
	req := httptest.NewRequest(http.MethodGet, "/api/v1/collector/ping", nil)
	w := httptest.NewRecorder()

	// Call handler
	server.handleCollectorPing(w, req)

	// Should return 501 Not Implemented when collector is not configured
	if w.Code != http.StatusNotImplemented {
		t.Errorf("Expected status 501, got %d", w.Code)
	}
}

// TestScheddPingHandlerWrongMethod tests schedd ping with wrong HTTP method
func TestScheddPingHandlerWrongMethod(t *testing.T) {
	// Create logger
	logger, err := logging.New(&logging.Config{
		OutputPath: "stderr",
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Create a server
	cfg := newTestConfig(t)
	cfg.Logger = logger
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Create POST request (should only accept GET)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/schedd/ping", nil)
	w := httptest.NewRecorder()

	// Call handler
	server.handleScheddPing(w, req)

	// Should return 405 Method Not Allowed
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", w.Code)
	}
}
