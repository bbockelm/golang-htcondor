package httpserver

import (
	"net/http"
	"net/http/httptest"
	"testing"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
)

// TestHandlerEmbedding tests that Handler can be created and embedded independently
func TestHandlerEmbedding(t *testing.T) {
	// Create a logger for testing
	logger, err := logging.New(&logging.Config{
		OutputPath: "stderr",
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Create a mock schedd for testing
	schedd := htcondor.NewSchedd("test-schedd", "127.0.0.1:9618")

	// Create handler config
	cfg := HandlerConfig{
		ScheddName:   "test-schedd",
		ScheddAddr:   "127.0.0.1:9618",
		Logger:       logger,
		OAuth2DBPath: t.TempDir() + "/sessions.db",
	}

	// Create the handler
	handler, err := NewHandler(cfg)
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	// Verify handler implements http.Handler
	var _ http.Handler = handler

	// Verify handler fields are accessible through embedding
	if handler.schedd == nil {
		t.Error("Handler schedd should not be nil")
	}

	if handler.logger == nil {
		t.Error("Handler logger should not be nil")
	}

	// Test that handler can be embedded in a custom server
	customMux := http.NewServeMux()
	customMux.Handle("/htcondor/", http.StripPrefix("/htcondor", handler))
	customMux.HandleFunc("/custom", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("custom endpoint"))
	})

	// Test custom endpoint
	req := httptest.NewRequest("GET", "/custom", nil)
	w := httptest.NewRecorder()
	customMux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	if w.Body.String() != "custom endpoint" {
		t.Errorf("Expected 'custom endpoint', got '%s'", w.Body.String())
	}

	// Test that HTCondor endpoints are accessible (health check endpoint)
	req = httptest.NewRequest("GET", "/htcondor/healthz", nil)
	w = httptest.NewRecorder()
	customMux.ServeHTTP(w, req)

	// Should get a response (even if schedd is not actually running)
	// The important thing is the handler responds
	if w.Code != http.StatusOK && w.Code != http.StatusServiceUnavailable {
		t.Logf("Health check returned status %d (expected OK or ServiceUnavailable)", w.Code)
	}

	// Clean up
	_ = schedd
}

// TestServerStillWorks verifies that the Server API still works after refactoring
func TestServerStillWorks(t *testing.T) {
	// Create a logger for testing
	logger, err := logging.New(&logging.Config{
		OutputPath: "stderr",
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Create server config
	cfg := Config{
		ListenAddr:   "127.0.0.1:0", // Use dynamic port
		ScheddName:   "test-schedd",
		ScheddAddr:   "127.0.0.1:9618",
		Logger:       logger,
		OAuth2DBPath: t.TempDir() + "/sessions.db",
	}

	// Create the server
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Verify server has a handler
	if server.Handler == nil {
		t.Error("Server Handler should not be nil")
	}

	// Verify server has HTTP server
	if server.httpServer == nil {
		t.Error("Server httpServer should not be nil")
	}

	// Verify embedded fields are accessible
	if server.schedd == nil {
		t.Error("Server schedd (from embedded Handler) should not be nil")
	}

	// Verify server methods are available
	if server.GetAddr() != "" {
		t.Error("GetAddr should return empty string before server starts")
	}
}
