package httpserver

import (
	"testing"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
)

// TestServerCreation tests basic server creation
func TestServerCreation(t *testing.T) {
	// Create a logger for the test
	logger, err := logging.New(&logging.Config{
		OutputPath:   "stderr",
		MinVerbosity: logging.VerbosityError,
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Create a simple server instance with minimal config
	s := &Server{
		schedd: htcondor.NewSchedd("test-schedd", "127.0.0.1:9618"),
		logger: logger,
	}

	// Test that the schedd is set correctly
	if s.schedd == nil {
		t.Error("Server schedd is nil")
	}

	if s.schedd.Address() != "127.0.0.1:9618" {
		t.Errorf("Schedd address = %v, want 127.0.0.1:9618", s.schedd.Address())
	}

	if s.logger == nil {
		t.Error("Server logger is nil")
	}
}

// TestServerWithTokenCache tests server with token cache initialization
func TestServerWithTokenCache(t *testing.T) {
	logger, err := logging.New(&logging.Config{
		OutputPath:   "stderr",
		MinVerbosity: logging.VerbosityError,
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	s := &Server{
		schedd:     htcondor.NewSchedd("test-schedd", "127.0.0.1:9618"),
		logger:     logger,
		tokenCache: NewTokenCache(),
	}

	if s.tokenCache == nil {
		t.Error("Token cache is nil")
	}
}
