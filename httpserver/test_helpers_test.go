package httpserver

import (
	"path/filepath"
	"testing"

	"github.com/bbockelm/golang-htcondor/logging"
)

// newTestLogger creates a basic stderr logger for tests.
func newTestLogger(t *testing.T) *logging.Logger {
	t.Helper()
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	return logger
}

// newTestConfig returns a baseline Config with a temp DB path and dummy schedd address.
func newTestConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		ScheddName:   "test-schedd",
		ScheddAddr:   "127.0.0.1:9618",
		Logger:       newTestLogger(t),
		OAuth2DBPath: filepath.Join(t.TempDir(), "sessions.db"),
	}
}
