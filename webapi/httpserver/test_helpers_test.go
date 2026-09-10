package httpserver

import (
	"os"
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

// writeTestSigningKey writes a POOL signing key and returns its path.
// The key's content does not matter -- the server signs and verifies
// with the same file -- but its presence does: without it the
// user-header path cannot mint a token and declines to authenticate.
func writeTestSigningKey(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "POOL")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	if err := os.WriteFile(path, key, 0600); err != nil {
		t.Fatalf("writing the signing key: %v", err)
	}
	return path
}
