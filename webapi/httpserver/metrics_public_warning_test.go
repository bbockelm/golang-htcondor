package httpserver

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/logging"
)

// An open /metrics is announced at startup, and only when it is open.
func TestMetricsPublicIsWarnedAtStartup(t *testing.T) {
	for _, public := range []bool{true, false} {
		logPath := filepath.Join(t.TempDir(), "server.log")
		logger, err := logging.New(&logging.Config{OutputPath: logPath, DefaultLevel: logging.VerbosityWarn, SkipGlobalInstall: true})
		if err != nil {
			t.Fatalf("logger: %v", err)
		}
		cfg := newTestConfig(t)
		cfg.Logger = logger
		cfg.MetricsPublic = public
		if _, err := NewServer(cfg); err != nil {
			t.Fatalf("NewServer: %v", err)
		}

		out, err := os.ReadFile(logPath) //nolint:gosec // G304: the test's own temp file
		if err != nil {
			t.Fatalf("reading the log: %v", err)
		}
		warned := strings.Contains(string(out), "HTTP_API_METRICS_PUBLIC")
		if warned != public {
			t.Errorf("MetricsPublic=%v: warned=%v, want %v; log:\n%s", public, warned, public, out)
		}
	}
}
