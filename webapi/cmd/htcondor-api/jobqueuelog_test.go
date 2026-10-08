package main

import (
	"os"
	"path/filepath"
	"testing"

	"strings"

	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/logging"
)

// cfgWith builds a config holding exactly the knobs given.
func cfgWith(t *testing.T, knobs map[string]string) *config.Config {
	t.Helper()
	cfg := config.NewEmpty()
	for name, value := range knobs {
		cfg.Set(name, value)
	}
	return cfg
}

func TestJobQueueLogUsesTheExplicitKnob(t *testing.T) {
	queue := filepath.Join(t.TempDir(), "job_queue.log")
	if err := os.WriteFile(queue, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := cfgWith(t, map[string]string{"HTTP_API_JOB_QUEUE_LOG": queue})

	if got := resolveJobQueueLog(cfg, testLogger(t)); got != queue {
		t.Errorf("resolveJobQueueLog = %q, want %q", got, queue)
	}
}

// The regression this whole change is about: the field was never set,
// so the mirror was nil and /api/v1/jobs/watch answered 503 everywhere.
func TestJobQueueLogFallsBackToTheScheddKnob(t *testing.T) {
	queue := filepath.Join(t.TempDir(), "job_queue.log")
	if err := os.WriteFile(queue, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := cfgWith(t, map[string]string{"JOB_QUEUE_LOG": queue})

	if got := resolveJobQueueLog(cfg, testLogger(t)); got != queue {
		t.Errorf("resolveJobQueueLog = %q, want the schedd's own path %q", got, queue)
	}
}

// An API server in its own container has no job_queue.log to tail.
// That is the deployment, not a fault in it, and it must not make the
// server claim a stream it cannot serve.
func TestJobQueueLogIgnoresAPathThatIsNotThere(t *testing.T) {
	cfg := cfgWith(t, map[string]string{"JOB_QUEUE_LOG": filepath.Join(t.TempDir(), "absent.log")})

	if got := resolveJobQueueLog(cfg, testLogger(t)); got != "" {
		t.Errorf("resolveJobQueueLog = %q, want \"\"", got)
	}
}

// Switching the stream off deliberately and naming a file that is not
// there both leave it off, so the return value cannot tell them
// apart. What distinguishes them is whether the operator is told
// something is wrong -- and being warned about a choice you made is
// how a log stops being read.
func TestSwitchingTheStreamOffIsNotAnError(t *testing.T) {
	queue := filepath.Join(t.TempDir(), "job_queue.log")
	if err := os.WriteFile(queue, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	off, offLog := resolveWithCapturedLog(t, map[string]string{
		"HTTP_API_JOB_QUEUE_LOG": "none",
		"JOB_QUEUE_LOG":          queue,
	})
	missing, missingLog := resolveWithCapturedLog(t, map[string]string{
		"HTTP_API_JOB_QUEUE_LOG": filepath.Join(t.TempDir(), "absent.log"),
		"JOB_QUEUE_LOG":          queue,
	})

	if off != "" || missing != "" {
		t.Fatalf("both should leave the stream off, got %q and %q", off, missing)
	}
	if strings.Contains(strings.ToLower(offLog), "warn") {
		t.Errorf("switching the stream off warned the operator about their own choice: %s", offLog)
	}
	if !strings.Contains(strings.ToLower(missingLog), "warn") {
		t.Errorf("a named file that cannot be read should be reported, got: %s", missingLog)
	}
}

// resolveWithCapturedLog runs the resolver against a logger writing to
// a file, and returns what it chose along with what it said.
func resolveWithCapturedLog(t *testing.T, knobs map[string]string) (string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "api.log")
	logger, err := logging.New(&logging.Config{OutputPath: path, DefaultLevel: logging.VerbosityDebug, SkipGlobalInstall: true})
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	chosen := resolveJobQueueLog(cfgWith(t, knobs), logger)
	written, err := os.ReadFile(path) // #nosec G304 -- a path this test just made
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	return chosen, string(written)
}

// Named explicitly but absent is an operator error, not the ordinary
// case, so it must not silently fall back to the schedd's path.
func TestAnExplicitPathThatIsMissingDoesNotFallBack(t *testing.T) {
	queue := filepath.Join(t.TempDir(), "job_queue.log")
	if err := os.WriteFile(queue, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := cfgWith(t, map[string]string{
		"HTTP_API_JOB_QUEUE_LOG": filepath.Join(t.TempDir(), "absent.log"),
		"JOB_QUEUE_LOG":          queue,
	})

	if got := resolveJobQueueLog(cfg, testLogger(t)); got != "" {
		t.Errorf("resolveJobQueueLog = %q, want \"\"", got)
	}
}
