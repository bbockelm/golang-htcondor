package logging

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/bbockelm/golang-htcondor/config"
)

// newTestConfig builds a config from the given param map (nil for empty).
func newTestConfig(t *testing.T, params map[string]string) *config.Config {
	t.Helper()
	var b strings.Builder
	for k, v := range params {
		b.WriteString(k)
		b.WriteString(" = ")
		b.WriteString(v)
		b.WriteString("\n")
	}
	cfg, err := config.NewFromReader(strings.NewReader(b.String()))
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	return cfg
}

// readLog returns the contents of a logger's file output.
func readLog(t *testing.T, path string) string {
	t.Helper()
	//nolint:gosec // G304: test-only, path is a t.TempDir() file
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	return string(b)
}

// TestApplyLevelsLive verifies condor_reconfig's mechanism: a destination suppressed at
// startup begins logging after ApplyLevels raises its level, on the already-constructed
// logger, with no handler rebuild.
func TestApplyLevelsLive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.log")
	l, err := New(&Config{
		OutputPath:        path,
		SkipGlobalInstall: true,
		DestinationLevels: map[Destination]Verbosity{DestinationCedar: VerbosityWarn},
		DefaultLevel:      VerbosityInfo,
	})
	if err != nil {
		t.Fatal(err)
	}

	l.Info(DestinationCedar, "cedar-before") // Info < Warn config -> suppressed
	if got := readLog(t, path); strings.Contains(got, "cedar-before") {
		t.Fatalf("cedar Info should be suppressed at Warn, got: %q", got)
	}

	// Reconfig raises cedar to Debug (like COLLECTOR_DEBUG = cedar:debug).
	l.ApplyLevels(map[Destination]Verbosity{DestinationCedar: VerbosityDebug}, VerbosityInfo)

	l.Info(DestinationCedar, "cedar-after")
	if got := readLog(t, path); !strings.Contains(got, "cedar-after") {
		t.Fatalf("cedar Info should log after ApplyLevels raised the level, got: %q", got)
	}
}

// TestParseDestinationLevels covers the shared <DAEMON>_DEBUG parser used by both startup
// and reconfig, including the cedar=Warn default and an explicit override.
func TestParseDestinationLevels(t *testing.T) {
	cfg := newTestConfig(t, map[string]string{
		"COLLECTOR_DEBUG": "cedar:debug, http:info",
	})
	levels := ParseDestinationLevels("COLLECTOR", cfg)
	if levels[DestinationCedar] != VerbosityDebug {
		t.Errorf("cedar = %v, want Debug (explicit override)", levels[DestinationCedar])
	}
	if levels[DestinationHTTP] != VerbosityInfo {
		t.Errorf("http = %v, want Info", levels[DestinationHTTP])
	}

	// With no <DAEMON>_DEBUG, cedar still defaults to Warn (session-ID/chatter suppression).
	bare := ParseDestinationLevels("COLLECTOR", newTestConfig(t, nil))
	if bare[DestinationCedar] != VerbosityWarn {
		t.Errorf("default cedar = %v, want Warn", bare[DestinationCedar])
	}
}

// TestLogFileMode0644 verifies daemon logs are created world-readable (matching C++
// HTCondor), not 0600. Umask is cleared so the mode is deterministic.
func TestLogFileMode0644(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)

	path := filepath.Join(t.TempDir(), "mode.log")
	l, err := New(&Config{OutputPath: path, SkipGlobalInstall: true, DefaultLevel: VerbosityInfo})
	if err != nil {
		t.Fatal(err)
	}
	l.Info(DestinationGeneral, "hi")

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0644 {
		t.Fatalf("log file mode = %o, want 0644", perm)
	}
}
