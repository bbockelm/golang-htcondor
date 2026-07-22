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
// HTCondor), not 0600 -- even under a restrictive umask. A daemon commonly inherits umask
// 077; os.OpenFile's mode is masked by it, so without the explicit fchmod (forceLogPerm)
// the file would come out 0600. Setting umask 077 here makes this a real regression for
// the umask masking, not just the OpenFile mode argument.
func TestLogFileMode0644(t *testing.T) {
	old := syscall.Umask(0o077)
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
		t.Fatalf("log file mode = %o under umask 077, want 0644 (explicit chmod should defeat umask)", perm)
	}
}

// TestLogRotationMode0644 verifies the freshly-created log after a rotation is also 0644
// under a restrictive umask (the rotate path recreates the file in production).
func TestLogRotationMode0644(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)

	path := filepath.Join(t.TempDir(), "rot.log")
	l, err := New(&Config{
		OutputPath:        path,
		SkipGlobalInstall: true,
		DefaultLevel:      VerbosityInfo,
		MaxLogSize:        200, // tiny, so a few lines trigger rotation
		MaxNumLogs:        2,
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		l.Info(DestinationGeneral, "a message long enough to push the log past its rotation size")
	}
	if _, err := os.Stat(path + ".old"); err != nil {
		t.Fatalf("expected a rotated .old log: %v", err)
	}
	info, err := os.Stat(path) // the post-rotation current log
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0644 {
		t.Fatalf("post-rotation log mode = %o under umask 077, want 0644", perm)
	}
}
