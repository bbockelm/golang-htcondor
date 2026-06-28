package htcondor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// buildTestDaemon compiles internal/testdaemon to a temp binary and returns its
// path.
func buildTestDaemon(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "testgodaemon")
	cmd := exec.CommandContext(context.Background(), "go", "build", "-o", bin, "./internal/testdaemon") //nolint:gosec // G204: building a fixed test fixture
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("building test daemon: %v", err)
	}
	return bin
}

// waitForLog polls path until it contains want or the deadline passes.
func waitForLog(t *testing.T, path, want string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(path) //nolint:gosec // G304: test reads its own log file
		if err == nil && strings.Contains(string(b), want) {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

// TestGoDaemonUnderCondorMaster brings up a minimal framework daemon as a managed
// child of a real condor_master and exercises the lifecycle: it registers with
// the master (DC_SET_READY), adopts the inherited shared-port listener, reloads
// on condor_reconfig (SIGHUP), and shuts down on condor_off (SIGTERM).
func TestGoDaemonUnderCondorMaster(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping condor_master integration test in -short mode")
	}
	bin := buildTestDaemon(t)

	// Add our daemon to the pool the harness configures.
	extra := fmt.Sprintf(`
TESTGODAEMON = %s
TESTGODAEMON_LOG = $(LOG)/TestGoDaemonLog
TESTGODAEMON_ARGS =
DAEMON_LIST = $(DAEMON_LIST) TESTGODAEMON
# Mark it DaemonCore so the master gives it a command port + shared-port endpoint.
DC_DAEMON_LIST = +TESTGODAEMON
`, bin)

	h := SetupCondorHarnessWithConfig(t, extra)
	defer h.Shutdown()

	daemonLog := filepath.Join(h.GetLogDir(), "TestGoDaemonLog")

	// 1. Launched under condor_master and signaled readiness.
	if !waitForLog(t, daemonLog, "detected condor_master parent", 30*time.Second) {
		dumpDaemonLog(t, daemonLog)
		t.Fatal("test daemon did not detect condor_master")
	}
	if !waitForLog(t, daemonLog, "DC_SET_READY sent", 30*time.Second) {
		dumpDaemonLog(t, daemonLog)
		t.Fatal("test daemon did not send DC_SET_READY")
	}

	// 2. Shared port: it adopted the inherited shared-port listener.
	if !waitForLog(t, daemonLog, "accepting shared-port forwarded connections", 10*time.Second) {
		dumpDaemonLog(t, daemonLog)
		t.Fatal("test daemon did not adopt the shared-port listener")
	}

	// 3. Reconfig: condor_reconfig makes the master SIGHUP its children.
	runCondorTool(t, h, "condor_reconfig")
	if !waitForLog(t, daemonLog, "received SIGHUP; reloading configuration", 20*time.Second) {
		dumpDaemonLog(t, daemonLog)
		t.Fatal("test daemon did not reconfigure on condor_reconfig")
	}

	// 4. Off: condor_off -subsystem makes the master stop (SIGTERM) the daemon.
	runCondorTool(t, h, "condor_off", "-subsystem", "TESTGODAEMON")
	if !waitForLog(t, daemonLog, "shutting down", 20*time.Second) {
		dumpDaemonLog(t, daemonLog)
		t.Fatal("test daemon did not shut down on condor_off")
	}
}

// runCondorTool runs an admin tool against the harness pool, using its config.
func runCondorTool(t *testing.T, h *CondorTestHarness, tool string, args ...string) {
	t.Helper()
	path, err := exec.LookPath(tool)
	if err != nil {
		t.Skipf("%s not found in PATH", tool)
	}
	cmd := exec.CommandContext(context.Background(), path, args...) //nolint:gosec // G204: test invoking a condor admin tool
	cmd.Env = append(os.Environ(), "CONDOR_CONFIG="+h.GetConfigFile())
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("%s %s output: %s", tool, strings.Join(args, " "), out)
		t.Fatalf("%s failed: %v", tool, err)
	}
}

func dumpDaemonLog(t *testing.T, path string) {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // G304: test reads its own log file
	if err == nil {
		t.Logf("=== %s ===\n%s", path, b)
	} else {
		t.Logf("could not read %s: %v", path, err)
	}
}
