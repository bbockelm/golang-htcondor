//go:build integration

package htcondor

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestMasterKeepAliveAndReady launches a tiny daemon under condor_master that
// uses the htcondor Master helper to emit DC_CHILDALIVE and DC_SET_READY. The
// test asserts the master log contains evidence of both commands when
// condor_master is available.
func TestMasterKeepAliveAndReady(t *testing.T) {
	// Build the helper daemon binary
	daemonDir := t.TempDir()
	daemonSrc := filepath.Join(daemonDir, "daemon_main.go")
	daemonBin := filepath.Join(daemonDir, "testdaemon")

	if err := os.WriteFile(daemonSrc, []byte(daemonMainSource), 0600); err != nil {
		t.Fatalf("failed to write daemon source: %v", err)
	}

	buildCmd := exec.Command("go", "build", "-o", daemonBin, daemonSrc)
	buildCmd.Env = append(os.Environ(), "GO111MODULE=on")
	buildCmd.Dir = projectRoot(t)
	if output, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build daemon: %v, output: %s", err, string(output))
	}

	extraConfig := fmt.Sprintf(`
DAEMON_LIST = MASTER, COLLECTOR, SCHEDD, NEGOTIATOR, STARTD, TESTDAEMON
TESTDAEMON = %s
MASTER_DEBUG = D_FULLDEBUG D_COMMAND
MASTER_LOG = $(LOG)/MasterLog
	ALLOW_DAEMON = *
	ALLOW_ADMINISTRATOR = *
`, daemonBin)

	harness := SetupCondorHarnessWithConfig(t, extraConfig)

	masterLogPath := filepath.Join(harness.GetLogDir(), "MasterLog")

	// Allow time for master to spawn the custom daemon and for it to send messages
	require.Eventually(t, func() bool {
		data, err := os.ReadFile(masterLogPath) //nolint:gosec // test log read
		if err != nil {
			return false
		}
		log := string(data)
		hasAlive := strings.Contains(log, "DC_CHILDALIVE") || strings.Contains(log, "60008")
		hasReady := strings.Contains(log, "SET_READY") || strings.Contains(log, "60043") || strings.Contains(log, "ready state")
		return hasAlive && hasReady
	}, 30*time.Second, 1*time.Second, "master log did not show keepalive and ready commands")
}

// daemonMainSource is the tiny daemon that emits keepalive and ready signals.
// It relies on CONDOR_INHERIT provided by condor_master when launched as a managed daemon.
const daemonMainSource = `package main

import (
    "context"
    "log"
    "time"

    htcondor "github.com/bbockelm/golang-htcondor"
)

func main() {
    m, err := htcondor.MasterFromEnv()
    if err != nil {
        log.Fatalf("master env missing: %v", err)
    }

    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    if err := m.SendReady(ctx, nil); err != nil {
        log.Fatalf("send ready failed: %v", err)
    }

    if err := m.SendKeepAlive(ctx, &htcondor.KeepAliveOptions{HangTimeout: 2 * time.Minute}); err != nil {
        log.Fatalf("keepalive failed: %v", err)
    }

    time.Sleep(500 * time.Millisecond)
    _ = m.SendKeepAlive(ctx, &htcondor.KeepAliveOptions{HangTimeout: 2 * time.Minute})

    // Give the master a moment to log the commands before exiting
    time.Sleep(500 * time.Millisecond)
}
`

// projectRoot returns the repository root directory for building the helper binary.
func projectRoot(t *testing.T) string {
	t.Helper()
	cwd, err := os.Getwd()
	require.NoError(t, err)
	return cwd
}
