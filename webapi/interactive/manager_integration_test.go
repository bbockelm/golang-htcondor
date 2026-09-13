//go:build integration

package interactive

import (
	"context"
	"fmt"
	"os/exec"
	"os/user"
	"strings"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
)

// TestInteractiveSessionIntegration drives a named session end-to-end
// against a real HTCondor pool, and in particular answers the question
// the unit tests cannot: does the heartbeat actually keep a job alive?
//
// That question was open. The browser terminal's heartbeat had no test
// of any kind -- not a unit test, not an e2e one -- so "the touch lands
// in the directory the watchdog stats" was an assumption held up by a
// code comment. Here the watchdog runs with a 20s freshness window and
// the test then says nothing to the session for well over that: if the
// heartbeat is not landing, the job is gone when it looks again.
//
// Run with: go test -tags=integration -run TestInteractiveSessionIntegration -v ./interactive/
//
//nolint:gocyclo // Integration test with several discrete verification stages.
func TestInteractiveSessionIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not in PATH; skipping")
	}
	// Ask the harness where sshd and the sshd_config template are,
	// rather than listing paths here: a hardcoded list is how this test
	// came to skip on the machine it was written on.
	extraConfig, ok := htcondor.SSHToJobHarnessConfig()
	if !ok {
		t.Skip("sshd or condor_ssh_to_job_sshd_config_template not found; this host cannot run condor_ssh_to_job")
	}

	harness := htcondor.SetupCondorHarnessWithConfig(t, extraConfig)
	if err := harness.WaitForDaemons(); err != nil {
		t.Fatalf("Daemons failed to start: %v", err)
	}
	if err := harness.WaitForStartd(45 * time.Second); err != nil {
		t.Fatalf("Startd never reported in: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	collector := htcondor.NewCollector(harness.GetCollectorAddr())
	location, err := collector.LocateDaemon(ctx, "Schedd", "")
	if err != nil {
		t.Fatalf("Failed to locate schedd: %v", err)
	}
	schedd := htcondor.NewSchedd(location.Name, location.Address)

	me, err := user.Current()
	if err != nil {
		t.Fatalf("user.Current: %v", err)
	}
	caller := Caller{Actor: me.Username, Owner: me.Username}

	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}

	// A 20s freshness window with a 5s poll makes eviction observable
	// inside a test rather than in fifteen minutes. The heartbeat runs
	// at 3s, the same ratio the production defaults use.
	const freshnessSec = 20
	mgr, err := NewManager(Options{
		Schedd:            func() ScheddClient { return schedd },
		Logger:            logger,
		Watchdog:          WatchdogTiming{PollSec: 5, FreshnessSec: freshnessSec},
		HeartbeatInterval: 3 * time.Second,
		DefaultLease:      10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer mgr.Close()

	// ---- Stage 1: create and run a command -------------------------
	if _, err := mgr.Create(ctx, caller, CreateSpec{Name: "itest", MemoryMB: 256, DiskMB: 256}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer stopCancel()
		_, _ = mgr.Stop(stopCtx, caller, "itest")
	}()

	result, err := mgr.Exec(ctx, caller, "itest", ExecRequest{
		Command:      "echo hello-from-the-job",
		WaitForReady: 4 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if result.ExitCode != 0 {
		t.Errorf("exit code = %d, want 0 (stderr: %s)", result.ExitCode, result.Stderr)
	}
	if !strings.Contains(result.Stdout, "hello-from-the-job") {
		t.Errorf("stdout = %q, want the echoed text", result.Stdout)
	}

	// ---- Stage 2: the heartbeat file is where the watchdog looks ----
	//
	// The watchdog stats HeartbeatFile relative to its cwd; the
	// heartbeat command touches it under $_CONDOR_SCRATCH_DIR. Those
	// are only the same file if an SSH exec lands in the scratch dir,
	// which is exactly the assumption nothing had ever checked.
	probe, err := mgr.Exec(ctx, caller, "itest", ExecRequest{
		Command: fmt.Sprintf(`test -f "${_CONDOR_SCRATCH_DIR}/%s" && echo heartbeat-present; pwd; echo "scratch=${_CONDOR_SCRATCH_DIR}"`, HeartbeatFile),
	})
	if err != nil {
		t.Fatalf("probe Exec: %v", err)
	}
	if !strings.Contains(probe.Stdout, "heartbeat-present") {
		t.Fatalf("no %s in the scratch dir; the heartbeat is touching something else:\n%s", HeartbeatFile, probe.Stdout)
	}
	t.Logf("sandbox probe:\n%s", probe.Stdout)

	// And it keeps being refreshed: two readings of its mtime, taken
	// more than one heartbeat interval apart, must differ.
	mtimeCmd := fmt.Sprintf(`stat -c %%Y "${_CONDOR_SCRATCH_DIR}/%s" 2>/dev/null || stat -f %%m "${_CONDOR_SCRATCH_DIR}/%s"`, HeartbeatFile, HeartbeatFile)
	first, err := mgr.Exec(ctx, caller, "itest", ExecRequest{Command: mtimeCmd})
	if err != nil {
		t.Fatalf("mtime Exec: %v", err)
	}
	time.Sleep(8 * time.Second)
	second, err := mgr.Exec(ctx, caller, "itest", ExecRequest{Command: mtimeCmd})
	if err != nil {
		t.Fatalf("mtime Exec: %v", err)
	}
	if strings.TrimSpace(first.Stdout) == strings.TrimSpace(second.Stdout) {
		t.Errorf("heartbeat mtime did not advance (%s then %s); nothing is touching it",
			strings.TrimSpace(first.Stdout), strings.TrimSpace(second.Stdout))
	}

	// ---- Stage 3: survive silence past the freshness window --------
	//
	// This is the bug the browser bridge had: no keystrokes meant no
	// heartbeats, and the watchdog reclaimed a session its user was
	// still sitting in. Here nobody says anything for well over the
	// window, and the session must still be there.
	silence := time.Duration(freshnessSec)*time.Second + 25*time.Second
	t.Logf("saying nothing for %s (watchdog freshness is %ds)", silence, freshnessSec)
	time.Sleep(silence)

	survivor, err := mgr.Exec(ctx, caller, "itest", ExecRequest{
		Command:      "echo still-here",
		WaitForReady: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("session did not survive %s of silence -- the heartbeat is not keeping it alive: %v", silence, err)
	}
	if !strings.Contains(survivor.Stdout, "still-here") {
		t.Errorf("stdout after silence = %q", survivor.Stdout)
	}

	// ---- Stage 4: a command's exit status is its own ----------------
	failed, err := mgr.Exec(ctx, caller, "itest", ExecRequest{Command: "echo to-stderr >&2; exit 7"})
	if err != nil {
		t.Fatalf("Exec with a non-zero exit reported an error: %v", err)
	}
	if failed.ExitCode != 7 {
		t.Errorf("exit code = %d, want 7", failed.ExitCode)
	}
	if !strings.Contains(failed.Stderr, "to-stderr") {
		t.Errorf("stderr = %q, want the text written to fd 2", failed.Stderr)
	}

	// ---- Stage 5: each exec is a fresh shell -----------------------
	//
	// Documented in the tool description, so it had better be true: a
	// model told that state persists would write two calls where it
	// needs one.
	if _, err := mgr.Exec(ctx, caller, "itest", ExecRequest{Command: "mkdir -p statedir && cd statedir"}); err != nil {
		t.Fatalf("Exec: %v", err)
	}
	cwd, err := mgr.Exec(ctx, caller, "itest", ExecRequest{Command: "basename \"$(pwd)\""})
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if strings.TrimSpace(cwd.Stdout) == "statedir" {
		t.Error("cwd persisted between execs; the tool description says it does not")
	}
	// Files DO persist, which is the half that makes a session useful.
	persisted, err := mgr.Exec(ctx, caller, "itest", ExecRequest{Command: "test -d statedir && echo dir-still-there"})
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if !strings.Contains(persisted.Stdout, "dir-still-there") {
		t.Error("a directory created by an earlier exec is gone; the sandbox is not shared between calls")
	}

	// ---- Stage 6: stop releases the slot ---------------------------
	if _, err := mgr.Stop(ctx, caller, "itest"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	waitForSessionGone(t, ctx, mgr, caller, "itest", 90*time.Second)

	// ---- Stage 7: nothing heartbeating means the slot comes back ---
	//
	// The other half of the contract. A session whose manager died
	// must not hold its slot forever: the watchdog evicts it once the
	// heartbeat goes stale, which is what bounds the damage from a
	// crashed API server.
	if _, err := mgr.Create(ctx, caller, CreateSpec{Name: "abandoned", MemoryMB: 256, DiskMB: 256}); err != nil {
		t.Fatalf("Create(abandoned): %v", err)
	}
	if _, err := mgr.Exec(ctx, caller, "abandoned", ExecRequest{
		Command:      "true",
		WaitForReady: 4 * time.Minute,
	}); err != nil {
		t.Fatalf("Exec(abandoned): %v", err)
	}

	// Close stops the heartbeats without removing anything -- the same
	// thing a crash does, minus the crash.
	mgr.Close()

	watcher, err := NewManager(Options{
		Schedd:       func() ScheddClient { return schedd },
		Logger:       logger,
		DefaultLease: time.Minute,
	})
	if err != nil {
		t.Fatalf("NewManager(watcher): %v", err)
	}
	defer watcher.Close()
	waitForSessionGone(t, ctx, watcher, caller, "abandoned",
		time.Duration(freshnessSec)*time.Second+90*time.Second)
}

// waitForSessionGone polls until the named session leaves the caller's
// live sessions. Polling the condition rather than sleeping a fixed
// interval keeps the common case fast and the loaded case correct.
func waitForSessionGone(t *testing.T, ctx context.Context, mgr *Manager, caller Caller, name string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		infos, err := mgr.List(ctx, caller)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		found := false
		for _, info := range infos {
			if info.Name == name {
				found = true
				break
			}
		}
		if !found {
			return
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("session %q was still live after %s", name, timeout)
}
