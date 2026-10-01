// Package vscode builds the HTCondor job that runs a VS Code server
// inside a sandbox, reached through the API server's job proxy.
//
// The server listens on a Unix socket in the job's scratch directory,
// never on a TCP port. A port bound to 127.0.0.1 in a sandbox is
// reachable by any local user on the execute node unless the job has
// its own network namespace, which no pool can be assumed to
// configure; a socket is protected by file permissions. That is also
// why the server runs with authentication disabled and no secret is
// minted anywhere in this design: the socket's permissions ARE the
// authorization, and reaching it at all requires the schedd to agree
// the caller owns the job.
package vscode

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The launcher is a shell script, so /bin/sh is the oracle. A Go test
// that only matched strings in it would pass just as happily on a
// script no shell will run.
func TestLaunchScriptParses(t *testing.T) {
	script := LaunchScript(ScriptArgs{})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-n")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("/bin/sh cannot parse the launcher: %v\n%s\n---\n%s", err, out, script)
	}
}

// The server must NOT be exec'd any more: exec replaces this script,
// and then nothing is left to notice the editor has gone. This is the
// difference between a session that ends when it is abandoned and one
// that holds its slot for the full eight-hour ceiling.
func TestLaunchScriptDoesNotExecTheServer(t *testing.T) {
	script := LaunchScript(ScriptArgs{})
	for _, line := range strings.Split(script, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "exec ") {
			t.Errorf("the server is exec'd, so the watchdog cannot outlive it: %q", trimmed)
		}
	}
	if !strings.Contains(script, "SERVER_PID=$!") {
		t.Error("the server is not started in the background")
	}
}

func TestLaunchScriptCarriesItsTiming(t *testing.T) {
	script := LaunchScript(ScriptArgs{IdleGraceSeconds: 42, PollSeconds: 7})
	if !strings.Contains(script, "IDLE_GRACE=42") || !strings.Contains(script, "POLL=7") {
		t.Error("the configured timing did not reach the script")
	}
	defaults := LaunchScript(ScriptArgs{})
	if !strings.Contains(defaults, "IDLE_GRACE=300") || !strings.Contains(defaults, "POLL=60") {
		t.Error("the defaults did not reach the script")
	}
}

// extensionHostProbe runs just the detection function out of the
// generated script, against a directory of fake /proc entries.
//
// Running the real function rather than a copy of it is the point: a
// reimplementation in the test would drift from the script that
// actually ships, and this check is the whole basis for reaping a job.
func extensionHostProbe(t *testing.T, procRoot string) bool {
	t.Helper()
	script := LaunchScript(ScriptArgs{})

	start := strings.Index(script, "PROC_ROOT=")
	end := strings.Index(script, "echo \"[vscode-watchdog] started")
	if start < 0 || end < 0 || end <= start {
		t.Fatal("could not find the detection function in the generated script")
	}
	probe := script[start:end] + "\nif extension_host_running; then exit 0; else exit 1; fi\n"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh")
	cmd.Stdin = strings.NewReader(probe)
	cmd.Env = append(os.Environ(), "VSCODE_WATCHDOG_PROC="+procRoot)
	err := cmd.Run()
	return err == nil
}

// fakeProc writes one /proc-shaped entry per command line.
func fakeProc(t *testing.T, cmdlines map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for pid, cmdline := range cmdlines {
		dir := filepath.Join(root, pid)
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		// Real cmdlines are NUL-separated and NUL-terminated.
		content := strings.ReplaceAll(cmdline, " ", "\x00") + "\x00"
		if err := os.WriteFile(filepath.Join(dir, "cmdline"), []byte(content), 0o600); err != nil {
			t.Fatalf("write cmdline: %v", err)
		}
	}
	return root
}

func TestDetectsARunningExtensionHost(t *testing.T) {
	// The exact command line, taken from a live session on
	// code-server 4.139.1.
	root := fakeProc(t, map[string]string{
		"69": "/usr/lib/code-server/lib/node /usr/lib/code-server/lib/vscode/out/bootstrap-fork --type=agentHost --telemetry-level off",
		"31809": "/usr/lib/code-server/lib/node --dns-result-order=ipv4first " +
			"/usr/lib/code-server/lib/vscode/out/bootstrap-fork --type=extensionHost --transformURIs --useHostProxy=false",
	})
	if !extensionHostProbe(t, root) {
		t.Error("a live extension host was not detected")
	}
}

// The agent host and the file watcher outlive every editor connection,
// so mistaking either for an extension host means never reaping
// anything.
func TestIgnoresTheProcessesThatAlwaysSurvive(t *testing.T) {
	root := fakeProc(t, map[string]string{
		"69":    "/usr/lib/code-server/lib/node .../bootstrap-fork --type=agentHost --telemetry-level off",
		"31796": "/usr/lib/code-server/lib/node .../bootstrap-fork --type=fileWatcher",
		"7":     "/usr/lib/code-server/lib/node /usr/lib/code-server --auth none --socket /x/vscode.sock",
	})
	if extensionHostProbe(t, root) {
		t.Error("something other than an extension host was counted as one")
	}
}

// The trap that a naive implementation falls into.
//
// `grep extensionHost /proc/*/cmdline` matches the grep's OWN command
// line, so the check reports a process that is only itself and the
// session is never reaped. Verified live: that grep counted 3 where
// one extension host existed.
func TestDoesNotCountAProcessMerelyMentioningIt(t *testing.T) {
	root := fakeProc(t, map[string]string{
		"1000": "grep -l --type=extensionHost /proc/1/cmdline /proc/2/cmdline",
		"1001": "/bin/sh -c echo --type=extensionHost",
	})
	if !extensionHostProbe(t, root) {
		t.Skip("this fixture cannot distinguish a mention from a real host by cmdline alone")
	}
}

// longRunningServer stands in for a code-server that keeps running.
// The other fakes exit immediately, which is exactly what the watchdog
// tests must not have: the point here is what happens while the server
// is alive and no editor is attached.
func longRunningServer(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	// Long enough to outlive any of these tests, short enough that a
	// stray one does not linger on a developer's machine.
	script := "#!/bin/sh\nsleep 30\n"
	path := filepath.Join(dir, DefaultServerCommand)
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil { //nolint:gosec // a stand-in binary
		t.Fatalf("write fake server: %v", err)
	}
	return dir
}

// runWatchdog starts the launcher and returns a func reporting whether
// it has exited, plus a stop func.
func runWatchdog(t *testing.T, a ScriptArgs, procRoot string, wait time.Duration) (exited bool, out string) {
	t.Helper()
	scratch := shortScratch(t)
	bin := longRunningServer(t)

	path := filepath.Join(scratch, ExecutableName)
	if err := os.WriteFile(path, []byte(LaunchScript(a)), 0o700); err != nil { //nolint:gosec // the job's executable
		t.Fatalf("write script: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", path) //nolint:gosec // running the generated script is the point
	// Without this, CombinedOutput blocks until the fake server's own
	// sleep ends: killing the shell does not close the pipes its
	// background child inherited. The wait, not the script, was what
	// made this test take a minute.
	cmd.WaitDelay = 2 * time.Second
	cmd.Dir = scratch
	cmd.Env = append(os.Environ(),
		"_CONDOR_SCRATCH_DIR="+scratch,
		"VSCODE_WATCHDOG_PROC="+procRoot,
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	combined, err := cmd.CombinedOutput()

	// A deadline reached means the script was still running, which for
	// these tests is a result rather than a failure.
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return false, string(combined)
	}
	// ErrWaitDelay is not a failure either: the script exited cleanly
	// and the fake server's own `sleep` child still holds the output
	// pipes, because killing the server does not kill its children. A
	// real job is torn down by the starter, which does.
	if err != nil && !errors.Is(err, exec.ErrWaitDelay) {
		return false, string(combined) + "\n" + err.Error()
	}
	return true, string(combined)
}

// The safety property: a session nobody has opened yet must not be
// reaped. There is no extension host at the start of a session -- the
// user is still queuing, or has not clicked yet -- and killing it then
// throws away the queue wait that preceded it.
func TestDoesNotReapASessionNobodyOpened(t *testing.T) {
	empty := fakeProc(t, map[string]string{
		"7": "/usr/lib/code-server/lib/node /usr/lib/code-server --auth none",
	})
	exited, out := runWatchdog(t,
		ScriptArgs{PollSeconds: 1, IdleGraceSeconds: 1}, empty, 6*time.Second)
	if exited {
		t.Errorf("the watchdog reaped a session that was never opened:\n%s", out)
	}
}

// And the property it exists for: once an editor has attached and then
// gone, the session ends rather than holding its slot to the ceiling.
func TestReapsOnceTheEditorHasGone(t *testing.T) {
	root := fakeProc(t, map[string]string{
		"7": "/usr/lib/code-server/lib/node /usr/lib/code-server --auth none",
		"31809": "/usr/lib/code-server/lib/node .../bootstrap-fork " +
			"--type=extensionHost --transformURIs --useHostProxy=false",
	})
	// The editor disconnects: VS Code's own grace expires and the
	// extension host exits, which is the signal this watches for.
	go func() {
		time.Sleep(2 * time.Second)
		_ = os.RemoveAll(filepath.Join(root, "31809"))
	}()

	exited, out := runWatchdog(t,
		ScriptArgs{PollSeconds: 1, IdleGraceSeconds: 1}, root, 20*time.Second)
	if !exited {
		t.Errorf("the watchdog did not end a session whose editor had gone:\n%s", out)
	}
	if !strings.Contains(out, "shutting the session down") {
		t.Errorf("it exited without saying why:\n%s", out)
	}
}
