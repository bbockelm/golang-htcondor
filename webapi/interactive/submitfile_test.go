package interactive

import (
	"fmt"
	"strings"
	"testing"
)

func TestBuildSubmitFileShape(t *testing.T) {
	const instanceID = "deadbeefdeadbeef"
	src := BuildSubmitFile(SubmitArgs{
		InstanceID: instanceID,
		BatchName:  BatchNameForSession("my-session"),
		Cpus:       4,
		MemoryMB:   2048,
		DiskMB:     4096,
		Watchdog:   DefaultSessionWatchdog,
	})

	for _, want := range []string{
		"universe = vanilla",
		"executable = interactive-watchdog.sh",
		"request_cpus = 4",
		"request_memory = 2048",
		// MiB in, KiB out: request_disk is the one that differs.
		"request_disk = 4194304",
		"batch_name = " + SessionBatchPrefix + "my-session",
		"queue",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("submit file missing %q:\n%s", want, src)
		}
	}

	// `job_batch_name` is not a submit command; the in-process parser
	// recognises `batch_name` only, and spelling it the other way left
	// JobBatchName unset and every session invisible to the prefix
	// filter that finds them.
	if strings.Contains(src, "job_batch_name") {
		t.Error("submit file uses job_batch_name, which the submit parser ignores")
	}
}

// TestSessionNameRoundTripsThroughTheBatchName: the name a caller
// passes has to come back out of the queue, because the queue is where
// it is stored between calls.
func TestSessionNameRoundTripsThroughTheBatchName(t *testing.T) {
	for _, name := range []string{"a", "build", "my-session.2", "A_b-c.9"} {
		got, ok := SessionNameFromBatchName(BatchNameForSession(name))
		if !ok || got != name {
			t.Errorf("round trip of %q gave (%q, %v)", name, got, ok)
		}
	}
	// A browser terminal is not a session and must not resolve as one:
	// the two share a watchdog, not a lifecycle.
	for _, batch := range []string{"", "analysis", BatchPrefix + "abc", SessionBatchPrefix} {
		if name, ok := SessionNameFromBatchName(batch); ok {
			t.Errorf("batch name %q resolved to session %q", batch, name)
		}
	}

	// And a session job is not one of the SSH bridge's terminals --
	// otherwise closing a browser tab opened on it would condor_rm an
	// agent's session out from under it.
	if IsInteractiveAd(fakeAd{"JobBatchName": BatchNameForSession("build")}) {
		t.Error("a session job is treated as a browser terminal")
	}
}

func TestBuildSubmitFileExtraLinesComeLast(t *testing.T) {
	src := BuildSubmitFile(SubmitArgs{
		InstanceID:       "abc",
		BatchName:        BatchPrefix + "abc",
		Cpus:             1,
		MemoryMB:         512,
		DiskMB:           512,
		ExtraSubmitLines: "request_memory = 9999\n",
	})
	// Submit commands are macro assignments evaluated at `queue`, so
	// the operator's override only wins if it is the last assignment.
	last := strings.LastIndex(src, "request_memory = 9999")
	first := strings.Index(src, "request_memory = 512")
	if last < 0 || first < 0 || last < first {
		t.Errorf("operator extras do not follow the generated lines:\n%s", src)
	}
	if q := strings.Index(src, "\nqueue"); q >= 0 && last > q {
		t.Errorf("operator extras land after `queue`, where they do nothing:\n%s", src)
	}
}

// TestWatchdogAndHeartbeatNameTheSameFile is the coupling that decides
// whether any of this works: the script stats one path and the
// heartbeat touches another, and if they ever disagree the session
// dies one freshness window after it starts, silently. A rename on
// either side must break here rather than in production.
func TestWatchdogAndHeartbeatNameTheSameFile(t *testing.T) {
	script := BuildWatchdogScript(DefaultSessionWatchdog)

	if !strings.Contains(script, fmt.Sprintf("HEARTBEAT_FILE=%q", HeartbeatFile)) {
		t.Errorf("watchdog does not watch %q:\n%s", HeartbeatFile, script)
	}
	if !strings.Contains(script, fmt.Sprintf("SHUTDOWN_FILE=%q", ShutdownFile)) {
		t.Errorf("watchdog does not watch %q", ShutdownFile)
	}
	if !strings.HasSuffix(HeartbeatCmd, "/"+HeartbeatFile+`"`) {
		t.Errorf("heartbeat command %q does not end at %q", HeartbeatCmd, HeartbeatFile)
	}
	if !strings.HasSuffix(ShutdownCmd, "/"+ShutdownFile+`"`) {
		t.Errorf("shutdown command %q does not end at %q", ShutdownCmd, ShutdownFile)
	}
	// Both commands are scratch-absolute: an SSH exec session does not
	// share the watchdog's cwd, so a relative path would land in the
	// user's home directory instead.
	for _, cmd := range []string{HeartbeatCmd, ShutdownCmd} {
		if !strings.Contains(cmd, "_CONDOR_SCRATCH_DIR") {
			t.Errorf("command %q is not anchored to the scratch dir", cmd)
		}
	}
}

func TestBuildWatchdogScriptTiming(t *testing.T) {
	script := BuildWatchdogScript(WatchdogTiming{PollSec: 7, FreshnessSec: 42})
	if !strings.Contains(script, "POLL_INTERVAL=7") || !strings.Contains(script, "FRESHNESS_WINDOW=42") {
		t.Errorf("timing not rendered into the script:\n%s", script)
	}

	// Zero means "use the terminal defaults", not "expire immediately".
	zero := BuildWatchdogScript(WatchdogTiming{})
	if !strings.Contains(zero, fmt.Sprintf("FRESHNESS_WINDOW=%d", DefaultTerminalWatchdogFreshnessSec)) {
		t.Errorf("zero timing did not fall back to the defaults:\n%s", zero)
	}

	// The session window has to outlast a restart of the API server;
	// the terminal window is deliberately tighter.
	if DefaultSessionWatchdogFreshnessSec <= DefaultTerminalWatchdogFreshnessSec {
		t.Errorf("session freshness (%d) is not wider than the terminal's (%d)",
			DefaultSessionWatchdogFreshnessSec, DefaultTerminalWatchdogFreshnessSec)
	}
}

func TestValidateSessionName(t *testing.T) {
	for _, ok := range []string{"a", "build", "my-session.2", "A_b-c.9", strings.Repeat("x", 64)} {
		if err := ValidateSessionName(ok); err != nil {
			t.Errorf("ValidateSessionName(%q) = %v, want nil", ok, err)
		}
	}
	// The name is spliced into a ClassAd string literal and into a
	// constraint; anything with syntax in it is refused outright
	// rather than escaped.
	for _, bad := range []string{"", " ", "has space", `quo"te`, `back\slash`, "-lead", ".lead", "tab\there", "nl\nhere", strings.Repeat("x", 65)} {
		if err := ValidateSessionName(bad); err == nil {
			t.Errorf("ValidateSessionName(%q) = nil, want an error", bad)
		}
	}
}

func TestIsInteractiveAd(t *testing.T) {
	if !IsInteractiveAd(fakeAd{"JobBatchName": BatchPrefix + "abc"}) {
		t.Error("an interactive job was not recognised")
	}
	for _, ad := range []fakeAd{{}, {"JobBatchName": "analysis"}, {"JobBatchName": "not-" + BatchPrefix}} {
		if IsInteractiveAd(ad) {
			t.Errorf("ad %v was treated as interactive", ad)
		}
	}
}

type fakeAd map[string]string

func (a fakeAd) EvaluateAttrString(name string) (string, bool) {
	v, ok := a[name]
	return v, ok
}

// TestWatchdogKillsOnlyThisJobsSshd: the watchdog kills sshd so the
// starter can wind the job down, and a kill matched on the process name
// alone is not confined to this job. Pools that run jobs as dedicated
// slot users hide that -- where jobs run as the submitting user, the
// same pkill reaches that user's login session on the execute node and
// their other interactive jobs.
func TestWatchdogKillsOnlyThisJobsSshd(t *testing.T) {
	script := BuildWatchdogScript(WatchdogTiming{})

	for _, line := range strings.Split(script, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "pkill") {
			continue
		}
		if !strings.Contains(trimmed, "-f") || !strings.Contains(trimmed, "${scratch}") {
			t.Errorf("pkill is not confined to this job's sandbox: %s", trimmed)
		}
	}
	if !strings.Contains(script, `scratch="${_CONDOR_SCRATCH_DIR:-$PWD}"`) {
		t.Error("the watchdog never resolves the sandbox path it matches on")
	}
	if !strings.Contains(script, "pkill -KILL") {
		t.Error("no hard kill; a wedged sshd would hold the slot")
	}
}
