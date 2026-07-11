package userlog

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fixedTime is a stable timestamp so header formatting is deterministic.
var fixedTime = time.Date(2026, 7, 10, 12, 9, 19, 0, time.Local)

func TestFormatHeader(t *testing.T) {
	w := NewWriter("/tmp/x.log", 16091, 0, 0)
	got := w.formatHeader(NumSubmit, fixedTime)
	want := "000 (16091.000.000) 2026-07-10 12:09:19 "
	if got != want {
		t.Fatalf("header = %q, want %q", got, want)
	}
}

// TestRoundTripSubmitExecuteTerminated writes a full vanilla-job sequence
// and parses it back with the sibling Parse(), asserting the writer's bytes
// are exactly what the parser expects.
func TestRoundTripSubmitExecuteTerminated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "job.log")
	w := NewWriter(path, 42, 3, 0)

	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(w.WriteEvent(SubmitEvent(fixedTime, "<127.0.0.1:9618?addrs=127.0.0.1-9618>")))
	must(w.WriteEvent(ExecuteEvent(fixedTime.Add(time.Second), "<10.0.0.1:9618>", "slot1@worker")))
	must(w.WriteEvent(TerminatedEvent(fixedTime.Add(2*time.Second), false, 0)))

	f, err := os.Open(path) //nolint:gosec // test reads a log file it just wrote under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	events, err := Parse(f)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("got %d events, want 3", len(events))
	}

	if events[0].Kind != KindSubmit || events[0].ClusterID != 42 || events[0].ProcID != 3 {
		t.Errorf("submit event wrong: %+v", events[0])
	}
	if events[0].SubmitHost != "<127.0.0.1:9618?addrs=127.0.0.1-9618>" {
		t.Errorf("submit host = %q", events[0].SubmitHost)
	}
	if events[1].Kind != KindExecute || events[1].ExecuteHost != "<10.0.0.1:9618>" {
		t.Errorf("execute event wrong: %+v", events[1])
	}
	if events[2].Kind != KindJobTerminated || !events[2].TerminatedNormally {
		t.Errorf("terminated event wrong: %+v", events[2])
	}
	if events[2].ReturnValue == nil || *events[2].ReturnValue != 0 {
		t.Errorf("return value = %v, want 0", events[2].ReturnValue)
	}
}

func TestRoundTripSignalTermination(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "job.log")
	w := NewWriter(path, 7, 0, 0)
	if err := w.WriteEvent(TerminatedEvent(fixedTime, true, 9)); err != nil {
		t.Fatal(err)
	}
	events := parseFile(t, path)
	if len(events) != 1 || events[0].Kind != KindJobTerminated {
		t.Fatalf("events = %+v", events)
	}
	if events[0].TerminatedNormally {
		t.Error("expected abnormal termination")
	}
	if events[0].TerminatedBySignal == nil || *events[0].TerminatedBySignal != 9 {
		t.Errorf("signal = %v, want 9", events[0].TerminatedBySignal)
	}
}

func TestRoundTripHoldReleaseAbort(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "job.log")
	w := NewWriter(path, 100, 0, 0)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(w.WriteEvent(HeldEvent(fixedTime, "via condor_hold (by user alice)", 1, 0)))
	must(w.WriteEvent(ReleasedEvent(fixedTime.Add(time.Second), "via condor_release (by user alice)")))
	must(w.WriteEvent(AbortedEvent(fixedTime.Add(2*time.Second), "via condor_rm (by user alice)")))

	events := parseFile(t, path)
	if len(events) != 3 {
		t.Fatalf("got %d events, want 3: %+v", len(events), events)
	}
	if events[0].Kind != KindJobHeld {
		t.Errorf("event 0 = %v", events[0].Kind)
	}
	if events[0].HoldReason != "via condor_hold (by user alice)" {
		t.Errorf("hold reason = %q", events[0].HoldReason)
	}
	if events[0].HoldReasonCode == nil || *events[0].HoldReasonCode != 1 {
		t.Errorf("hold code = %v", events[0].HoldReasonCode)
	}
	if events[1].Kind != KindJobReleased {
		t.Errorf("event 1 = %v", events[1].Kind)
	}
	if events[2].Kind != KindJobAborted {
		t.Errorf("event 2 = %v", events[2].Kind)
	}
	if events[2].AbortReason != "via condor_rm (by user alice)" {
		t.Errorf("abort reason = %q", events[2].AbortReason)
	}
}

func TestRoundTripEvicted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "job.log")
	w := NewWriter(path, 5, 0, 0)
	if err := w.WriteEvent(EvictedEvent(fixedTime, "shadow exception: connection lost")); err != nil {
		t.Fatal(err)
	}
	events := parseFile(t, path)
	if len(events) != 1 || events[0].Kind != KindJobEvicted {
		t.Fatalf("events = %+v", events)
	}
}

func TestRoundTripReconnect(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "job.log")
	w := NewWriter(path, 9, 0, 0)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(w.WriteEvent(DisconnectedEvent(fixedTime, "schedd restarted", "slot1@worker", "<10.0.0.1:9618>")))
	must(w.WriteEvent(ReconnectedEvent(fixedTime.Add(time.Second), "slot1@worker", "<10.0.0.1:9618>", "<10.0.0.1:40000>")))
	events := parseFile(t, path)
	if len(events) != 2 {
		t.Fatalf("got %d events: %+v", len(events), events)
	}
	if events[0].Kind != KindJobDisconnected || events[1].Kind != KindJobReconnected {
		t.Errorf("kinds = %v, %v", events[0].Kind, events[1].Kind)
	}
}

// TestCondorWaitAccepts validates the writer's output against the stock C++
// condor_wait: a file whose last event is a terminal (Terminated) event must
// make condor_wait exit 0 promptly. Skips when condor_wait is not available.
func TestCondorWaitAccepts(t *testing.T) {
	wait := findCondorWait()
	if wait == "" {
		t.Skip("condor_wait not found on PATH or build dir")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "job.log")
	w := NewWriter(path, 314, 0, 0)
	now := time.Now()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(w.WriteEvent(SubmitEvent(now, "<127.0.0.1:9618?addrs=127.0.0.1-9618>")))
	must(w.WriteEvent(ExecuteEvent(now.Add(time.Second), "<10.0.0.1:9618>", "slot1@worker")))
	must(w.WriteEvent(TerminatedEvent(now.Add(2*time.Second), false, 0)))

	// -wait 30 gives condor_wait a bounded time; it should return immediately
	// because the job already terminated.
	cmd := exec.Command(wait, "-wait", "30", path) //nolint:noctx,gosec // test invokes the locally-built condor_wait binary
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("condor_wait rejected our log (exit err %v):\n%s", err, out)
	}
	t.Logf("condor_wait accepted the log:\n%s", out)
}

// TestCondorWaitAbort validates condor_wait treats an aborted job as done.
func TestCondorWaitAbort(t *testing.T) {
	wait := findCondorWait()
	if wait == "" {
		t.Skip("condor_wait not found on PATH or build dir")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "job.log")
	w := NewWriter(path, 271, 0, 0)
	now := time.Now()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(w.WriteEvent(SubmitEvent(now, "<127.0.0.1:9618>")))
	must(w.WriteEvent(AbortedEvent(now.Add(time.Second), "via condor_rm (by user test)")))

	cmd := exec.Command(wait, "-wait", "30", path) //nolint:noctx,gosec // test invokes the locally-built condor_wait binary
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("condor_wait did not treat abort as terminal (exit err %v):\n%s", err, out)
	}
	t.Logf("condor_wait accepted the aborted log:\n%s", out)
}

func parseFile(t *testing.T, path string) []Event {
	t.Helper()
	f, err := os.Open(path) //nolint:gosec // test reads a log file it just wrote under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	events, err := Parse(f)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return events
}

func findCondorWait() string {
	if p, err := exec.LookPath("condor_wait"); err == nil {
		return p
	}
	for _, cand := range []string{
		"/Users/bbockelm/projects/htcondor/build/release_dir/bin/condor_wait",
	} {
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
	}
	return ""
}

var _ = strings.TrimSpace
