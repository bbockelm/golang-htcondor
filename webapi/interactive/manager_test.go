package interactive

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	htcondor "github.com/bbockelm/golang-htcondor"
)

var alice = Caller{Actor: "alice@uid.example.com", Owner: "alice"}
var bob = Caller{Actor: "bob@uid.example.com", Owner: "bob"}

func TestCreateSubmitsAndSpoolsWatchdog(t *testing.T) {
	schedd := newFakeSchedd()
	mgr, _ := testManager(t, schedd, Options{})

	info, err := mgr.Create(context.Background(), alice, CreateSpec{Name: "build", Cpus: 2, MemoryMB: 4096})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if info.Name != "build" || info.JobID == "" {
		t.Fatalf("unexpected info: %+v", info)
	}
	if info.LeaseExpires.IsZero() {
		t.Error("a created session has no lease; nothing would keep it alive")
	}

	if len(schedd.submitted) != 1 {
		t.Fatalf("submitted %d jobs, want 1", len(schedd.submitted))
	}
	submit := schedd.submitted[0]
	for _, want := range []string{
		"batch_name = " + BatchNameForSession("build"),
		"request_cpus = 2",
		"request_memory = 4096",
		"executable = interactive-watchdog.sh",
	} {
		if !strings.Contains(submit, want) {
			t.Errorf("submit file missing %q:\n%s", want, submit)
		}
	}

	// The watchdog script is the job's executable; a session whose
	// executable never got spooled is held forever.
	if len(schedd.spooled) != 1 || len(schedd.spooled[0]) != 1 || schedd.spooled[0][0] != "interactive-watchdog.sh" {
		t.Errorf("spooled %v, want [interactive-watchdog.sh]", schedd.spooled)
	}
}

func TestCreateRejectsDuplicateName(t *testing.T) {
	schedd := newFakeSchedd()
	mgr, _ := testManager(t, schedd, Options{})
	mustCreate(t, mgr, schedd, alice, "build")

	_, err := mgr.Create(context.Background(), alice, CreateSpec{Name: "build"})
	if err == nil {
		t.Fatal("second Create with the same name succeeded; two jobs would answer to one name")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error does not say what is wrong: %v", err)
	}

	// A different owner may use the same name: sessions are keyed by
	// (owner, name), and one user's choice of name must not collide
	// with another's.
	if _, err := mgr.Create(context.Background(), bob, CreateSpec{Name: "build"}); err != nil {
		t.Errorf("bob cannot use a name alice took: %v", err)
	}
}

func TestCreateEnforcesPerOwnerLimit(t *testing.T) {
	schedd := newFakeSchedd()
	mgr, _ := testManager(t, schedd, Options{MaxPerOwner: 2})
	mustCreate(t, mgr, schedd, alice, "one")
	mustCreate(t, mgr, schedd, alice, "two")

	_, err := mgr.Create(context.Background(), alice, CreateSpec{Name: "three"})
	if err == nil {
		t.Fatal("per-owner limit not enforced; an agent in a retry loop would drain the pool")
	}
	if !strings.Contains(err.Error(), "per-user limit") {
		t.Errorf("error does not explain the limit: %v", err)
	}
}

func TestCreateValidatesName(t *testing.T) {
	schedd := newFakeSchedd()
	mgr, _ := testManager(t, schedd, Options{})
	for _, name := range []string{"", "has space", `quote"inject`, "-leading", strings.Repeat("x", 65)} {
		if _, err := mgr.Create(context.Background(), alice, CreateSpec{Name: name}); err == nil {
			t.Errorf("Create accepted invalid session name %q", name)
		}
	}
	if len(schedd.submitted) != 0 {
		t.Errorf("an invalid name still submitted %d job(s)", len(schedd.submitted))
	}
}

func TestExecRunsCommandAndExtendsLease(t *testing.T) {
	schedd := newFakeSchedd()
	mgr, shell := testManager(t, schedd, Options{DefaultLease: time.Hour})
	job := mustCreate(t, mgr, schedd, alice, "build")
	schedd.setStatus(job, jobStatusRunning)

	shell.stdout = "hello\n"
	shell.stderr = "warn\n"
	shell.exitCode = 3

	result, err := mgr.Exec(context.Background(), alice, "build", ExecRequest{Command: "echo hello"})
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if result.ExitCode != 3 {
		t.Errorf("ExitCode = %d, want 3 (a non-zero exit is a result, not an error)", result.ExitCode)
	}
	if result.Stdout != "hello\n" || result.Stderr != "warn\n" {
		t.Errorf("streams = %q/%q", result.Stdout, result.Stderr)
	}
	if got := shell.ran(); len(got) == 0 || got[len(got)-1] != "echo hello" {
		t.Errorf("command not dispatched verbatim: %v", got)
	}
	if time.Until(result.LeaseExpires) < 50*time.Minute {
		t.Errorf("lease not extended by the call: expires in %s", time.Until(result.LeaseExpires))
	}
}

func TestExecWaitsForHeldJobAndReportsWhy(t *testing.T) {
	schedd := newFakeSchedd()
	mgr, _ := testManager(t, schedd, Options{})
	job := mustCreate(t, mgr, schedd, alice, "build")
	job.holdReason = "no matching slots"
	job.holdCode = 3
	schedd.setStatus(job, jobStatusHeld)

	_, err := mgr.Exec(context.Background(), alice, "build", ExecRequest{Command: "true"})
	if err == nil {
		t.Fatal("Exec against a held session returned no error")
	}
	if !strings.Contains(err.Error(), "no matching slots") {
		t.Errorf("hold reason not surfaced: %v", err)
	}
}

// TestExecWaitsThroughTheSpoolingHold: every job this manager submits
// is held (code 16) between SubmitRemote and the end of spooling.
// Reading that as "held, and will not start" makes the first exec after
// a create fail outright -- which is exactly what it did.
func TestExecWaitsThroughTheSpoolingHold(t *testing.T) {
	schedd := newFakeSchedd()
	mgr, shell := testManager(t, schedd, Options{})
	job := mustCreate(t, mgr, schedd, alice, "build")
	schedd.setStatus(job, jobStatusHeld)
	job.holdCode = 16
	job.holdReason = "Spooling input data files"

	// Spooling finishes while the caller is waiting.
	var queries int
	schedd.onQuery = func() {
		queries++
		if queries >= 2 {
			job.status = jobStatusRunning
			job.holdCode = 0
			job.holdReason = ""
		}
	}
	shell.stdout = "ready\n"

	result, err := mgr.Exec(context.Background(), alice, "build", ExecRequest{
		Command:      "true",
		WaitForReady: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("Exec gave up on a job that was only spooling: %v", err)
	}
	if result.Stdout != "ready\n" {
		t.Errorf("stdout = %q", result.Stdout)
	}
}

// A hold that is NOT the spooling one is terminal, and says why.
func TestExecReportsARealHold(t *testing.T) {
	schedd := newFakeSchedd()
	mgr, _ := testManager(t, schedd, Options{})
	job := mustCreate(t, mgr, schedd, alice, "build")
	schedd.setStatus(job, jobStatusHeld)
	job.holdCode = 13
	job.holdReason = "Error from starter: no such file"

	_, err := mgr.Exec(context.Background(), alice, "build", ExecRequest{Command: "true", WaitForReady: time.Second})
	if err == nil || !strings.Contains(err.Error(), "no such file") {
		t.Fatalf("a real hold was not reported: %v", err)
	}
}

func TestExecGivesUpWaitingForAnIdleSession(t *testing.T) {
	schedd := newFakeSchedd()
	// A clock that jumps a minute per reading turns the wait loop into
	// a handful of iterations instead of a real two-minute wait.
	now := time.Now()
	mgr, _ := testManager(t, schedd, Options{Now: func() time.Time {
		now = now.Add(time.Minute)
		return now
	}})
	mustCreate(t, mgr, schedd, alice, "build") // stays idle

	_, err := mgr.Exec(context.Background(), alice, "build", ExecRequest{Command: "true", WaitForReady: time.Second})
	if err == nil {
		t.Fatal("Exec returned no error for a session that never started")
	}
	if !strings.Contains(err.Error(), "waiting for a slot") {
		t.Errorf("error does not explain the wait: %v", err)
	}
}

func TestExecUnknownSession(t *testing.T) {
	schedd := newFakeSchedd()
	mgr, _ := testManager(t, schedd, Options{})
	_, err := mgr.Exec(context.Background(), alice, "nope", ExecRequest{Command: "true"})
	if err == nil || !strings.Contains(err.Error(), "no interactive session named") {
		t.Fatalf("unhelpful error for an unknown session: %v", err)
	}
}

// TestExecAdoptsSessionCreatedElsewhere is the sessionless case: a
// manager that has never heard of this session finds it in the queue
// by name and uses it.
func TestExecAdoptsSessionCreatedElsewhere(t *testing.T) {
	schedd := newFakeSchedd()
	first, _ := testManager(t, schedd, Options{})
	job := mustCreate(t, first, schedd, alice, "build")
	schedd.setStatus(job, jobStatusRunning)
	first.Close()

	// A brand new manager: same queue, no memory of the session.
	second, shell := testManager(t, schedd, Options{})
	shell.stdout = "adopted\n"
	result, err := second.Exec(context.Background(), alice, "build", ExecRequest{Command: "true"})
	if err != nil {
		t.Fatalf("Exec on an adopted session: %v", err)
	}
	if result.Stdout != "adopted\n" {
		t.Errorf("stdout = %q", result.Stdout)
	}
	if result.LeaseExpires.IsZero() {
		t.Error("adopted session has no lease; nothing would keep it alive")
	}
}

func TestExecRefusesAnotherOwnersSession(t *testing.T) {
	schedd := newFakeSchedd()
	mgr, _ := testManager(t, schedd, Options{})
	job := mustCreate(t, mgr, schedd, alice, "build")
	schedd.setStatus(job, jobStatusRunning)

	if _, err := mgr.Exec(context.Background(), bob, "build", ExecRequest{Command: "whoami"}); err == nil {
		t.Fatal("bob executed a command inside alice's session")
	}
}

// TestListIgnoresJobsTheCallerDoesNotOwn covers the case where the
// schedd's own filter does not apply: the client-side owner check has
// to be what fails closed.
func TestListIgnoresJobsTheCallerDoesNotOwn(t *testing.T) {
	schedd := newFakeSchedd()
	mgr, _ := testManager(t, schedd, Options{})
	mustCreate(t, mgr, schedd, alice, "build")
	schedd.leakOtherOwners = true

	infos, err := mgr.List(context.Background(), bob)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(infos) != 0 {
		t.Fatalf("bob sees alice's session when the schedd leaks it: %+v", infos)
	}

	// And the constraint asked for the right owner in the first place.
	if len(schedd.constraints) == 0 || !strings.Contains(schedd.constraints[0], `Owner == "alice"`) {
		t.Errorf("query was not owner-scoped: %v", schedd.constraints)
	}
}

func TestExecTruncatesLargeOutput(t *testing.T) {
	schedd := newFakeSchedd()
	mgr, shell := testManager(t, schedd, Options{MaxOutputBytes: 16})
	job := mustCreate(t, mgr, schedd, alice, "build")
	schedd.setStatus(job, jobStatusRunning)
	shell.stdout = strings.Repeat("x", 100)

	result, err := mgr.Exec(context.Background(), alice, "build", ExecRequest{Command: "cat big"})
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if len(result.Stdout) != 16 {
		t.Errorf("stdout length = %d, want the 16-byte cap", len(result.Stdout))
	}
	if !result.StdoutTruncated {
		t.Error("truncation not reported; the caller would read a cut-off answer as the whole answer")
	}
}

func TestExecTimeoutReturnsPartialOutput(t *testing.T) {
	schedd := newFakeSchedd()
	mgr, shell := testManager(t, schedd, Options{})
	job := mustCreate(t, mgr, schedd, alice, "build")
	schedd.setStatus(job, jobStatusRunning)
	shell.block = make(chan struct{})
	t.Cleanup(func() { close(shell.block) })

	result, err := mgr.Exec(context.Background(), alice, "build", ExecRequest{
		Command: "sleep 600",
		Timeout: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("a timed-out command should be a result, not an error: %v", err)
	}
	if !result.TimedOut {
		t.Error("TimedOut not set")
	}
}

func TestExecReattachesAfterTransportFailure(t *testing.T) {
	schedd := newFakeSchedd()
	dead := &fakeShell{runErr: errors.New("ssh: connection closed"), notDispatched: true}
	live := &fakeShell{stdout: "back\n"}
	shells := []Shell{dead, live}
	dialed := 0

	mgr, _ := testManager(t, schedd, Options{
		Dial: func(context.Context, int, int) (Shell, error) {
			s := shells[dialed]
			dialed++
			return s, nil
		},
	})
	job := mustCreate(t, mgr, schedd, alice, "build")
	schedd.setStatus(job, jobStatusRunning)

	result, err := mgr.Exec(context.Background(), alice, "build", ExecRequest{Command: "echo back"})
	if err != nil {
		t.Fatalf("Exec did not recover from a dead connection: %v", err)
	}
	if result.Stdout != "back\n" {
		t.Errorf("stdout = %q, want the retried command's output", result.Stdout)
	}
	if dialed != 2 {
		t.Errorf("dialed %d times, want 2 (one dead, one redial)", dialed)
	}
}

// TestExecDoesNotRetryAfterTheCommandStarted: a command that began
// running and then lost its transport must not be run again. Retrying
// it would repeat whatever it had already done, which for anything
// that writes files or installs packages is worse than the error.
func TestExecDoesNotRetryAfterTheCommandStarted(t *testing.T) {
	schedd := newFakeSchedd()
	// notDispatched is deliberately false: the command started.
	broken := &fakeShell{runErr: errors.New("ssh: unexpected packet")}
	dialed := 0
	mgr, _ := testManager(t, schedd, Options{
		Dial: func(context.Context, int, int) (Shell, error) {
			dialed++
			return broken, nil
		},
	})
	job := mustCreate(t, mgr, schedd, alice, "build")
	schedd.setStatus(job, jobStatusRunning)

	if _, err := mgr.Exec(context.Background(), alice, "build", ExecRequest{Command: "make install"}); err == nil {
		t.Fatal("a mid-command transport failure was reported as success")
	}
	if dialed != 1 {
		t.Errorf("dialed %d times; the command was re-dispatched after it had already started", dialed)
	}
	if n := len(broken.ran()); n != 1 {
		t.Errorf("command ran %d times, want 1", n)
	}
}

// TestHeartbeatRunsWithoutAnyActivity is the regression this whole
// design turns on. The browser bridge only beat while the user had
// typed in the last 60 seconds, so a session nobody touched died
// inside two minutes -- which under MCP, where minutes pass between
// tool calls by construction, would be every session. A leased session
// must be heartbeated because it is leased, not because somebody is
// interacting with it.
func TestHeartbeatRunsWithoutAnyActivity(t *testing.T) {
	schedd := newFakeSchedd()
	mgr, shell := testManager(t, schedd, Options{
		HeartbeatInterval: 10 * time.Millisecond,
		DefaultLease:      time.Hour,
	})
	job := mustCreate(t, mgr, schedd, alice, "build")
	schedd.setStatus(job, jobStatusRunning)

	if _, err := mgr.Exec(context.Background(), alice, "build", ExecRequest{Command: "true"}); err != nil {
		t.Fatalf("Exec: %v", err)
	}

	// No further calls: exactly the state the old gate treated as
	// "nobody is there".
	waitFor(t, "heartbeats with no caller activity", 2*time.Second, func() bool {
		return shell.countOf(HeartbeatCmd) >= 3
	})
}

func TestLeaseExpiryReleasesTheSlot(t *testing.T) {
	schedd := newFakeSchedd()
	mgr, shell := testManager(t, schedd, Options{
		HeartbeatInterval: 10 * time.Millisecond,
		DefaultLease:      60 * time.Millisecond,
	})
	job := mustCreate(t, mgr, schedd, alice, "build")
	schedd.setStatus(job, jobStatusRunning)
	if _, err := mgr.Exec(context.Background(), alice, "build", ExecRequest{Command: "true"}); err != nil {
		t.Fatalf("Exec: %v", err)
	}

	waitFor(t, "the expired session to be removed", 3*time.Second, func() bool {
		return len(schedd.removedJobs()) > 0
	})
	if shell.countOf(ShutdownCmd) == 0 {
		t.Error("no shutdown sentinel was dropped; the slot frees only after the full freshness window")
	}
	// And it stops beating, rather than keeping a session alive that
	// nothing is leasing any more.
	beats := shell.countOf(HeartbeatCmd)
	time.Sleep(50 * time.Millisecond)
	if after := shell.countOf(HeartbeatCmd); after > beats {
		t.Errorf("heartbeat continued after expiry: %d -> %d", beats, after)
	}
}

func TestStopRemovesTheJob(t *testing.T) {
	schedd := newFakeSchedd()
	mgr, shell := testManager(t, schedd, Options{})
	job := mustCreate(t, mgr, schedd, alice, "build")
	schedd.setStatus(job, jobStatusRunning)
	if _, err := mgr.Exec(context.Background(), alice, "build", ExecRequest{Command: "true"}); err != nil {
		t.Fatalf("Exec: %v", err)
	}

	if _, err := mgr.Stop(context.Background(), alice, "build"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if shell.countOf(ShutdownCmd) == 0 {
		t.Error("Stop dropped no shutdown sentinel")
	}
	removed := schedd.removedJobs()
	if len(removed) != 1 {
		t.Fatalf("condor_rm issued %d times, want 1", len(removed))
	}
	if !strings.Contains(removed[0], `Owner == "alice"`) {
		t.Errorf("removal constraint is not owner-scoped: %q", removed[0])
	}
	if !shell.closed {
		t.Error("the SSH connection was left open after Stop")
	}
}

func TestStopRefusesAnotherOwnersSession(t *testing.T) {
	schedd := newFakeSchedd()
	mgr, _ := testManager(t, schedd, Options{})
	mustCreate(t, mgr, schedd, alice, "build")

	if _, err := mgr.Stop(context.Background(), bob, "build"); err == nil {
		t.Fatal("bob stopped alice's session")
	}
	if len(schedd.removedJobs()) != 0 {
		t.Error("a job was removed on a refused request")
	}
}

// TestCloseLeavesSessionsRunning pins the restart story: shutting the
// manager down must not kill sessions, because the next process is
// expected to adopt them.
func TestCloseLeavesSessionsRunning(t *testing.T) {
	schedd := newFakeSchedd()
	mgr, shell := testManager(t, schedd, Options{})
	job := mustCreate(t, mgr, schedd, alice, "build")
	schedd.setStatus(job, jobStatusRunning)
	if _, err := mgr.Exec(context.Background(), alice, "build", ExecRequest{Command: "true"}); err != nil {
		t.Fatalf("Exec: %v", err)
	}

	mgr.Close()

	if n := len(schedd.removedJobs()); n != 0 {
		t.Errorf("Close removed %d job(s); a restart would lose every live session", n)
	}
	if shell.countOf(ShutdownCmd) != 0 {
		t.Error("Close dropped a shutdown sentinel; the session would end on restart")
	}
	if !shell.closed {
		t.Error("Close leaked the SSH connection")
	}
}

func TestUnauthenticatedCallerRefused(t *testing.T) {
	schedd := newFakeSchedd()
	mgr, _ := testManager(t, schedd, Options{})
	anon := Caller{}
	if _, err := mgr.Create(context.Background(), anon, CreateSpec{Name: "x"}); err == nil {
		t.Error("Create allowed an unauthenticated caller")
	}
	if _, err := mgr.List(context.Background(), anon); err == nil {
		t.Error("List allowed an unauthenticated caller")
	}
	if _, err := mgr.Exec(context.Background(), anon, "x", ExecRequest{Command: "true"}); err == nil {
		t.Error("Exec allowed an unauthenticated caller")
	}
	if _, err := mgr.Stop(context.Background(), anon, "x"); err == nil {
		t.Error("Stop allowed an unauthenticated caller")
	}
}

// TestLeaseSurvivesALongRunningCommand covers the worst bug the review
// found: Exec used to extend the lease only on the way OUT, so a
// command started near the end of a lease had the lease expire
// underneath it -- expiry drops the shutdown sentinel and condor_rm's
// the job, so the sandbox the command was working in disappears
// mid-write and the caller gets a transport error instead of output.
func TestLeaseSurvivesALongRunningCommand(t *testing.T) {
	schedd := newFakeSchedd()
	mgr, shell := testManager(t, schedd, Options{
		HeartbeatInterval: 10 * time.Millisecond,
		// Shorter than the command takes.
		DefaultLease: 50 * time.Millisecond,
	})
	job := mustCreate(t, mgr, schedd, alice, "build")
	schedd.setStatus(job, jobStatusRunning)

	release := make(chan struct{})
	shell.block = release
	shell.stdout = "finished\n"

	done := make(chan *ExecResult, 1)
	go func() {
		result, err := mgr.Exec(context.Background(), alice, "build", ExecRequest{
			Command: "make",
			Timeout: 10 * time.Second,
		})
		if err != nil {
			t.Errorf("Exec: %v", err)
			done <- nil
			return
		}
		done <- result
	}()

	// Hold the command open well past the lease, then let it finish.
	time.Sleep(250 * time.Millisecond)
	if removed := schedd.removedJobs(); len(removed) != 0 {
		t.Errorf("the job was removed while a command was still running: %v", removed)
	}
	if shell.countOf(ShutdownCmd) != 0 {
		t.Error("a shutdown sentinel was dropped while a command was still running")
	}
	close(release)

	result := <-done
	if result == nil {
		t.Fatal("the command did not complete")
	}
	if result.Stdout != "finished\n" {
		t.Errorf("stdout = %q", result.Stdout)
	}
	// And the lease runs from when the command ENDED, not when it began.
	if time.Until(result.LeaseExpires) <= 0 {
		t.Errorf("lease expires at %v, which is already past", result.LeaseExpires)
	}
}

// TestStaleHeartbeatDoesNotCloseItsSuccessor covers the second finding:
// teardown used to be addressed by (owner, name), so a goroutine that
// had already been superseded closed whatever now answered to that name
// -- including the freshly dialed connection Exec's retry was running
// its command on.
func TestStaleHeartbeatDoesNotCloseItsSuccessor(t *testing.T) {
	schedd := newFakeSchedd()
	mgr, _ := testManager(t, schedd, Options{DefaultLease: time.Hour})
	job := mustCreate(t, mgr, schedd, alice, "build")
	schedd.setStatus(job, jobStatusRunning)

	// Attach, then capture the session the manager is tracking.
	if _, err := mgr.Exec(context.Background(), alice, "build", ExecRequest{Command: "true"}); err != nil {
		t.Fatalf("Exec: %v", err)
	}
	stale := mgr.sessionFor(alice.Owner, "build")
	if stale == nil {
		t.Fatal("no session registered")
	}

	// Replace it the way Create-after-reclaim does.
	live := &session{
		name:          "build",
		owner:         alice.Owner,
		cluster:       stale.cluster,
		proc:          stale.proc,
		leaseExpires:  time.Now().Add(time.Hour),
		leaseDuration: time.Hour,
		shell:         &fakeShell{},
	}
	mgr.mu.Lock()
	mgr.sessions[sessionKey(alice.Owner, "build")] = live
	mgr.mu.Unlock()

	// The superseded holder tears itself down. It must not touch the
	// session that replaced it.
	mgr.detach(stale, "stale holder")
	mgr.forget(stale, "stale holder")

	mgr.mu.Lock()
	current := mgr.sessions[sessionKey(alice.Owner, "build")]
	mgr.mu.Unlock()
	if current != live {
		t.Fatal("the stale holder evicted its successor from the registry")
	}
	if live.shell == nil {
		t.Fatal("the stale holder dropped its successor's connection")
	}
	if live.shell.(*fakeShell).closed {
		t.Error("the stale holder closed its successor's connection")
	}
}

// TestCCBStreamingReachesTheDial pins the setting that decides whether a
// session can be reached at all when the job is behind CCB.
//
// The dial-back default requires the execute node to connect back to
// this process, which an access point's API server generally cannot
// accept -- the broker then points the starter at an address nothing
// routes to and the dial fails with "ccb: broker failure: failed to
// connect". The REST terminal has passed this setting since it hit
// exactly that; the session manager was built with nil options and
// silently took the default, so every session on a CCB pool failed
// while every local test passed.
func TestCCBStreamingReachesTheDial(t *testing.T) {
	for name, streaming := range map[string]bool{"enabled": true, "disabled": false} {
		t.Run(name, func(t *testing.T) {
			var captured *htcondor.JobShellOptions
			restore := openJobShell
			openJobShell = func(_ context.Context, _ *htcondor.Schedd, _, _ int, opts *htcondor.JobShellOptions) (*ssh.Client, error) {
				captured = opts
				return nil, errors.New("stop before dialing")
			}
			defer func() { openJobShell = restore }()

			schedd := newFakeSchedd()
			mgr, _ := testManager(t, schedd, Options{
				CCBStreaming: streaming,
				// Force the real dialer: the point is what IT asks for.
				Dial: nil,
			})
			mgr.opts.Dial = sshDialer(func() ScheddClient {
				return htcondor.NewSchedd("test", "127.0.0.1:1")
			}, streaming)

			_, _ = mgr.opts.Dial(context.Background(), 1, 0)

			if captured == nil {
				t.Fatal("the dialer passed no JobShellOptions; nil means CCB dial-back")
			}
			if captured.CCBStreaming != streaming {
				t.Errorf("CCBStreaming = %v, want %v", captured.CCBStreaming, streaming)
			}
		})
	}
}

// TestNewManagerHandsStreamingToTheDialer: the option has to survive the
// trip from the host's config into the dialer the manager builds.
func TestNewManagerHandsStreamingToTheDialer(t *testing.T) {
	var captured *htcondor.JobShellOptions
	restore := openJobShell
	openJobShell = func(_ context.Context, _ *htcondor.Schedd, _, _ int, opts *htcondor.JobShellOptions) (*ssh.Client, error) {
		captured = opts
		return nil, errors.New("stop before dialing")
	}
	defer func() { openJobShell = restore }()

	mgr, err := NewManager(Options{
		Schedd:       func() ScheddClient { return htcondor.NewSchedd("test", "127.0.0.1:1") },
		CCBStreaming: true,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer mgr.Close()

	_, _ = mgr.opts.Dial(context.Background(), 1, 0)
	if captured == nil || !captured.CCBStreaming {
		t.Errorf("NewManager built a dialer that does not request CCB streaming: %+v", captured)
	}
}

// TestWatchdogWindowFollowsTheLease: nothing touches .heartbeat until a
// caller attaches, and attaching only happens on the first exec. With a
// fixed window, a session created and left alone was reclaimed while
// start had just promised it for the lease -- and after a restart of the
// daemon that same window, not the lease, was what bounded recovery.
func TestWatchdogWindowFollowsTheLease(t *testing.T) {
	schedd := newFakeSchedd()
	mgr, _ := testManager(t, schedd, Options{HeartbeatInterval: 60 * time.Second})

	if _, err := mgr.Create(context.Background(), alice, CreateSpec{
		Name:  "long",
		Lease: 2 * time.Hour,
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(schedd.submitted) != 1 {
		t.Fatalf("submitted %d jobs", len(schedd.submitted))
	}
	want := fmt.Sprintf("FRESHNESS_WINDOW=%d", int((2 * time.Hour).Seconds()))
	if !strings.Contains(schedd.spooledScript(), want) {
		t.Errorf("the job's watchdog does not honour the requested lease (want %s):\n%s",
			want, schedd.spooledScript())
	}

	// A very short lease must still outlast several heartbeats, or one
	// slow round trip evicts a session nobody abandoned.
	if _, err := mgr.Create(context.Background(), alice, CreateSpec{
		Name:  "short",
		Lease: 10 * time.Second,
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if strings.Contains(schedd.spooledScript(), "FRESHNESS_WINDOW=10") {
		t.Error("a 10s lease produced a 10s watchdog window; one slow heartbeat would evict it")
	}
}

// TestOperatorRequirementsReachEverySession is the bug this pins: the
// REST terminal applied HTTP_API_INTERACTIVE_REQUIREMENTS and sessions
// did not, because this manager builds its own submit file and nothing
// carried the value across. A session then landed on exactly the
// machines the operator had excluded.
func TestOperatorRequirementsReachEverySession(t *testing.T) {
	const operator = `GLIDEIN_Site =!= "BadSite"`

	t.Run("with no caller expression", func(t *testing.T) {
		schedd := newFakeSchedd()
		mgr, _ := testManager(t, schedd, Options{Requirements: operator})
		mustCreate(t, mgr, schedd, alice, "plain")
		if !strings.Contains(schedd.submitted[0], "requirements = ("+operator+")") {
			t.Errorf("the operator's requirements are not in the submit file:\n%s", schedd.submitted[0])
		}
	})

	t.Run("anded with the caller's", func(t *testing.T) {
		const caller = `TARGET.HasCVMFS == true`
		schedd := newFakeSchedd()
		mgr, _ := testManager(t, schedd, Options{Requirements: operator})
		if _, err := mgr.Create(context.Background(), alice, CreateSpec{
			Name:         "narrowed",
			Requirements: caller,
		}); err != nil {
			t.Fatalf("Create: %v", err)
		}
		got := schedd.submitted[0]
		if !strings.Contains(got, operator) || !strings.Contains(got, caller) {
			t.Errorf("both expressions should apply:\n%s", got)
		}
		// The caller must not be able to widen past the operator: an OR
		// would let them do exactly that.
		if strings.Contains(got, "||") {
			t.Errorf("the two expressions are not ANDed:\n%s", got)
		}
	})
}

// TestCallerRequirementsMustParse: the operator's expression and the
// submit policy land in the same file, so a caller expression that does
// not parse would take them down with it.
func TestCallerRequirementsMustParse(t *testing.T) {
	schedd := newFakeSchedd()
	mgr, _ := testManager(t, schedd, Options{})
	_, err := mgr.Create(context.Background(), alice, CreateSpec{
		Name:         "bad",
		Requirements: "((",
	})
	if err == nil {
		t.Fatal("an unparseable requirements expression was accepted")
	}
	if len(schedd.submitted) != 0 {
		t.Error("a job was submitted despite the bad expression")
	}
}

// TestCallerSubmitLinesCannotRedefineTheSession: a caller may add submit
// commands, but not the handful that make the job a session -- those
// produce a job that submits cleanly and then cannot be attached to.
func TestCallerSubmitLinesCannotRedefineTheSession(t *testing.T) {
	for _, bad := range []string{
		"executable = /bin/bash",
		"batch_name = something-else",
		"universe = docker",
		"transfer_executable = false",
		"queue 5",
	} {
		schedd := newFakeSchedd()
		mgr, _ := testManager(t, schedd, Options{})
		_, err := mgr.Create(context.Background(), alice, CreateSpec{
			Name:        "redefine",
			SubmitLines: bad,
		})
		if err == nil {
			t.Errorf("%q was accepted; the session would submit and then be unreachable", bad)
		}
		if len(schedd.submitted) != 0 {
			t.Errorf("%q still submitted a job", bad)
		}
	}

	// What a caller actually wants does go through.
	schedd := newFakeSchedd()
	mgr, _ := testManager(t, schedd, Options{})
	if _, err := mgr.Create(context.Background(), alice, CreateSpec{
		Name:        "ok",
		SubmitLines: "+WantGPULab = true\ncontainer_image = docker://rockylinux:9\n",
	}); err != nil {
		t.Fatalf("ordinary submit commands were refused: %v", err)
	}
	if !strings.Contains(schedd.submitted[0], "container_image = docker://rockylinux:9") {
		t.Errorf("the caller's submit commands are not in the file:\n%s", schedd.submitted[0])
	}
}
