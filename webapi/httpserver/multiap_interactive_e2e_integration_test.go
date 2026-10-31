//go:build integration

package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/interactive"
)

// Interactive sessions in multi-AP mode, end to end, on the stack
// TestMultiAPEndToEnd uses: two real schedds behind a real hub, AP
// assignment from a real mapfile, and the one-slot startd that runs only
// jobs marked E2ERun.
//
// The session job is marked through HTTP_API_INTERACTIVE_EXTRA_SUBMIT --
// the operator knob that adds submit lines to every interactive job --
// rather than through a test-only hook: it is how a site steers
// interactive work onto its own slots, so the session reaching the
// startd exercises the same path a deployment uses.
//
// What is checked, on the schedds themselves and in both directions: the
// session lands on the AP the assignment names and nowhere else; a
// command runs in it; after the assignment moves to the other AP the
// same name still reaches the same job; and stopping it removes it on
// its own AP while the other AP's queue is untouched.

// e2eSessionName names the session this test starts.
const e2eSessionName = "e2e-work"

// e2eSession is the session under test and how to look at it.
type e2eSession struct {
	s     *multiAPStack
	token string
	batch string
	// job is the session's job, once started; on2 is condor_q's
	// ClusterId and JobStatus for it on ap2 then.
	job apJob
	on2 []string
}

// on lists ClusterId and JobStatus of every job of the session on schedd.
func (e *e2eSession) on(t *testing.T, schedd string) []string {
	t.Helper()
	return strings.Fields(e.s.condor(t, "condor_q", "-name", schedd, "-allusers", "-constraint",
		fmt.Sprintf("JobBatchName == %q", e.batch), "-af", "ClusterId", "JobStatus"))
}

func TestMultiAPInteractiveEndToEnd(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("integration test (runs two schedds, three htcondordb daemons and an API server)")
	}
	bin := htcondordbBinary(t)
	if os.Geteuid() == 0 {
		t.Skip("schedd sync refuses to run as root; run this test as an ordinary user")
	}
	s := startMultiAPStack(t, bin, func(c *Config) {
		c.InteractiveExtraSubmit = "+E2ERun = true\n"
	})
	if !s.sshOK {
		t.Skip("no sshd config template for ssh-to-job here; a session cannot be attached to")
	}
	s.waitList(t, "both APs fresh through the hub", 90*time.Second, s.me, func(l e2eList) bool {
		return l.Sources.APs == 2 && l.Sources.Fresh == 2
	})

	e := &e2eSession{s: s, token: s.writeToken(t, s.me), batch: interactive.BatchNameForSession(e2eSessionName)}
	t.Cleanup(func() {
		for _, ap := range []string{e2eAP1, e2eAP2} {
			s.condorQuiet("condor_rm", "-name", ap, "-constraint", fmt.Sprintf("JobBatchName == %q", e.batch))
		}
	})
	ap1Before := s.queueState(t, e2eAP1)

	e.start(t)
	e.exec(t, "a command to run in the session on "+e2eAP2)
	e.afterReassignment(t)
	e.stop(t)
	if after := s.queueState(t, e2eAP1); after != ap1Before {
		t.Errorf("the session's lifetime changed %s's queue:\nbefore %s\nafter  %s", e2eAP1, ap1Before, after)
	}

	if n := s.srv.multi.scheddCalls.Load(); n != 0 {
		t.Errorf("the single-schedd accessor was called %d times in multi-AP mode", n)
	}
	if n := s.srv.Handler.mcpServer.MultiAPScheddCalls(); n != 0 {
		t.Errorf("the MCP server's schedd accessor was called %d times in multi-AP mode", n)
	}
}

// start: the test user is assigned to ap2, and the session lands there,
// on ap2 only, and runs.
func (e *e2eSession) start(t *testing.T) {
	t.Helper()
	// Small, so the test pool's one slot fits it whatever this host has.
	text := e.s.mcpTool(t, e.token, "interactive_session_start", map[string]any{"session": e2eSessionName,
		"cpus": 1, "memory_mb": 256, "disk_mb": 256})
	if !strings.Contains(text, "on access point "+e2eAP2) {
		t.Errorf("interactive_session_start does not name %s: %s", e2eAP2, text)
	}
	e.on2 = e.on(t, e2eAP2)
	if len(e.on2) != 2 {
		t.Fatalf("the session on %s: %v, want exactly one job\n%s", e2eAP2, e.on2, text)
	}
	if got := e.on(t, e2eAP1); len(got) != 0 {
		t.Fatalf("the session also landed on %s: %v", e2eAP1, got)
	}
	e.job = apJob{e2eAP2, mustInt(t, e.on2[0]), 0}
	if !strings.Contains(text, e.job.String()) {
		t.Errorf("start names a job other than %s: %s", e.job, text)
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("=== %s on %s ===\n%s", e.job, e2eAP2, e.s.condorOut("condor_q", "-name", e2eAP2, "-better-analyze", e.job.local()))
		}
	})
	waitFor(t, e.job.String()+" to run", 120*time.Second, func() bool {
		return e.s.scheddAttr(t, e2eAP2, e.job, "JobStatus") == "2"
	})
}

// exec runs a command in the session by its name.
func (e *e2eSession) exec(t *testing.T, what string) {
	t.Helper()
	var out string
	// The first command waits for the sandbox's sshd; a retry covers a
	// dial that raced the job's own startup.
	waitFor(t, what, 90*time.Second, func() bool {
		res, failure := e.s.mcpToolTry(t, e.token, "interactive_session_exec", map[string]any{
			"session": e2eSessionName, "command": "echo e2e-$((6*7))", "wait_seconds": 60,
		})
		out = res + failure
		return failure == "" && strings.Contains(res, "e2e-42")
	})
	if !strings.Contains(out, "exit code 0") {
		t.Errorf("%s: %s", what, out)
	}
}

// afterReassignment: the assignment moves to ap1. The session stays
// where it is -- the same name reaches the same job on ap2, nothing
// appears on ap1, and a second session of that name is refused.
func (e *e2eSession) afterReassignment(t *testing.T) {
	t.Helper()
	dom := e.s.harness.GetTrustDomain()
	e.s.writeAssignment(t, true, fmt.Sprintf("USER %s@%s %s\n", e.s.me, dom, e2eAP1), e2eAP1)
	e.exec(t, "a command in the session after the assignment moved to "+e2eAP1)
	if got := e.on(t, e2eAP1); len(got) != 0 {
		t.Errorf("the reassignment put a session on %s: %v", e2eAP1, got)
	}
	if got := e.on(t, e2eAP2); len(got) != 2 || got[0] != e.on2[0] {
		t.Errorf("the session on %s is now %v, want %v", e2eAP2, got, e.on2)
	}
	list := e.s.mcpTool(t, e.token, "interactive_session_list", nil)
	if !strings.Contains(list, e.job.String()) || !strings.Contains(list, "on access point "+e2eAP2) {
		t.Errorf("interactive_session_list does not show %s: %s", e.job, list)
	}
	if _, failure := e.s.mcpToolTry(t, e.token, "interactive_session_start", map[string]any{"session": e2eSessionName}); !strings.Contains(failure, "already exists") {
		t.Errorf("a second %q was not refused: %q", e2eSessionName, failure)
	}
	// The REST listing, from the hub, names the session's AP.
	waitFor(t, "the session in GET /api/v1/interactive/terminal", 60*time.Second, func() bool {
		code, body := e.s.get(t, e.s.me, "/api/v1/interactive/terminal")
		var resp struct {
			Terminals []InteractiveTerminalSummary `json:"terminals"`
		}
		if code != http.StatusOK || json.Unmarshal([]byte(body), &resp) != nil {
			return false
		}
		for _, tm := range resp.Terminals {
			if tm.Name == e2eSessionName && tm.Schedd == e2eAP2 && tm.JobID == e.job.String() {
				return true
			}
		}
		return false
	})
}

// stop removes the session on ap2.
func (e *e2eSession) stop(t *testing.T) {
	t.Helper()
	text := e.s.mcpTool(t, e.token, "interactive_session_stop", map[string]any{"session": e2eSessionName})
	if !strings.Contains(text, e.job.String()) {
		t.Errorf("stop names a job other than %s: %s", e.job, text)
	}
	waitFor(t, e.job.String()+" to leave the live queue on "+e2eAP2, 60*time.Second, func() bool {
		st := e.on(t, e2eAP2)
		return len(st) == 0 || (len(st) == 2 && (st[1] == "3" || st[1] == "4"))
	})
}

// condorOut runs an HTCondor tool for a diagnostic, whatever it exits
// with.
func (s *multiAPStack) condorOut(tool string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, tool, args...) //nolint:gosec // HTCondor tools with test-built arguments
	cmd.Env = append(os.Environ(), "CONDOR_CONFIG="+s.cfgFile)
	out, _ := cmd.CombinedOutput()
	return string(out)
}
