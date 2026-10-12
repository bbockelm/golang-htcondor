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

func TestMultiAPInteractiveEndToEnd(t *testing.T) {
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

	token := s.writeToken(t, s.me)
	batch := interactive.BatchNameForSession(e2eSessionName)
	sessionOn := func(schedd string) []string {
		return strings.Fields(s.condor(t, "condor_q", "-name", schedd, "-allusers", "-constraint",
			fmt.Sprintf("JobBatchName == %q", batch), "-af", "ClusterId", "JobStatus"))
	}
	t.Cleanup(func() {
		for _, ap := range []string{e2eAP1, e2eAP2} {
			s.condorQuiet("condor_rm", "-name", ap, "-constraint", fmt.Sprintf("JobBatchName == %q", batch))
		}
	})

	// Start: the test user is assigned to ap2.
	ap1Before := s.queueState(t, e2eAP1)
	// Small, so the test pool's one slot fits it whatever this host has.
	text := s.mcpTool(t, token, "interactive_session_start", map[string]any{"session": e2eSessionName,
		"cpus": 1, "memory_mb": 256, "disk_mb": 256})
	if !strings.Contains(text, "on access point "+e2eAP2) {
		t.Errorf("interactive_session_start does not name %s: %s", e2eAP2, text)
	}
	on2 := sessionOn(e2eAP2)
	if len(on2) != 2 {
		t.Fatalf("the session on %s: %v, want exactly one job\n%s", e2eAP2, on2, text)
	}
	if got := sessionOn(e2eAP1); len(got) != 0 {
		t.Fatalf("the session also landed on %s: %v", e2eAP1, got)
	}
	job := apJob{e2eAP2, mustInt(t, on2[0]), 0}
	if !strings.Contains(text, job.String()) {
		t.Errorf("start names a job other than %s: %s", job, text)
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("=== %s on %s ===\n%s", job, e2eAP2, s.condorOut("condor_q", "-name", e2eAP2, "-better-analyze", job.local()))
		}
	})
	waitFor(t, job.String()+" to run", 120*time.Second, func() bool {
		return s.scheddAttr(t, e2eAP2, job, "JobStatus") == "2"
	})

	exec := func(what string) {
		t.Helper()
		var out string
		// The first command waits for the sandbox's sshd; a retry covers a
		// dial that raced the job's own startup.
		waitFor(t, what, 90*time.Second, func() bool {
			res, failure := s.mcpToolTry(t, token, "interactive_session_exec", map[string]any{
				"session": e2eSessionName, "command": "echo e2e-$((6*7))", "wait_seconds": 60,
			})
			out = res + failure
			return failure == "" && strings.Contains(res, "e2e-42")
		})
		if !strings.Contains(out, "exit code 0") {
			t.Errorf("%s: %s", what, out)
		}
	}
	exec("a command to run in the session on " + e2eAP2)

	// The assignment moves to ap1. The session stays where it is: the
	// same name reaches the same job on ap2, and nothing appears on ap1.
	dom := s.harness.GetTrustDomain()
	s.writeAssignment(t, true, fmt.Sprintf("USER %s@%s %s\n", s.me, dom, e2eAP1), e2eAP1)
	exec("a command in the session after the assignment moved to " + e2eAP1)
	if got := sessionOn(e2eAP1); len(got) != 0 {
		t.Errorf("the reassignment put a session on %s: %v", e2eAP1, got)
	}
	if got := sessionOn(e2eAP2); len(got) != 2 || got[0] != on2[0] {
		t.Errorf("the session on %s is now %v, want %v", e2eAP2, got, on2)
	}
	list := s.mcpTool(t, token, "interactive_session_list", nil)
	if !strings.Contains(list, job.String()) || !strings.Contains(list, "on access point "+e2eAP2) {
		t.Errorf("interactive_session_list does not show %s: %s", job, list)
	}
	// A second session of the same name is refused, though the
	// assignment now names the other AP.
	if _, failure := s.mcpToolTry(t, token, "interactive_session_start", map[string]any{"session": e2eSessionName}); !strings.Contains(failure, "already exists") {
		t.Errorf("a second %q was not refused: %q", e2eSessionName, failure)
	}

	// The REST listing, from the hub, names the session's AP.
	waitFor(t, "the session in GET /api/v1/interactive/terminal", 60*time.Second, func() bool {
		code, body := s.get(t, s.me, "/api/v1/interactive/terminal")
		var resp struct {
			Terminals []InteractiveTerminalSummary `json:"terminals"`
		}
		if code != http.StatusOK || json.Unmarshal([]byte(body), &resp) != nil {
			return false
		}
		for _, tm := range resp.Terminals {
			if tm.Name == e2eSessionName && tm.Schedd == e2eAP2 && tm.JobID == job.String() {
				return true
			}
		}
		return false
	})

	// Stop: removed on ap2, and ap1's queue is as it was before the
	// session existed.
	text = s.mcpTool(t, token, "interactive_session_stop", map[string]any{"session": e2eSessionName})
	if !strings.Contains(text, job.String()) {
		t.Errorf("stop names a job other than %s: %s", job, text)
	}
	waitFor(t, job.String()+" to leave the live queue on "+e2eAP2, 60*time.Second, func() bool {
		st := sessionOn(e2eAP2)
		return len(st) == 0 || (len(st) == 2 && (st[1] == "3" || st[1] == "4"))
	})
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
