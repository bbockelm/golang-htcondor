//go:build integration

package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/apassign"
)

// The submit phases of TestMultiAPEndToEnd: AP assignment from a real
// mapfile places new work, and everything is checked on the schedds
// themselves, in both directions -- the job is on the assigned AP, and
// nothing new is on the other one.

// e2eAssignMap is where the stack's assignment mapfile lives.
func (s *multiAPStack) assignMapPath() string { return filepath.Join(s.dir, "assign.map") }

// e2eInitialAssignment sends the test user to ap2 and the other user to
// ap1.
func (s *multiAPStack) e2eInitialAssignment() string {
	return fmt.Sprintf("USER %s@%s %s\nUSER %s@%s %s\n",
		s.me, s.harness.GetTrustDomain(), e2eAP2, e2eOther, s.harness.GetTrustDomain(), e2eAP1)
}

// writeAssignment rewrites the mapfile and waits until the server's
// answer for the test user is wantHome with exactly wantAlts. Nothing
// tells the server: it notices the edit itself.
func (s *multiAPStack) writeAssignment(t *testing.T, text, wantHome string, wantAlts ...string) {
	t.Helper()
	if err := os.WriteFile(s.assignMapPath(), []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	// A new modification time whatever the filesystem's resolution.
	s.assignEdits++
	when := time.Now().Add(time.Duration(s.assignEdits) * time.Minute)
	if err := os.Chtimes(s.assignMapPath(), when, when); err != nil {
		t.Fatal(err)
	}
	waitFor(t, fmt.Sprintf("the server to assign the test user to %s %v", wantHome, wantAlts), 30*time.Second, func() bool {
		a := s.assignmentOf(t, s.me)
		return a != nil && a.Schedd == wantHome && strings.Join(a.Alternates, " ") == strings.Join(wantAlts, " ")
	})
}

// assignmentOf is GET /api/v1/whoami's assignment for user.
func (s *multiAPStack) assignmentOf(t *testing.T, user string) *APAssignmentInfo {
	t.Helper()
	code, body := s.get(t, user, "/api/v1/whoami")
	var who WhoAmIResponse
	if code != http.StatusOK || json.Unmarshal([]byte(body), &who) != nil {
		t.Fatalf("whoami as %s = %d %s", user, code, body)
	}
	return who.Assignment
}

// restSubmit POSTs a submit file and decodes the answer.
func (s *multiAPStack) restSubmit(t *testing.T, query, submitFile string) (int, JobSubmitResponse, string) {
	t.Helper()
	body, _ := json.Marshal(JobSubmitRequest{SubmitFile: submitFile})
	code, out := s.do(t, s.me, http.MethodPost, "/api/v1/jobs"+query, string(body))
	var resp JobSubmitResponse
	_ = json.Unmarshal([]byte(out), &resp)
	return code, resp, out
}

// markedOn lists the clusters on schedd whose E2ESubmitted is marker.
func (s *multiAPStack) markedOn(t *testing.T, schedd, marker string) []string {
	t.Helper()
	out := s.condor(t, "condor_q", "-name", schedd, "-allusers", "-constraint",
		fmt.Sprintf("E2ESubmitted =?= %q", marker), "-af", "ClusterId")
	return strings.Fields(out)
}

// assertOnlyOn checks a marked submission is on want, exactly once, and
// not on the other AP.
func (s *multiAPStack) assertOnlyOn(t *testing.T, marker, want string, cluster int) {
	t.Helper()
	other := e2eAP1
	if want == e2eAP1 {
		other = e2eAP2
	}
	if got := s.markedOn(t, want, marker); len(got) != 1 || got[0] != fmt.Sprint(cluster) {
		t.Errorf("%s: on %s the marked clusters are %v, want exactly [%d]", marker, want, got, cluster)
	}
	if got := s.markedOn(t, other, marker); len(got) != 0 {
		t.Errorf("%s: also on %s as %v", marker, other, got)
	}
}

// purge removes a job this phase submitted, completed or not, so the
// test user's queue is what it was.
func (s *multiAPStack) purge(schedd, id string) {
	s.condorQuiet("condor_rm", "-name", schedd, id)
	s.condorQuiet("condor_rm", "-name", schedd, "-forcex", id)
}

func e2eMarker(what string) string { return fmt.Sprintf("%s-%d", what, time.Now().UnixNano()) }

// e2eSubmitTwoStep: POST /api/v1/jobs lands on the assigned AP (ap2),
// the hub lists it there once, the mapfile is changed to ap1 before the
// input arrives, and the input still reaches ap2 by the job's id; the job
// runs there and its output reads back. The next submission goes to ap1.
func e2eSubmitTwoStep(t *testing.T, s *multiAPStack) {
	if a := s.assignmentOf(t, e2eOther); a == nil || a.Schedd != e2eAP1 {
		t.Errorf("the other user's assignment = %+v, want %s", a, e2eAP1)
	}
	if a := s.assignmentOf(t, s.me); a == nil || a.Schedd != e2eAP2 || a.Source != apassign.BackendMapfile {
		t.Fatalf("the test user's assignment = %+v, want %s from the mapfile", a, e2eAP2)
	}
	ap1Before := s.queueState(t, e2eAP1)

	marker := e2eMarker("two-step")
	code, resp, body := s.restSubmit(t, "", "executable = /bin/cat\narguments = input.txt\ntransfer_executable = false\n"+
		"transfer_input_files = input.txt\nshould_transfer_files = YES\nwhen_to_transfer_output = ON_EXIT\n"+
		"output = out.txt\nerror = err.txt\n+E2ERun = true\n+E2ESubmitted = \""+marker+"\"\nqueue\n")
	if code != http.StatusCreated {
		t.Fatalf("POST /api/v1/jobs = %d %s", code, body)
	}
	k := apJob{e2eAP2, int64(resp.ClusterID), 0}
	t.Cleanup(func() { s.purge(k.schedd, k.local()) })
	if resp.Schedd != e2eAP2 || len(resp.JobIDs) != 1 || resp.JobIDs[0] != k.String() ||
		len(resp.Jobs) != 1 || resp.Jobs[0].Schedd != e2eAP2 || resp.Assignment == nil || resp.Assignment.Source != "mapfile" {
		t.Fatalf("submit answer %s, want %s on %s", body, k, e2eAP2)
	}
	// On schedd2 itself, waiting for its input; nothing new on ap1.
	s.assertOnlyOn(t, marker, e2eAP2, resp.ClusterID)
	if got := s.scheddAttr(t, e2eAP2, k, "HoldReasonCode"); got != "16" {
		t.Fatalf("%s HoldReasonCode = %q, want 16 (awaiting input)", k, got)
	}
	if after := s.queueState(t, e2eAP1); after != ap1Before {
		t.Errorf("submitting to ap2 changed ap1's queue:\nbefore %s\nafter  %s", ap1Before, after)
	}
	// Through the hub: on ap2, once.
	s.waitList(t, k.String()+" to reach the hub listing", 60*time.Second, s.me, func(l e2eList) bool {
		n := 0
		for _, r := range l.Jobs {
			if r.raw["E2ESubmitted"] == marker {
				if r.key() != k {
					t.Fatalf("the hub lists %s's submission as %s", marker, r.key())
				}
				n++
			}
		}
		return n == 1
	})

	// The site moves the test user to ap1 between the steps.
	s.writeAssignment(t, fmt.Sprintf("USER %s@%s %s\n", s.me, s.harness.GetTrustDomain(), e2eAP1), e2eAP1)

	// Step two names the job; it goes to ap2, where the job is.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPut,
		s.baseURL+"/api/v1/jobs/"+url.PathEscape(k.String())+"/input",
		bytes.NewReader(e2eInputTar(t, "input.txt", "hello from the two-step submit\n")))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Test-User", s.me)
	req.Header.Set("Content-Type", "application/x-tar")
	put, err := s.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = put.Body.Close()
	if put.StatusCode != http.StatusOK {
		t.Fatalf("PUT input for %s = %d", k, put.StatusCode)
	}
	waitFor(t, k.String()+" to run and complete on ap2", 120*time.Second, func() bool {
		return s.scheddAttr(t, e2eAP2, k, "JobStatus") == "4"
	})
	if code, out := s.get(t, s.me, "/api/v1/jobs/"+url.PathEscape(k.String())+"/stdout"); code != http.StatusOK ||
		!strings.Contains(out, "hello from the two-step submit") {
		t.Errorf("stdout of %s = %d %q", k, code, out)
	}
	if after := s.queueState(t, e2eAP1); after != ap1Before {
		t.Errorf("the second step changed ap1's queue:\nbefore %s\nafter  %s", ap1Before, after)
	}

	// The next submission follows the new assignment.
	next := e2eMarker("after-move")
	code, resp, body = s.restSubmit(t, "", "executable = /bin/sleep\narguments = 600\ntransfer_executable = false\n"+
		"+E2ESubmitted = \""+next+"\"\nqueue\n")
	if code != http.StatusCreated || resp.Schedd != e2eAP1 {
		t.Fatalf("submit after the move = %d %s, want it on %s", code, body, e2eAP1)
	}
	t.Cleanup(func() { s.purge(e2eAP1, fmt.Sprint(resp.ClusterID)) })
	s.assertOnlyOn(t, next, e2eAP1, resp.ClusterID)
}

// e2eSubmitExplicitTarget: ?schedd= naming an AP that is neither home nor
// an alternate is refused and creates nothing; once the mapfile makes it
// an alternate, the submission lands there.
func e2eSubmitExplicitTarget(t *testing.T, s *multiAPStack) {
	dom := s.harness.GetTrustDomain()
	s.writeAssignment(t, fmt.Sprintf("USER %s@%s %s\n", s.me, dom, e2eAP2), e2eAP2)
	ap1Before := s.queueState(t, e2eAP1)
	refused := e2eMarker("refused")
	sub := func(marker string) string {
		return "executable = /bin/sleep\narguments = 600\ntransfer_executable = false\n+E2ESubmitted = \"" + marker + "\"\nqueue\n"
	}
	code, _, body := s.restSubmit(t, "?schedd="+url.QueryEscape(e2eAP1), sub(refused))
	var refusal struct {
		Reason string `json:"reason"`
	}
	if code != http.StatusForbidden || json.Unmarshal([]byte(body), &refusal) != nil || refusal.Reason != apassign.ReasonTargetNotAllowed {
		t.Errorf("submit to a non-alternate = %d %s, want 403 %s", code, body, apassign.ReasonTargetNotAllowed)
	}
	if after := s.queueState(t, e2eAP1); after != ap1Before {
		t.Errorf("a refused submission changed ap1's queue:\nbefore %s\nafter  %s", ap1Before, after)
	}
	if got := s.markedOn(t, e2eAP2, refused); len(got) != 0 {
		t.Errorf("a refused submission landed on the home AP: %v", got)
	}

	// ap1 becomes an alternate.
	s.writeAssignment(t, fmt.Sprintf("# home, then alternates\nUSER %s@%s %s %s\n", s.me, dom, e2eAP2, e2eAP1), e2eAP2, e2eAP1)
	allowed := e2eMarker("alternate")
	code, resp, body := s.restSubmit(t, "?schedd="+url.QueryEscape(e2eAP1), sub(allowed))
	if code != http.StatusCreated || resp.Schedd != e2eAP1 {
		t.Fatalf("submit to the alternate = %d %s", code, body)
	}
	t.Cleanup(func() { s.purge(e2eAP1, fmt.Sprint(resp.ClusterID)) })
	s.assertOnlyOn(t, allowed, e2eAP1, resp.ClusterID)

	// /api/v1/aps marks both, and only the home AP as home.
	code, body = s.get(t, s.me, "/api/v1/aps")
	var aps APsResponse
	if code != http.StatusOK || json.Unmarshal([]byte(body), &aps) != nil {
		t.Fatalf("aps = %d %s", code, body)
	}
	for _, a := range aps.APs {
		if !a.Submit || a.Home != (a.Schedd == e2eAP2) {
			t.Errorf("aps: %s submit=%v home=%v", a.Schedd, a.Submit, a.Home)
		}
	}
}

// e2eSubmitMCP: MCP submit_job lands on the home AP, answers with the
// complete id, and refuses a schedd that is not an alternate. Runs after
// e2eSubmitExplicitTarget, which left ap1 an alternate: the reassignment
// back to ap2 alone must be in force before the refusal is asked for.
func e2eSubmitMCP(t *testing.T, s *multiAPStack) {
	dom := s.harness.GetTrustDomain()
	s.writeAssignment(t, fmt.Sprintf("USER %s@%s %s\n", s.me, dom, e2eAP2), e2eAP2)
	token := s.writeToken(t, s.me)
	if text := s.mcpTool(t, token, "whoami", nil); !strings.Contains(text, `"home_access_point": "`+e2eAP2+`"`) {
		t.Errorf("MCP whoami does not name the home AP: %s", text)
	}
	marker := e2eMarker("mcp")
	text := s.mcpTool(t, token, "submit_job", map[string]any{"submit_file": "executable = /bin/sleep\narguments = 600\n" +
		"transfer_executable = false\n+E2ESubmitted = \"" + marker + "\"\nqueue\n"})
	clusters := s.markedOn(t, e2eAP2, marker)
	if len(clusters) != 1 {
		t.Fatalf("submit_job: marked clusters on %s = %v, want one\n%s", e2eAP2, clusters, text)
	}
	t.Cleanup(func() { s.purge(e2eAP2, clusters[0]) })
	var cluster int
	_, _ = fmt.Sscan(clusters[0], &cluster)
	s.assertOnlyOn(t, marker, e2eAP2, cluster)
	full := fmt.Sprintf("%d.0@%s", cluster, e2eAP2)
	if !strings.Contains(text, full) || !strings.Contains(text, "submitted to access point "+e2eAP2) {
		t.Errorf("submit_job answer does not name %s on %s: %s", full, e2eAP2, text)
	}

	refused := e2eMarker("mcp-refused")
	ap1Before := s.queueState(t, e2eAP1)
	_, failure := s.mcpToolTry(t, token, "submit_job", map[string]any{"schedd": e2eAP1, "submit_file": "executable = /bin/sleep\n" +
		"arguments = 600\ntransfer_executable = false\n+E2ESubmitted = \"" + refused + "\"\nqueue\n"})
	if !strings.Contains(failure, "you may submit to "+e2eAP2) {
		t.Errorf("submit_job to %s: %q, want the not-an-alternate refusal", e2eAP1, failure)
	}
	if after := s.queueState(t, e2eAP1); after != ap1Before {
		t.Errorf("a refused MCP submission changed ap1's queue:\nbefore %s\nafter  %s", ap1Before, after)
	}
}
