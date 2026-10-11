//go:build integration

package httpserver

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/cedar/security"
	"github.com/gorilla/websocket"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/mcpserver"
	"github.com/bbockelm/golang-htcondor/webapi/multiap"
)

// The action phases of TestMultiAPEndToEnd. Every action is asserted on
// the schedds themselves, in both directions: it happened on the job's
// AP, and the same-numbered job on the other AP is untouched.

// e2eRefusesUnserved: what multi-AP mode does not do yet is still a
// 501, and a mutation on a bare id is a 400 naming both candidates.
func e2eRefusesUnserved(t *testing.T, s *multiAPStack) {
	code, body := s.do(t, s.me, http.MethodPost, "/api/v1/jobs", `{"submit_file":"executable=/bin/true\nqueue\n"}`)
	if code != http.StatusNotImplemented {
		t.Errorf("POST /api/v1/jobs = %d %s, want 501", code, body)
	}
	code, body = s.do(t, s.me, http.MethodDelete, "/api/v1/jobs/1.0", "")
	var refusal struct {
		Reason     string           `json:"reason"`
		Candidates []multiap.JobRef `json:"candidates"`
	}
	if code != http.StatusBadRequest || json.Unmarshal([]byte(body), &refusal) != nil ||
		refusal.Reason != multiap.ReasonIncompleteID || len(refusal.Candidates) != 2 {
		t.Errorf("DELETE /api/v1/jobs/1.0 = %d %s, want 400 naming both 1.0s", code, body)
	}
	for _, k := range []apJob{e2eAP1Job1, e2eAP2Job1} {
		if got := s.scheddAttr(t, k.schedd, k, "JobStatus"); got != "1" {
			t.Errorf("%s has JobStatus %q after a refused DELETE", k, got)
		}
	}
}

// e2eTrustProbe: both members accept the server's tokens.
func e2eTrustProbe(t *testing.T, s *multiAPStack) {
	waitFor(t, "both APs to pass the trust probe", 60*time.Second, func() bool {
		n := 0
		for _, a := range s.aps(t).APs {
			if a.Trust.State == "trusted" && a.Trust.Actions {
				n++
			}
		}
		return n == 2
	})
}

// e2eSingleJobActions: hold, release and edit 1.0 on ap2 through REST,
// and hold and release 2.0 on ap2 through MCP, land on schedd2 only.
func e2eSingleJobActions(t *testing.T, s *multiAPStack) {
	// Whatever happens here, the next phase starts with the jobs idle.
	t.Cleanup(func() {
		for _, k := range []apJob{e2eAP2Job1, e2eAP2Job2} {
			s.condorQuiet("condor_release", "-name", k.schedd, k.local())
		}
	})
	ap1Before := s.queueState(t, e2eAP1)
	t.Cleanup(func() {
		if after := s.queueState(t, e2eAP1); after != ap1Before {
			t.Errorf("actions on ap2 changed ap1's queue:\nbefore %s\nafter  %s", ap1Before, after)
		}
	})
	path := "/api/v1/jobs/" + url.PathEscape(e2eAP2Job1.String())
	status := func(k apJob) string { return s.scheddAttr(t, k.schedd, k, "JobStatus") }

	if code, body := s.do(t, s.me, http.MethodPost, path+"/hold", `{"reason":"e2e"}`); code != http.StatusOK {
		t.Fatalf("hold %s = %d %s", e2eAP2Job1, code, body)
	}
	if got := status(e2eAP2Job1); got != "5" {
		t.Errorf("%s after hold: JobStatus %q, want 5", e2eAP2Job1, got)
	}
	if got := status(e2eAP1Job1); got != "1" {
		t.Errorf("hold %s reached %s: JobStatus %q", e2eAP2Job1, e2eAP1Job1, got)
	}
	if code, body := s.do(t, s.me, http.MethodPost, path+"/release", ""); code != http.StatusOK {
		t.Fatalf("release %s = %d %s", e2eAP2Job1, code, body)
	}
	if got := status(e2eAP2Job1); got != "1" {
		t.Errorf("%s after release: JobStatus %q, want 1", e2eAP2Job1, got)
	}

	if code, body := s.do(t, s.me, http.MethodPatch, path, `{"attributes":{"E2EMarker":42}}`); code != http.StatusOK {
		t.Fatalf("edit %s = %d %s", e2eAP2Job1, code, body)
	}
	if got := s.scheddAttr(t, e2eAP2, e2eAP2Job1, "E2EMarker"); got != "42" {
		t.Errorf("%s E2EMarker = %q, want 42", e2eAP2Job1, got)
	}
	if got := s.scheddAttr(t, e2eAP1, e2eAP1Job1, "E2EMarker"); got != "undefined" {
		t.Errorf("edit %s reached %s: E2EMarker = %q", e2eAP2Job1, e2eAP1Job1, got)
	}

	// MCP, with a bearer IDTOKEN that may write.
	token := s.writeToken(t, s.me)
	text := s.mcpTool(t, token, "hold_job", map[string]any{"job_id": e2eAP2Job2.String(), "reason": "e2e mcp"})
	if !strings.Contains(text, e2eAP2) {
		t.Errorf("hold_job answer does not name the AP: %s", text)
	}
	if got := status(e2eAP2Job2); got != "5" {
		t.Errorf("%s after hold_job: JobStatus %q, want 5", e2eAP2Job2, got)
	}
	if got := status(e2eAP1Job2); got != "1" {
		t.Errorf("hold_job %s reached %s: JobStatus %q", e2eAP2Job2, e2eAP1Job2, got)
	}
	s.mcpTool(t, token, "release_job", map[string]any{"job_id": e2eAP2Job2.String()})
	if got := status(e2eAP2Job2); got != "1" {
		t.Errorf("%s after release_job: JobStatus %q, want 1", e2eAP2Job2, got)
	}
}

// e2eBulkHold: a bulk hold reaches both APs, reports each, and holds
// exactly the caller's matching jobs -- not the other user's.
func e2eBulkHold(t *testing.T, s *multiAPStack) {
	t.Cleanup(func() {
		for _, k := range e2eMine {
			s.condorQuiet("condor_release", "-name", k.schedd, k.local())
		}
	})
	code, body := s.do(t, s.me, http.MethodPost, "/api/v1/jobs/hold", `{"constraint":"JobStatus == 1","reason":"e2e bulk"}`)
	var rep MultiAPBulkResponse
	if code != http.StatusOK || json.Unmarshal([]byte(body), &rep) != nil {
		t.Fatalf("bulk hold = %d %s", code, body)
	}
	got := map[string]multiap.BulkAPResult{}
	for _, a := range rep.APs {
		got[a.Schedd] = a
	}
	for _, ap := range []string{e2eAP1, e2eAP2} {
		if a := got[ap]; a.Status != multiap.BulkActed || a.Counts == nil || a.Counts.Success != 2 {
			t.Errorf("%s: %+v, want 2 of the caller's jobs held", ap, a)
		}
	}
	if !rep.Complete || rep.Totals.Success != 4 {
		t.Errorf("report: complete=%v totals=%+v", rep.Complete, rep.Totals)
	}
	for _, k := range e2eMine {
		if st := s.scheddAttr(t, k.schedd, k, "JobStatus"); st != "5" {
			t.Errorf("%s after bulk hold: JobStatus %q", k, st)
		}
	}
	if st := s.scheddAttr(t, e2eAP1, e2eAP1Other, "JobStatus"); st != "1" {
		t.Errorf("the other user's %s was held by a bulk hold: JobStatus %q", e2eAP1Other, st)
	}
	code, body = s.do(t, s.me, http.MethodPost, "/api/v1/jobs/release", `{"constraint":"JobStatus == 5"}`)
	if code != http.StatusOK {
		t.Fatalf("bulk release = %d %s", code, body)
	}
	for _, k := range e2eMine {
		if st := s.scheddAttr(t, k.schedd, k, "JobStatus"); st != "1" {
			t.Errorf("%s after bulk release: JobStatus %q", k, st)
		}
	}
}

// e2eSpoolAndShare: input uploaded through the API, and through a share
// URL minted for a job on ap2, spools into schedd2's job.
func e2eSpoolAndShare(t *testing.T, s *multiAPStack) {
	ap1Before := s.queueState(t, e2eAP1)
	t.Cleanup(func() {
		if after := s.queueState(t, e2eAP1); after != ap1Before {
			t.Errorf("spooling into ap2 changed ap1's queue:\nbefore %s\nafter  %s", ap1Before, after)
		}
	})
	direct := s.submitAwaitingInput(t, e2eAP2)
	t.Cleanup(func() { s.condorQuiet("condor_rm", "-name", direct.schedd, direct.local()) })
	tarball := e2eInputTar(t, "input.txt", "hello from the API\n")
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPut,
		s.baseURL+"/api/v1/jobs/"+url.PathEscape(direct.String())+"/input", bytes.NewReader(tarball))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Test-User", s.me)
	req.Header.Set("Content-Type", "application/x-tar")
	resp, err := s.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT input for %s = %d", direct, resp.StatusCode)
	}
	s.waitSpooled(t, direct)

	shared := s.submitAwaitingInput(t, e2eAP2)
	t.Cleanup(func() { s.condorQuiet("condor_rm", "-name", shared.schedd, shared.local()) })
	code, body := s.do(t, s.me, http.MethodPost, "/api/v1/jobs/"+url.PathEscape(shared.String())+"/input/share", "")
	var minted ShareInputResponse
	if code != http.StatusOK || json.Unmarshal([]byte(body), &minted) != nil || len(minted.Uploads) != 1 {
		t.Fatalf("mint input share for %s = %d %s", shared, code, body)
	}
	if minted.Uploads[0].JobID != shared.String() {
		t.Errorf("minted for %q, want %s", minted.Uploads[0].JobID, shared)
	}
	put, err := http.NewRequestWithContext(context.Background(), http.MethodPut, minted.Uploads[0].URL,
		bytes.NewReader(e2eInputTar(t, "input.txt", "hello from a share URL\n")))
	if err != nil {
		t.Fatal(err)
	}
	resp, err = s.client.Do(put)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("redeeming the share URL = %d", resp.StatusCode)
	}
	s.waitSpooled(t, shared)

	// And through an upload URL minted over MCP: the URL names ap2.
	viaMCP := s.submitAwaitingInput(t, e2eAP2)
	t.Cleanup(func() { s.condorQuiet("condor_rm", "-name", viaMCP.schedd, viaMCP.local()) })
	text := s.mcpTool(t, s.writeToken(t, s.me), "create_input_upload_url", map[string]any{"job_id": viaMCP.String()})
	up := firstURL(text)
	if up == "" {
		t.Fatalf("no URL in create_input_upload_url: %s", text)
	}
	put, err = http.NewRequestWithContext(context.Background(), http.MethodPut, up,
		bytes.NewReader(e2eInputTar(t, "input.txt", "hello from an MCP upload URL\n")))
	if err != nil {
		t.Fatal(err)
	}
	resp, err = s.client.Do(put)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("redeeming the MCP upload URL = %d", resp.StatusCode)
	}
	s.waitSpooled(t, viaMCP)
}

// e2eBulkContactsStaleAP: with ap2's spoke stopped, a job submitted to
// ap2 is invisible to the hub -- and a bulk hold still finds it, because
// a stale AP is always contacted.
func e2eBulkContactsStaleAP(t *testing.T, s *multiAPStack) {
	s.submit(t, e2eAP2, `+E2ELate = true`+"\n")
	late := s.lastCluster(t, e2eAP2)
	code, body := s.do(t, s.me, http.MethodPost, "/api/v1/jobs/hold", `{"constraint":"E2ELate =?= true"}`)
	var rep MultiAPBulkResponse
	if code != http.StatusOK || json.Unmarshal([]byte(body), &rep) != nil {
		t.Fatalf("bulk hold with %s stale = %d %s", e2eAP2, code, body)
	}
	got := map[string]string{}
	for _, a := range rep.APs {
		got[a.Schedd] = a.Status
	}
	// ap1 may be skipped on the hub's word, or contacted anyway if this
	// server changed something there more recently than the hub's copy
	// (the previous phase's DELETE) -- both are right; acting is not.
	if got[e2eAP2] != multiap.BulkActed || (got[e2eAP1] != multiap.BulkSkipped && got[e2eAP1] != multiap.BulkNoMatch) {
		t.Errorf("per-AP = %v, want %s acted (stale, contacted) and %s skipped or no_match", got, e2eAP2, e2eAP1)
	}
	t.Logf("with %s stale: %v", e2eAP2, got)
	if st := s.scheddAttr(t, e2eAP2, late, "JobStatus"); st != "5" {
		t.Errorf("the job the hub had not seen (%s) was not held: JobStatus %q", late, st)
	}
	s.condorRm(t, late)
}

// e2eRemoveViaAPI: DELETE of 2.0 on ap1 removes it there; ap2's 2.0
// stays. Then the removal reaches the list and history through the hub.
func e2eRemoveViaAPI(t *testing.T, s *multiAPStack) {
	code, body := s.do(t, s.me, http.MethodDelete, "/api/v1/jobs/"+url.PathEscape(e2eAP1Job2.String()), "")
	if code != http.StatusOK {
		t.Fatalf("DELETE %s = %d %s", e2eAP1Job2, code, body)
	}
	if st := s.scheddAttr(t, e2eAP2, e2eAP2Job2, "JobStatus"); st != "1" {
		t.Errorf("DELETE %s reached %s: JobStatus %q", e2eAP1Job2, e2eAP2Job2, st)
	}
	s.waitList(t, e2eAP1Job2.String()+" to leave the list", 60*time.Second, s.me, func(l e2eList) bool {
		return sameJobs(l.keys(), []apJob{e2eAP1Job1, e2eAP2Job1, e2eAP2Job2})
	})
	s.waitArchive(t, e2eAP1Job2)
}

// --- helpers ----------------------------------------------------------------

// writeToken is mintToken with WRITE, for MCP actions.
func (s *multiAPStack) writeToken(t *testing.T, user string) string {
	t.Helper()
	now := time.Now().Unix()
	tok, err := security.GenerateJWT(s.harness.GetPasswordDir(), "POOL", user+"@"+s.harness.GetTrustDomain(),
		s.harness.GetTrustDomain(), now-60, now+900, []string{"READ", "WRITE"})
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}
	return tok
}

// lastCluster is the newest cluster on schedd that belongs to the test
// user.
func (s *multiAPStack) lastCluster(t *testing.T, schedd string) apJob {
	t.Helper()
	out := strings.Fields(s.condor(t, "condor_q", "-name", schedd, "-af", "ClusterId"))
	if len(out) == 0 {
		t.Fatalf("no jobs on %s", schedd)
	}
	var newest int64
	for _, f := range out {
		var c int64
		if _, err := fmt.Sscan(f, &c); err == nil && c > newest {
			newest = c
		}
	}
	return apJob{schedd, newest, 0}
}

// submitAwaitingInput queues a job on schedd as the test user without
// spooling its input, so it waits (held, code 16) for an upload.
func (s *multiAPStack) submitAwaitingInput(t *testing.T, schedd string) apJob {
	t.Helper()
	cfg, err := s.harness.GetConfig()
	if err != nil {
		t.Fatal(err)
	}
	coll := htcondor.NewCollector(s.harness.GetCollectorAddr())
	ctx, cancel := context.WithTimeout(htcondor.WithDaemonCredential(context.Background(), "e2e submit"), time.Minute)
	defer cancel()
	ads, _, err := coll.QueryAdsWithOptions(ctx, "Schedd", fmt.Sprintf("Name == %q", schedd),
		&htcondor.QueryOptions{Limit: -1, Projection: []string{"Name", "MyAddress"}})
	if err != nil || len(ads) != 1 {
		t.Fatalf("locating %s: %v (%d ads)", schedd, err, len(ads))
	}
	addr, _ := ads[0].EvaluateAttrString("MyAddress")
	sch := htcondor.NewSchedd(schedd, addr).WithConfig(cfg)
	cluster, _, err := sch.SubmitRemote(ctx, "executable = /bin/cat\narguments = input.txt\ntransfer_executable = false\n"+
		"transfer_input_files = input.txt\nshould_transfer_files = YES\nqueue\n")
	if err != nil {
		t.Fatalf("SubmitRemote to %s: %v", schedd, err)
	}
	k := apJob{schedd, int64(cluster), 0}
	if st := s.scheddAttr(t, schedd, k, "HoldReasonCode"); st != "16" {
		t.Fatalf("%s is not awaiting input: HoldReasonCode %q", k, st)
	}
	return k
}

// waitSpooled waits for k to leave the spooling hold on its own schedd.
func (s *multiAPStack) waitSpooled(t *testing.T, k apJob) {
	t.Helper()
	waitFor(t, k.String()+" to leave the input-spooling hold", 30*time.Second, func() bool {
		return s.scheddAttr(t, k.schedd, k, "JobStatus") == "1"
	})
}

func e2eInputTar(t *testing.T, name, content string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), ModTime: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// e2eBulkSkipsProvablyEmpty: with HTTP_API_BULK_FRESH_SECONDS > 0 and
// nothing written by this server yet, a bulk action whose constraint
// matches nothing anywhere skips both fresh APs on the hub's word. A
// broken freshness path (staleness, the jobs-stream gate) contacts them
// instead, which this catches.
func e2eBulkSkipsProvablyEmpty(t *testing.T, s *multiAPStack) {
	var last string
	waitFor(t, "a bulk action matching nothing to skip both APs", 45*time.Second, func() bool {
		code, body := s.do(t, s.me, http.MethodPost, "/api/v1/jobs/hold", `{"constraint":"E2ENothing =?= true"}`)
		last = fmt.Sprintf("%d %s", code, body)
		var rep MultiAPBulkResponse
		if json.Unmarshal([]byte(body), &rep) != nil || len(rep.APs) != 2 {
			return false
		}
		for _, a := range rep.APs {
			if a.Status != multiap.BulkSkipped {
				return false
			}
		}
		return code == http.StatusNotFound && rep.Complete
	})
	t.Logf("last answer: %s", last)
}

// e2eRunningJob: a job running on ap2, whose cluster.proc is an idle job
// of the caller's on ap1, is reached through every live-job route on
// ap2; the same calls on ap1's id find a job that is not running.
//
//nolint:gocyclo // one job, every route that reaches into it
func e2eRunningJob(t *testing.T, s *multiAPStack) {
	// ap1's next job, idle, and ap2's job with the same number, running.
	s.submit(t, e2eAP1, "")
	idle := s.lastCluster(t, e2eAP1)
	t.Cleanup(func() { s.condorQuiet("condor_rm", "-name", idle.schedd, idle.local()) })
	for {
		s.submit(t, e2eAP2, "")
		filler := s.lastCluster(t, e2eAP2)
		s.condorQuiet("condor_rm", "-name", filler.schedd, filler.local())
		if filler.cluster+1 >= idle.cluster {
			if filler.cluster+1 != idle.cluster {
				t.Fatalf("cannot line ap2's clusters up with ap1's %s (ap2 is at %s)", idle, filler)
			}
			break
		}
	}
	s.submitSpooled(t, e2eAP2, "executable = /bin/sh\narguments = \"-c 'echo hello-e2e; sleep 25'\"\n"+
		"transfer_executable = false\noutput = out.txt\nerror = err.txt\nshould_transfer_files = YES\n"+
		"when_to_transfer_output = ON_EXIT\n+E2ERun = true\nqueue\n")
	running := apJob{e2eAP2, idle.cluster, 0}
	t.Cleanup(func() { s.condorQuiet("condor_rm", "-name", running.schedd, running.local()) })
	if got := s.lastCluster(t, e2eAP2); got != running {
		t.Fatalf("the running job is %s, want %s", got, running)
	}
	waitFor(t, running.String()+" to run", 90*time.Second, func() bool {
		return s.scheddAttr(t, running.schedd, running, "JobStatus") == "2"
	})
	path := func(k apJob, sub string) string { return "/api/v1/jobs/" + url.PathEscape(k.String()) + sub }

	// Peek, through the starter, on ap2.
	waitFor(t, "peek to show the job's output", 30*time.Second, func() bool {
		code, body := s.get(t, s.me, path(running, "/peek?stream=stdout"))
		return code == http.StatusOK && strings.Contains(body, "hello-e2e")
	})
	if code, body := s.get(t, s.me, path(idle, "/peek?stream=stdout")); code == http.StatusOK || strings.Contains(body, "hello-e2e") {
		t.Errorf("peek on %s (idle) = %d %s, want a failure", idle, code, body)
	}

	// MCP tail_job_output and exec_in_job.
	token := s.writeToken(t, s.me)
	if text := s.mcpTool(t, token, "tail_job_output", map[string]any{"job_id": running.String(), "stream": "stdout"}); !strings.Contains(text, "hello-e2e") {
		t.Errorf("tail_job_output %s = %s", running, text)
	}
	if text, failure := s.mcpToolTry(t, token, "tail_job_output", map[string]any{"job_id": idle.String()}); failure == "" {
		t.Errorf("tail_job_output %s (idle) succeeded: %s", idle, text)
	}
	if s.sshOK {
		if text := s.mcpTool(t, token, "exec_in_job", map[string]any{"job_id": running.String(), "command": "echo exec-ok"}); !strings.Contains(text, "exec-ok") {
			t.Errorf("exec_in_job %s = %s", running, text)
		}
		if text, failure := s.mcpToolTry(t, token, "exec_in_job", map[string]any{"job_id": idle.String(), "command": "echo exec-ok"}); failure == "" {
			t.Errorf("exec_in_job %s (idle) succeeded: %s", idle, text)
		}
		if got := s.wsEcho(t, path(running, "/ssh"), "WS_OK_E2E"); !strings.Contains(got, "WS_OK_E2E") {
			t.Errorf("/ssh on %s never echoed: %q", running, got)
		}
		if got := s.wsEcho(t, path(idle, "/ssh"), "WS_OK_E2E"); strings.Contains(got, "WS_OK_E2E\r\n") {
			t.Errorf("/ssh on %s (idle) echoed a shell: %q", idle, got)
		}
	} else {
		t.Log("no sshd config template here: exec_in_job and /ssh not exercised")
	}

	// Once it finishes, its stdout comes back from ap2's spool, through
	// the API and through an MCP download URL.
	waitFor(t, running.String()+" to finish", 90*time.Second, func() bool {
		return s.scheddAttr(t, running.schedd, running, "JobStatus") == "4"
	})
	if code, body := s.get(t, s.me, path(running, "/stdout")); code != http.StatusOK || !strings.Contains(body, "hello-e2e") {
		t.Errorf("stdout of %s = %d %q", running, code, body)
	}
	if code, body := s.get(t, s.me, path(idle, "/stdout")); code == http.StatusOK && strings.Contains(body, "hello-e2e") {
		t.Errorf("stdout of %s (idle, never ran) = %d %q", idle, code, body)
	}
	text := s.mcpTool(t, token, "create_output_download_url", map[string]any{"job_id": running.String()})
	u := firstURL(text)
	if u == "" {
		t.Fatalf("no URL in create_output_download_url: %s", text)
	}
	resp, err := s.client.Get(u) //nolint:noctx // test
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !bytes.Contains(b, []byte("hello-e2e")) {
		t.Errorf("the download URL for %s = %d (%d bytes), want its output", running, resp.StatusCode, len(b))
	}
}

// --- more helpers --------------------------------------------------------------

func (k apJob) local() string { return fmt.Sprintf("%d.%d", k.cluster, k.proc) }

// condorQuiet runs a tool for cleanup: a failure is logged, not fatal.
func (s *multiAPStack) condorQuiet(tool string, args ...string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, tool, args...) //nolint:gosec // HTCondor tools with test-built arguments
	cmd.Env = append(os.Environ(), "CONDOR_CONFIG="+s.cfgFile)
	_ = cmd.Run()
}

// submitSpooled submits body to schedd with -spool, so the job's output
// stays in the spool after it finishes.
func (s *multiAPStack) submitSpooled(t *testing.T, schedd, body string) {
	t.Helper()
	sub := filepath.Join(s.dir, fmt.Sprintf("job-%d.sub", time.Now().UnixNano()))
	if err := os.WriteFile(sub, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	out := s.condor(t, "condor_submit", "-terse", "-spool", "-name", schedd, sub)
	t.Logf("submitted %s to %s (spooled)", strings.TrimSpace(out), schedd)
}

// mcpToolTry calls a tool and returns its text or its failure.
func (s *multiAPStack) mcpToolTry(t *testing.T, token, name string, args map[string]any) (string, string) {
	t.Helper()
	params, _ := json.Marshal(map[string]any{"name": name, "arguments": args})
	resp := sendMCPRequest(t, s.client, s.baseURL, token, mcpserver.MCPMessage{
		JSONRPC: "2.0", ID: 1, Method: "tools/call", Params: params,
	})
	if msg, failed := mcpToolFailure(t, resp); failed {
		return "", msg
	}
	return toolText(t, resp.Result), ""
}

// wsEcho opens the /ssh bridge, types `echo <sentinel>`, and returns
// what came back within a few seconds.
func (s *multiAPStack) wsEcho(t *testing.T, path, sentinel string) string {
	t.Helper()
	u, err := url.Parse(s.baseURL + path)
	if err != nil {
		t.Fatal(err)
	}
	u.Scheme = "ws"
	hdr := http.Header{}
	hdr.Set("X-Test-User", s.me)
	hdr.Set("Origin", s.baseURL)
	conn, resp, err := (&websocket.Dialer{HandshakeTimeout: 30 * time.Second}).Dial(u.String(), hdr)
	if err != nil {
		if resp != nil {
			b, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			return fmt.Sprintf("handshake %d %s", resp.StatusCode, b)
		}
		return "dial: " + err.Error()
	}
	defer func() { _ = conn.Close() }()
	if err := conn.WriteMessage(websocket.BinaryMessage, []byte("echo "+sentinel+"\n")); err != nil {
		return "write: " + err.Error()
	}
	var got strings.Builder
	deadline := time.Now().Add(20 * time.Second)
	_ = conn.SetReadDeadline(deadline)
	for time.Now().Before(deadline) && !strings.Contains(got.String(), sentinel+"\r\n") {
		mt, payload, err := conn.ReadMessage()
		if err != nil {
			break
		}
		if mt == websocket.TextMessage {
			got.WriteString("[ctl " + string(payload) + "]")
			continue
		}
		got.Write(payload)
	}
	return got.String()
}

// firstURL is the first http(s) URL in text.
func firstURL(text string) string {
	for _, f := range strings.Fields(text) {
		f = strings.Trim(f, `"',()[]<>`)
		if strings.HasPrefix(f, "http://") || strings.HasPrefix(f, "https://") {
			return f
		}
	}
	return ""
}

// queueState is every job on schedd, with its state, for asserting an
// AP was not touched.
func (s *multiAPStack) queueState(t *testing.T, schedd string) string {
	t.Helper()
	return s.condor(t, "condor_q", "-name", schedd, "-allusers", "-af", "ClusterId", "ProcId", "JobStatus", "HoldReasonCode", "E2EMarker")
}
