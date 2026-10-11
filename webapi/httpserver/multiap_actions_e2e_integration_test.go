//go:build integration

package httpserver

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/cedar/security"

	htcondor "github.com/bbockelm/golang-htcondor"
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
	direct := s.submitAwaitingInput(t, e2eAP2)
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
	// Out of the way of the phases that count the caller's jobs.
	s.condorRm(t, direct)
	s.condorRm(t, shared)
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
