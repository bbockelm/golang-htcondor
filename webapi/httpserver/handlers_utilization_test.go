package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	"github.com/bbockelm/golang-htcondor/webapi/multiap/multiaptest"
	"github.com/bbockelm/golang-htcondor/webapi/utilization"
)

// historyAd is a finished job as the schedd's history records it.
// MemoryUsage is the schedd's expression over ResidentSetSize, so the
// read has to carry ResidentSetSize for it to mean anything.
func historyAd(t *testing.T, cluster int, owner, cmd string, peakMiB, requestMiB, wall int) *classad.ClassAd {
	t.Helper()
	now := time.Now().Unix()
	text := fmt.Sprintf(`ClusterId = %d
ProcId = 0
Owner = %q
Cmd = %q
JobUniverse = 5
JobStatus = 4
ExitCode = 0
ExitBySignal = false
QDate = %d
EnteredHistoryTime = %d
CompletionDate = %d
RequestCpus = 1
RequestMemory = %d
RequestDisk = 1048576
ResidentSetSize = %d
MemoryUsage = ((ResidentSetSize + 1023) / 1024)
DiskUsage = 204800
RemoteWallClockTime = %d.0
CommittedTime = %d
CumulativeRemoteUserCpu = %d.0
CumulativeRemoteSysCpu = 0.0
NumJobStarts = 1`, cluster, owner, cmd, now-int64(wall)-600, now-60, now-60, requestMiB, peakMiB*1024, wall, wall, wall*9/10)
	ad, err := classad.ParseOld(text)
	if err != nil {
		t.Fatalf("parsing fixture ad: %v", err)
	}
	return ad
}

// utilizationFixture is the two-owner schedd with recent history for
// both: three jobs of alice's (alice_sim) and two of bob's (bob_sim).
func utilizationFixture(t *testing.T) *twoOwnerFixture {
	t.Helper()
	f := twoOwnerScheddServer(t)
	f.schedd.AddHistory(
		historyAd(t, 101, "alice", "/home/alice/alice_sim", 900, 2048, 3600),
		historyAd(t, 102, "alice", "/home/alice/alice_sim", 950, 2048, 3600),
		historyAd(t, 103, "alice", "/home/alice/alice_sim", 1000, 2048, 3600),
		historyAd(t, 201, "bob", "/home/bob/bob_sim", 300, 1024, 1800),
		historyAd(t, 202, "bob", "/home/bob/bob_sim", 310, 1024, 1800),
	)
	return f
}

func (f *twoOwnerFixture) utilization(t *testing.T, path string, auth func(*http.Request)) utilization.Response {
	t.Helper()
	w := f.do(t, http.MethodGet, path, "", auth)
	if w.Code != http.StatusOK {
		t.Fatalf("GET %s: status %d: %s", path, w.Code, w.Body.String())
	}
	var resp utilization.Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding %s: %v", w.Body.String(), err)
	}
	return resp
}

func workflowExecutables(resp utilization.Response) []string {
	var out []string
	for _, w := range resp.Workflows {
		out = append(out, w.Executable)
	}
	slices.Sort(out)
	return out
}

// A non-administrator asking for everyone's jobs still gets only their
// own. Neither the schedd nor the mirror filters history by owner, so the
// scope this server puts on the read is the whole of the enforcement.
func TestUtilizationNonAdminIsConfinedToOwnJobs(t *testing.T) {
	f := utilizationFixture(t)
	for _, auth := range []struct {
		name string
		fn   func(*http.Request)
	}{
		{"bearer", f.bearer(t, "bob")},
		{"session", f.session(t, "bob")},
	} {
		for _, path := range []string{
			"/api/v1/utilization?owned_by_me=false",
			"/api/v1/utilization",
			"/api/v1/utilization?owned_by_me=false&days=30",
		} {
			resp := f.utilization(t, path, auth.fn)
			if got := workflowExecutables(resp); !slices.Equal(got, []string{"bob_sim"}) || resp.JobsConsidered != 2 {
				t.Errorf("%s %s: workflows %v over %d jobs, want only bob's 2", auth.name, path, got, resp.JobsConsidered)
			}
			for _, w := range resp.Workflows {
				if w.Owner != "" {
					t.Errorf("%s %s: owner %q shown in a personal scope", auth.name, path, w.Owner)
				}
			}
		}
	}
}

// An administrator asking for everyone sees everyone, with owners named;
// asking for their own, sees their own. The cache keeps the two apart.
func TestUtilizationAdminSeesEveryone(t *testing.T) {
	f := utilizationFixture(t)
	root := f.bearer(t, "root")

	resp := f.utilization(t, "/api/v1/utilization?owned_by_me=false", root)
	if got := workflowExecutables(resp); !slices.Equal(got, []string{"alice_sim", "bob_sim"}) {
		t.Fatalf("admin pool-wide workflows = %v", got)
	}
	owners := map[string]string{}
	for _, w := range resp.Workflows {
		owners[w.Executable] = w.Owner
	}
	if owners["alice_sim"] != "alice" || owners["bob_sim"] != "bob" {
		t.Errorf("owners = %v", owners)
	}

	if mine := f.utilization(t, "/api/v1/utilization", root); mine.JobsConsidered != 0 || len(mine.Workflows) != 0 {
		t.Errorf("root's own jobs: %d jobs %v, want none", mine.JobsConsidered, workflowExecutables(mine))
	}
	// And a non-admin asking right after the admin does not get the
	// admin's cached answer.
	if got := workflowExecutables(f.utilization(t, "/api/v1/utilization?owned_by_me=false", f.bearer(t, "alice"))); !slices.Equal(got, []string{"alice_sim"}) {
		t.Errorf("alice after the admin: %v", got)
	}
}

// Nothing to analyse is a 200 with zero jobs, not an error.
func TestUtilizationNothingToAnalyse(t *testing.T) {
	f := utilizationFixture(t)
	resp := f.utilization(t, "/api/v1/utilization?days=1", f.bearer(t, "carol"))
	if resp.JobsConsidered != 0 || resp.Workflows == nil || len(resp.Workflows) != 0 || resp.Days != 1 {
		t.Errorf("response = %+v", resp)
	}
	if resp.Until-resp.Since != 86400 {
		t.Errorf("window = [%d, %d], want one day", resp.Since, resp.Until)
	}
}

func TestUtilizationValidatesParameters(t *testing.T) {
	f := utilizationFixture(t)
	bob := f.bearer(t, "bob")
	for _, path := range []string{
		"/api/v1/utilization?days=2",
		"/api/v1/utilization?days=week",
		"/api/v1/utilization?owned_by_me=maybe",
	} {
		if w := f.do(t, http.MethodGet, path, "", bob); w.Code != http.StatusBadRequest {
			t.Errorf("GET %s: status %d, want 400", path, w.Code)
		}
	}
	if w := f.do(t, http.MethodPost, "/api/v1/utilization", "", bob); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: status %d", w.Code)
	}
	if resp := f.utilization(t, "/api/v1/utilization", bob); resp.Days != 7 {
		t.Errorf("default days = %d, want 7", resp.Days)
	}
}

// The schedd path reads MemoryUsage through its expression.
func TestUtilizationEvaluatesMemoryUsage(t *testing.T) {
	f := utilizationFixture(t)
	resp := f.utilization(t, "/api/v1/utilization", f.bearer(t, "alice"))
	if len(resp.Workflows) != 1 {
		t.Fatalf("workflows = %v", workflowExecutables(resp))
	}
	peaks := resp.Workflows[0].Memory.PeakMiB
	if peaks == nil || peaks.N != 3 || peaks.Max != 1000 {
		t.Errorf("peaks = %+v, want 3 jobs peaking at 1000 MiB", peaks)
	}
}

// A first request that goes away mid-computation must not leave an
// error -- or nothing -- behind for the next one. The computation runs on
// its own context and its answer lands in the cache.
func TestUtilizationCacheSurvivesCancelledFirstRequest(t *testing.T) {
	c := newUtilizationCache()
	started := make(chan struct{})
	release := make(chan struct{})
	var computes atomic.Int32
	compute := func(ctx context.Context) (*utilization.Response, error) {
		computes.Add(1)
		close(started)
		<-release
		// The computation's context must still be live after its
		// requester gave up.
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return &utilization.Response{JobsConsidered: 42}, nil
	}

	firstCtx, cancelFirst := context.WithCancel(context.Background())
	firstDone := make(chan error, 1)
	go func() {
		_, err := c.get(firstCtx, "k", compute)
		firstDone <- err
	}()
	<-started
	cancelFirst()
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatalf("the cancelled request's computation failed: %v", err)
	}

	resp, err := c.get(context.Background(), "k", func(context.Context) (*utilization.Response, error) {
		t.Error("recomputed: the first answer was not cached")
		return nil, errors.New("unexpected")
	})
	if err != nil || resp.JobsConsidered != 42 {
		t.Errorf("second request = %+v, %v; want the cached answer", resp, err)
	}
	if computes.Load() != 1 {
		t.Errorf("computed %d times", computes.Load())
	}
}

// Concurrent identical requests cost one computation.
func TestUtilizationCacheSingleFlights(t *testing.T) {
	c := newUtilizationCache()
	var computes atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := c.get(context.Background(), "k", func(context.Context) (*utilization.Response, error) {
				computes.Add(1)
				time.Sleep(20 * time.Millisecond)
				return &utilization.Response{}, nil
			})
			if err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if computes.Load() != 1 {
		t.Errorf("8 concurrent requests computed %d times, want 1", computes.Load())
	}
}

// A failure is not cached, and an expired answer is recomputed.
func TestUtilizationCacheExpiresAndDoesNotCacheErrors(t *testing.T) {
	c := newUtilizationCache()
	now := time.Unix(1700000000, 0)
	c.now = func() time.Time { return now }

	if _, err := c.get(context.Background(), "k", func(context.Context) (*utilization.Response, error) {
		return nil, errors.New("schedd unreachable")
	}); err == nil {
		t.Fatal("error swallowed")
	}
	resp, err := c.get(context.Background(), "k", func(context.Context) (*utilization.Response, error) {
		return &utilization.Response{JobsConsidered: 1}, nil
	})
	if err != nil || resp.JobsConsidered != 1 {
		t.Fatalf("after a failure: %+v, %v", resp, err)
	}
	now = now.Add(utilizationRefresh + time.Second)
	resp, _ = c.get(context.Background(), "k", func(context.Context) (*utilization.Response, error) {
		return &utilization.Response{JobsConsidered: 2}, nil
	})
	if resp.JobsConsidered != 2 {
		t.Errorf("expired answer served: %+v", resp)
	}
}

// putHubHistory appends a history row the way the federation hub stores
// one: ScheddName and User on the row.
func putHubHistory(t *testing.T, hub *multiaptest.DB, schedd, user string, cluster int, cmd string) {
	t.Helper()
	cl, closer, err := hub.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer closer()
	owner, _, _ := strings.Cut(user, "@")
	now := time.Now().Unix()
	ad := fmt.Sprintf(`ScheddName = %q
User = %q
Owner = %q
ClusterId = %d
ProcId = 0
Cmd = %q
JobUniverse = 5
JobStatus = 4
ExitCode = 0
QDate = %d
EnteredHistoryTime = %d
RequestMemory = 2048
RequestCpus = 1
MemoryUsage = 700
RemoteWallClockTime = 3600.0`, schedd, user, owner, cluster, cmd, now-4000, now-60)
	if err := cl.ArchiveAppend(context.Background(), "history", ad); err != nil {
		t.Fatal(err)
	}
}

// In multi-AP mode the analysis covers the caller's jobs on every access
// point, names the access point on each workflow, and the same executable
// on two access points is two workflows.
func TestUtilizationMultiAP(t *testing.T) {
	hub := multiaptest.NewHub(t)
	putHubHistory(t, hub, ap1, "alice@d", 10, "/home/alice/sim")
	putHubHistory(t, hub, ap1, "alice@d", 11, "/home/alice/sim")
	putHubHistory(t, hub, ap2, "alice@d", 10, "/home/alice/sim")
	putHubHistory(t, hub, ap1, "bob@d", 12, "/home/bob/sim")
	hub.PutSource(ap1, "fresh", 2)
	hub.PutSource(ap2, "fresh", 2)
	srv := newMultiAPServer(t, multiAPService(t, hub, multiaptest.NewRegistry(ap1, ap2)))

	rec := doAs(t, srv, "alice", http.MethodGet, "/api/v1/utilization?owned_by_me=false")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var resp utilization.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.JobsConsidered != 3 {
		t.Errorf("jobs = %d, want alice's 3 (bob's excluded)", resp.JobsConsidered)
	}
	jobsBySchedd := map[string]int{}
	for _, w := range resp.Workflows {
		jobsBySchedd[w.Schedd] = w.Jobs
	}
	if jobsBySchedd[ap1] != 2 || jobsBySchedd[ap2] != 1 || len(jobsBySchedd) != 2 {
		t.Errorf("workflows by schedd = %v", jobsBySchedd)
	}

	rec = doAs(t, srv, "alice", http.MethodGet, "/api/v1/utilization?schedd="+ap2)
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if resp.JobsConsidered != 1 {
		t.Errorf("schedd=%s: jobs = %d, want 1", ap2, resp.JobsConsidered)
	}
}

// The endpoint is in the OpenAPI document.
func TestUtilizationIsDocumented(t *testing.T) {
	var doc struct {
		Paths map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal([]byte(openAPISchema), &doc); err != nil {
		t.Fatalf("openapi does not parse: %v", err)
	}
	if _, ok := doc.Paths["/utilization"]; !ok {
		t.Error("/utilization missing from the OpenAPI paths")
	}
}
