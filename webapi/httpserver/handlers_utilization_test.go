package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/PelicanPlatform/classad/collections/vm"
	"github.com/PelicanPlatform/classad/parser"

	htcondor "github.com/bbockelm/golang-htcondor"
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

func (f *twoOwnerFixture) utilization(t *testing.T, path string, auth func(*http.Request)) utilization.Summary {
	t.Helper()
	w := f.do(t, http.MethodGet, path, "", auth)
	if w.Code != http.StatusOK {
		t.Fatalf("GET %s: status %d: %s", path, w.Code, w.Body.String())
	}
	var resp utilization.Summary
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding %s: %v", w.Body.String(), err)
	}
	return resp
}

// workflowDetail is GET /api/v1/utilization/workflow for one key.
func (f *twoOwnerFixture) workflowDetail(t *testing.T, key string, auth func(*http.Request)) (int, utilization.Workflow, *int) {
	t.Helper()
	w := f.do(t, http.MethodGet, "/api/v1/utilization/workflow?w="+key, "", auth)
	if w.Code != http.StatusOK {
		return w.Code, utilization.Workflow{}, nil
	}
	var detail UtilizationWorkflowDetail
	var wf utilization.Workflow
	if err := json.Unmarshal(w.Body.Bytes(), &detail); err != nil {
		t.Fatalf("decoding %s: %v", w.Body.String(), err)
	}
	if err := json.Unmarshal(detail.Workflow, &wf); err != nil {
		t.Fatalf("decoding the workflow: %v", err)
	}
	return w.Code, wf, detail.WaitingJobs
}

func workflowExecutables(resp utilization.Summary) []string {
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
	_, wf, _ := f.workflowDetail(t, resp.Workflows[0].Key, f.bearer(t, "alice"))
	peaks := wf.Memory.PeakMiB
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
	compute := func(ctx context.Context) (*utilizationResult, error) {
		computes.Add(1)
		close(started)
		<-release
		// The computation's context must still be live after its
		// requester gave up.
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return &utilizationResult{summary: &utilization.Summary{JobsConsidered: 42}}, nil
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

	resp, err := c.get(context.Background(), "k", func(context.Context) (*utilizationResult, error) {
		t.Error("recomputed: the first answer was not cached")
		return nil, errors.New("unexpected")
	})
	if err != nil || resp.summary.JobsConsidered != 42 {
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
			_, err := c.get(context.Background(), "k", func(context.Context) (*utilizationResult, error) {
				computes.Add(1)
				time.Sleep(20 * time.Millisecond)
				return &utilizationResult{summary: &utilization.Summary{}}, nil
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

	if _, err := c.get(context.Background(), "k", func(context.Context) (*utilizationResult, error) {
		return nil, errors.New("schedd unreachable")
	}); err == nil {
		t.Fatal("error swallowed")
	}
	resp, err := c.get(context.Background(), "k", func(context.Context) (*utilizationResult, error) {
		return &utilizationResult{summary: &utilization.Summary{JobsConsidered: 1}}, nil
	})
	if err != nil || resp.summary.JobsConsidered != 1 {
		t.Fatalf("after a failure: %+v, %v", resp, err)
	}
	now = now.Add(utilizationRefresh + time.Second)
	resp, _ = c.get(context.Background(), "k", func(context.Context) (*utilizationResult, error) {
		return &utilizationResult{summary: &utilization.Summary{JobsConsidered: 2}}, nil
	})
	if resp.summary.JobsConsidered != 2 {
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
	var resp utilization.Summary
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
	for _, path := range []string{"/utilization", "/utilization/jobs", "/utilization/workflow", "/utilization/apply"} {
		if _, ok := doc.Paths[path]; !ok {
			t.Errorf("%s missing from the OpenAPI paths", path)
		}
	}
}

// slotAd is a startd slot ad.
func slotAd(t *testing.T, text string) *classad.ClassAd {
	t.Helper()
	ad, err := classad.ParseOld(text)
	if err != nil {
		t.Fatalf("parsing slot ad: %v", err)
	}
	return ad
}

// throughputFixture is the utilization fixture plus 25 of carol's jobs
// asking for 1 core and 8 GB and peaking at 900 MB, and a collector -- the
// fake schedd's address answers startd queries -- holding ten 4-core/
// 16 GB partitionable slots, dynamic slots carved from them (which the
// query excludes), and a dynamic slot that does not say so in SlotType
// (which the parse must drop). Counted wrongly, the dynamic slots would
// inflate the fit.
func throughputFixture(t *testing.T) *twoOwnerFixture {
	t.Helper()
	f := utilizationFixture(t)
	for i := range 25 {
		f.schedd.AddHistory(historyAd(t, 400+i, "carol", "/home/carol/big", 900, 8192, 3600))
	}
	for i := range 10 {
		f.schedd.AddStartds(slotAd(t, fmt.Sprintf(`Name = "slot1@ep%d"
SlotType = "Partitionable"
PartitionableSlot = true
Cpus = 2
Memory = 8192
Disk = 50000000
TotalSlotCpus = 4
TotalSlotMemory = 16384
TotalSlotDisk = 100000000`, i)))
		f.schedd.AddStartds(slotAd(t, fmt.Sprintf(`Name = "slot1_1@ep%d"
SlotType = "Dynamic"
DynamicSlot = true
Cpus = 2
Memory = 8192
Disk = 50000000`, i)))
	}
	f.schedd.AddStartds(slotAd(t, `Name = "slot1_9@ep0"
DynamicSlot = true
Cpus = 4
Memory = 16384
Disk = 100000000`))
	f.s.collector = htcondor.NewCollector(f.schedd.Addr())
	return f
}

func workflowByExecutable(t *testing.T, resp utilization.Summary, exe string) utilization.WorkflowSummary {
	t.Helper()
	for _, w := range resp.Workflows {
		if w.Executable == exe {
			return w
		}
	}
	t.Fatalf("no %s workflow in %v", exe, workflowExecutables(resp))
	return utilization.WorkflowSummary{}
}

// The estimate reads the pool's machines from the collector: ten
// 4-core/16 GB machines hold 20 one-core 8 GB jobs today and 40 at the
// suggested 1 GB, a gain of 2. Dynamic slots add nothing. The pool is
// read once for every request that follows.
func TestUtilizationThroughputFromCollector(t *testing.T) {
	f := throughputFixture(t)
	carol := f.bearer(t, "carol")
	resp := f.utilization(t, "/api/v1/utilization", carol)
	big := workflowByExecutable(t, resp, "big")
	if big.Gain == nil || *big.Gain != 2 || big.SlotsLimited == nil {
		t.Errorf("summary gain = %v, slots_limited %v", big.Gain, big.SlotsLimited)
	}
	_, wf, _ := f.workflowDetail(t, big.Key, carol)
	tp := wf.Throughput
	if tp == nil {
		t.Fatal("no throughput estimate")
	}
	if tp.FitCurrent != 20 || tp.FitSuggested != 40 || tp.Gain != 2 || tp.LimitedBy != utilization.ResourceMemory {
		t.Errorf("throughput = %+v, want 20 -> 40 on the ten partitionable slots, gain 2", tp)
	}
	if resp.Overall.ThroughputGain == nil || *resp.Overall.ThroughputGain != 2 {
		t.Errorf("overall gain = %v", resp.Overall.ThroughputGain)
	}

	_ = f.utilization(t, "/api/v1/utilization?days=30", carol)
	_ = f.utilization(t, "/api/v1/utilization", f.bearer(t, "alice"))
	if n := f.schedd.StartdQueries(); n != 1 {
		t.Errorf("the pool was read %d times for three analyses, want once", n)
	}
}

// A collector that cannot be read costs the estimate, not the answer.
func TestUtilizationThroughputWithoutCollector(t *testing.T) {
	f := throughputFixture(t)
	f.s.collector = htcondor.NewCollector("127.0.0.1:1")
	resp := f.utilization(t, "/api/v1/utilization", f.bearer(t, "carol"))
	if w := workflowByExecutable(t, resp, "big"); w.Gain != nil || resp.Overall.ThroughputGain != nil {
		t.Errorf("gain = %v, overall %v; want null without a pool", w.Gain, resp.Overall.ThroughputGain)
	}
	if resp.JobsConsidered != 25 {
		t.Errorf("jobs = %d", resp.JobsConsidered)
	}
}

// Multi-AP mode has no one pool to measure: no estimate, even for a
// workflow whose advice changes its request.
func TestUtilizationMultiAPHasNoThroughput(t *testing.T) {
	hub := multiaptest.NewHub(t)
	for i := range 22 {
		putHubHistory(t, hub, ap1, "alice@d", 10+i, "/home/alice/sim")
	}
	hub.PutSource(ap1, "fresh", 2)
	srv := newMultiAPServer(t, multiAPService(t, hub, multiaptest.NewRegistry(ap1)))
	rec := doAs(t, srv, "alice", http.MethodGet, "/api/v1/utilization")
	var resp utilization.Summary
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	w := workflowByExecutable(t, resp, "sim")
	if a := w.Advice; len(a) == 0 || !strings.HasPrefix(a[0].ID, "memory-") {
		t.Fatalf("advice = %+v; the fixture should change the memory request", a)
	}
	if w.Gain != nil || resp.Overall.ThroughputGain != nil {
		t.Errorf("gain = %v, overall %v; want null in multi-AP mode", w.Gain, resp.Overall.ThroughputGain)
	}
}

// HTCondor 25.8 writes no EnteredHistoryTime into history, and a window on
// it alone matched nothing. A record without it falls back to its last
// status change, then to CompletionDate; one that left the queue before
// the window stays out.
func TestUtilizationHistoryWithoutEnteredHistoryTime(t *testing.T) {
	f := utilizationFixture(t)
	now := time.Now().Unix()
	ad := func(cluster int, extra string) *classad.ClassAd {
		text := fmt.Sprintf(`ClusterId = %d
ProcId = 0
Owner = "dave"
Cmd = "/home/dave/run"
JobUniverse = 5
QDate = %d
RequestCpus = 1
RequestMemory = 1024
ResidentSetSize = 512000
MemoryUsage = ((ResidentSetSize + 1023) / 1024)
RemoteWallClockTime = 600.0
%s`, cluster, now-7200, extra)
		parsed, err := classad.ParseOld(text)
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}
	f.schedd.AddHistory(
		// Completed, both times recorded.
		ad(501, fmt.Sprintf("JobStatus = 4\nExitCode = 0\nCompletionDate = %d\nEnteredCurrentStatus = %d", now-100, now-100)),
		// Removed: no CompletionDate, only the status change.
		ad(502, fmt.Sprintf("JobStatus = 3\nCompletionDate = 0\nEnteredCurrentStatus = %d", now-200)),
		// Completed, CompletionDate only.
		ad(503, fmt.Sprintf("JobStatus = 4\nExitCode = 0\nCompletionDate = %d", now-300)),
		// Left the queue three days ago: outside a one-day window.
		ad(504, fmt.Sprintf("JobStatus = 4\nExitCode = 0\nCompletionDate = %d\nEnteredCurrentStatus = %d", now-3*86400, now-3*86400)),
	)
	resp := f.utilization(t, "/api/v1/utilization?days=1", f.bearer(t, "dave"))
	if resp.JobsConsidered != 3 {
		t.Errorf("jobs_considered = %d, want the 3 that entered history today", resp.JobsConsidered)
	}
	if len(resp.Workflows) == 1 && resp.Workflows[0].Removed != 1 {
		t.Errorf("removed = %d, want the removed job counted", resp.Workflows[0].Removed)
	}
}

// The mirror stamps EnteredHistoryTime on every record and zone-maps it,
// but prunes only on a top-level "attribute op literal" conjunct, so its
// window must stay a plain comparison; the schedd's carries the fallback.
func TestUtilizationWindowPerBackend(t *testing.T) {
	mirror, schedd := utilizationWindow(`Owner == "dave"`, 1000)
	if mirror != `(Owner == "dave") && EnteredHistoryTime >= 1000` {
		t.Errorf("mirror window = %q; it must stay prunable", mirror)
	}
	if !strings.Contains(schedd, "EnteredCurrentStatus") || !strings.Contains(schedd, ">= 1000") {
		t.Errorf("schedd window = %q; it needs the fallback", schedd)
	}
	for _, c := range []string{mirror, schedd} {
		if _, err := classad.ParseExpr(c); err != nil {
			t.Errorf("%q does not parse: %v", c, err)
		}
	}
}

// A constraint narrows the analysis; one the parser rejects is a 400
// carrying the parser's message. Each is its own cache entry.
func TestUtilizationConstraint(t *testing.T) {
	f := utilizationFixture(t)
	alice := f.bearer(t, "alice")
	if resp := f.utilization(t, "/api/v1/utilization", alice); resp.JobsConsidered != 3 {
		t.Fatalf("unfiltered: %d jobs", resp.JobsConsidered)
	}
	resp := f.utilization(t, "/api/v1/utilization?constraint="+url.QueryEscape("ClusterId == 101 || ClusterId == 103"), alice)
	if resp.JobsConsidered != 2 {
		t.Errorf("filtered: %d jobs, want 2", resp.JobsConsidered)
	}
	// A constraint cannot reach past its parentheses into the scope.
	resp = f.utilization(t, "/api/v1/utilization?owned_by_me=false&constraint="+url.QueryEscape("true || true"), f.bearer(t, "bob"))
	if got := workflowExecutables(resp); !slices.Equal(got, []string{"bob_sim"}) {
		t.Errorf("bob with a constraint of 'true || true': %v", got)
	}
	w := f.do(t, http.MethodGet, "/api/v1/utilization?constraint="+url.QueryEscape("ClusterId == == 3"), "", alice)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid constraint") {
		t.Errorf("bad constraint: %d %s", w.Code, w.Body.String())
	}
}

// owners narrows an administrator's view and lists who is in it; for a
// caller who may see only their own jobs it intersects, never widens.
func TestUtilizationOwners(t *testing.T) {
	f := utilizationFixture(t)
	resp := f.utilization(t, "/api/v1/utilization?owners=alice", f.bearer(t, "root"))
	if got := workflowExecutables(resp); !slices.Equal(got, []string{"alice_sim"}) {
		t.Errorf("admin owners=alice: %v", got)
	}
	if len(resp.Owners) != 1 || resp.Owners[0].Owner != "alice" || resp.Owners[0].Jobs != 3 || resp.Owners[0].WallHours != 3 {
		t.Errorf("owners list = %+v", resp.Owners)
	}
	everyone := f.utilization(t, "/api/v1/utilization?owned_by_me=false", f.bearer(t, "root"))
	if len(everyone.Owners) != 2 || everyone.Owners[0].Owner != "alice" {
		t.Errorf("admin owners list = %+v, want alice (3 h) then bob (1 h)", everyone.Owners)
	}

	bob := f.bearer(t, "bob")
	for _, path := range []string{
		"/api/v1/utilization?owners=alice",
		"/api/v1/utilization?owners=alice&owned_by_me=false",
		"/api/v1/utilization?owners=alice,bob&owned_by_me=false",
	} {
		resp := f.utilization(t, path, bob)
		for _, w := range resp.Workflows {
			if w.Executable == "alice_sim" {
				t.Errorf("bob GET %s read alice's jobs", path)
			}
		}
		if resp.Owners != nil {
			t.Errorf("bob GET %s: an owners list in a personal scope: %+v", path, resp.Owners)
		}
	}
	if resp := f.utilization(t, "/api/v1/utilization?owners=alice,bob&owned_by_me=false", bob); resp.JobsConsidered != 2 {
		t.Errorf("bob naming himself among others: %d jobs, want his 2", resp.JobsConsidered)
	}
}

func TestUtilizationLimit(t *testing.T) {
	f := utilizationFixture(t)
	f.s.utilizationMaxJobs = 10
	alice := f.bearer(t, "alice")
	resp := f.utilization(t, "/api/v1/utilization?limit=2", alice)
	if resp.JobsConsidered != 2 || !resp.Truncated || resp.Limit != 2 || resp.MaxLimit != 10 {
		t.Errorf("limit=2: %d jobs truncated=%v limit=%d max=%d", resp.JobsConsidered, resp.Truncated, resp.Limit, resp.MaxLimit)
	}
	if resp := f.utilization(t, "/api/v1/utilization?limit=5000000", alice); resp.Limit != 10 || resp.JobsConsidered != 3 || resp.Truncated {
		t.Errorf("limit above the ceiling: limit=%d jobs=%d truncated=%v; want clamped to 10", resp.Limit, resp.JobsConsidered, resp.Truncated)
	}
	// The default is itself clamped to a lower ceiling.
	if resp := f.utilization(t, "/api/v1/utilization", alice); resp.Limit != 10 {
		t.Errorf("default limit under a ceiling of 10 = %d", resp.Limit)
	}
	f.s.utilizationMaxJobs = 0
	if resp := f.utilization(t, "/api/v1/utilization?days=30", alice); resp.Limit != utilizationDefaultLimit || resp.MaxLimit != utilizationDefaultMaxLimit {
		t.Errorf("defaults: limit %d max %d", resp.Limit, resp.MaxLimit)
	}
	for _, bad := range []string{"0", "-1", "lots"} {
		if w := f.do(t, http.MethodGet, "/api/v1/utilization?limit="+bad, "", alice); w.Code != http.StatusBadRequest {
			t.Errorf("limit=%s: %d", bad, w.Code)
		}
	}
	if d := utilizationComputeTimeout(1000000); d != 13*time.Minute {
		t.Errorf("timeout for a million = %v", d)
	}
}

// The mirror prunes history segments on top-level "attribute op literal"
// conjuncts. However the caller's owners and constraint are combined
// with the scope, the window must survive as one of them -- and the
// owner list as an "in" probe -- in the planner's own reading.
func TestUtilizationWindowStaysPrunable(t *testing.T) {
	uq := utilizationQuery{owners: []string{"alice", "bob"}, filter: `JobBatchName == "x" || ClusterId > 5`}
	mirror, _ := utilizationWindow(uq.narrow(`Owner == "root"`), 1000)
	expr, err := parser.ParseExpr(mirror)
	if err != nil {
		t.Fatalf("%q: %v", mirror, err)
	}
	var window, owners bool
	for _, p := range vm.Compile(expr).Probes() {
		if p.Attr == "EnteredHistoryTime" && p.Op == ">=" {
			window = true
		}
		if p.Attr == "Owner" && p.Op == "in" && len(p.Vals) == 2 {
			owners = true
		}
	}
	if !window || !owners {
		t.Errorf("probes of %q: window %v, owners %v", mirror, window, owners)
	}
}

func (f *twoOwnerFixture) utilizationJobs(t *testing.T, path string, auth func(*http.Request)) (int, UtilizationJobsResponse) {
	t.Helper()
	w := f.do(t, http.MethodGet, path, "", auth)
	var resp UtilizationJobsResponse
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decoding %s: %v", w.Body.String(), err)
		}
	}
	return w.Code, resp
}

// A workflow's jobs page through in the requested order, for the caller
// who may see them and nobody else.
func TestUtilizationJobs(t *testing.T) {
	f := utilizationFixture(t)
	alice := f.bearer(t, "alice")
	key := f.utilization(t, "/api/v1/utilization", alice).Workflows[0].Key

	code, page := f.utilizationJobs(t, "/api/v1/utilization/jobs?w="+key+"&sort=memory&page_size=2", alice)
	if code != http.StatusOK || page.Total != 3 || len(page.Jobs) != 2 || page.NextOffset == nil || *page.NextOffset != 2 {
		t.Fatalf("first page: %d %+v", code, page)
	}
	// Peaks 1000, 950, 900 MiB: largest first.
	if page.Jobs[0].ID != "103.0" || page.Jobs[1].ID != "102.0" || *page.Jobs[0].MemoryPeakMiB != 1000 {
		t.Errorf("first page = %+v", page.Jobs)
	}
	_, page = f.utilizationJobs(t, "/api/v1/utilization/jobs?w="+key+"&sort=memory&page_size=2&offset=2", alice)
	if len(page.Jobs) != 1 || page.Jobs[0].ID != "101.0" || page.NextOffset != nil {
		t.Errorf("second page = %+v", page)
	}
	r := page.Jobs[0]
	if r.Owner != "alice" || r.Outcome != "ok" || *r.Request.MemoryMiB != 2048 || r.Wall != 3600 || *r.CoresUsed != 0.9 {
		t.Errorf("row = %+v", r)
	}

	// Owner-scoped like the analysis: bob cannot list alice's workflow,
	// whatever he asks for; an administrator can.
	for _, path := range []string{
		"/api/v1/utilization/jobs?w=" + key,
		"/api/v1/utilization/jobs?owned_by_me=false&w=" + key,
		"/api/v1/utilization/jobs?owners=alice&w=" + key,
	} {
		if code, page := f.utilizationJobs(t, path, f.bearer(t, "bob")); code != http.StatusNotFound {
			t.Errorf("bob GET %s: %d %+v, want 404", path, code, page)
		}
	}
	if code, page := f.utilizationJobs(t, "/api/v1/utilization/jobs?owned_by_me=false&w="+key, f.bearer(t, "root")); code != http.StatusOK || page.Total != 3 {
		t.Errorf("admin: %d %+v", code, page)
	}
	// With the analysis cached, the read is narrowed to the workflow's
	// owner; the jobs listed must not change.
	root := f.bearer(t, "root")
	_ = f.utilization(t, "/api/v1/utilization?owned_by_me=false&days=30", root)
	if code, page := f.utilizationJobs(t, "/api/v1/utilization/jobs?owned_by_me=false&days=30&w="+key, root); code != http.StatusOK || page.Total != 3 {
		t.Errorf("admin, narrowed by the cached analysis: %d %+v", code, page)
	}

	for _, bad := range []string{"", "&sort=colour", "&order=up", "&offset=-1", "&page_size=0"} {
		path := "/api/v1/utilization/jobs?w=" + key + bad
		if bad == "" {
			path = "/api/v1/utilization/jobs"
		}
		if code, _ := f.utilizationJobs(t, path, alice); code != http.StatusBadRequest {
			t.Errorf("GET %s: %d, want 400", path, code)
		}
	}
}

// The jobs cache is bounded by total jobs held: keeping a workflow evicts
// the least recently paged ones until the total fits, and one bigger than
// the whole bound is not kept at all.
func TestJobSetCacheBoundedBySize(t *testing.T) {
	c := newSharedCache[utilizationJobSet](time.Hour, time.Minute)
	c.maxEntries = 10
	c.sizeOf = func(s utilizationJobSet) int { return len(s.jobs) }
	c.maxSize = 10
	clock := time.Unix(1700000000, 0)
	c.now = func() time.Time { clock = clock.Add(time.Second); return clock }

	computed := map[string]int{}
	get := func(key string, n int) {
		t.Helper()
		_, err := c.get(context.Background(), key, func(context.Context) (utilizationJobSet, error) {
			computed[key]++
			return utilizationJobSet{jobs: make([]utilization.Job, n)}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	get("a", 6)
	get("b", 3)
	get("a", 6) // a is now the more recently served
	get("c", 5) // 6+3+5 > 10: b goes first (least recent), then 6+5 still > 10, a goes
	if _, ok := c.peek("b"); ok {
		t.Error("b survived; it was least recently served")
	}
	if _, ok := c.peek("c"); !ok {
		t.Error("c was not kept")
	}
	total := 0
	for _, e := range c.byKey {
		total += e.size
	}
	if total > c.maxSize {
		t.Errorf("cache holds %d jobs, bound %d", total, c.maxSize)
	}

	// Larger than the whole bound: served, never kept.
	get("huge", 11)
	get("huge", 11)
	if computed["huge"] != 2 {
		t.Errorf("an oversized set was computed %d times for two requests, want 2 (not cached)", computed["huge"])
	}
	if _, ok := c.peek("c"); !ok {
		t.Error("an oversized set evicted c")
	}
	if computed["a"] != 1 || computed["c"] != 1 {
		t.Errorf("computations = %v", computed)
	}
}

// queueAd is a job in the queue.
func queueAd(t *testing.T, cluster, proc int, owner, cmd string, status int, requestMemory string) *classad.ClassAd {
	t.Helper()
	ad, err := classad.ParseOld(fmt.Sprintf(`ClusterId = %d
ProcId = %d
Owner = %q
Cmd = %q
JobUniverse = 5
JobStatus = %d
RequestCpus = 1
RequestDisk = 1048576
RequestMemory = %s`, cluster, proc, owner, cmd, status, requestMemory))
	if err != nil {
		t.Fatal(err)
	}
	return ad
}

// applyFixture is the throughput fixture -- carol's 25 finished "big"
// jobs, advised 1 GB of memory and 256 MB of disk -- with a queue: three
// of the same workflow waiting (one whose memory request is a formula),
// and jobs that must not be touched: another program, a running one, a
// held one, and bob's.
type editCall struct {
	constraint string
	attrs      map[string]string
}

func applyFixture(t *testing.T) (*twoOwnerFixture, *[]editCall) {
	t.Helper()
	f := throughputFixture(t)
	f.schedd.AddJobs(
		queueAd(t, 900, 0, "carol", "/home/carol/big", 1, "8192"),
		queueAd(t, 900, 1, "carol", "/home/carol/big", 1, "8192"),
		queueAd(t, 901, 0, "carol", "/home/carol/big", 1, `ifThenElse(MemoryUsage isnt undefined, 2 * MemoryUsage, 8192)`),
		queueAd(t, 902, 0, "carol", "/home/carol/other", 1, "8192"),
		queueAd(t, 903, 0, "carol", "/home/carol/big", 2, "8192"),
		queueAd(t, 904, 0, "carol", "/home/carol/big", 5, "8192"),
		queueAd(t, 905, 0, "bob", "/home/carol/big", 1, "8192"),
	)
	var calls []editCall
	f.s.utilizationEditHook = func(_ context.Context, constraint string, attrs map[string]string) (int, error) {
		calls = append(calls, editCall{constraint, attrs})
		start := strings.Index(constraint, "member(ProcId, {")
		if start < 0 {
			return 0, nil
		}
		list, _, _ := strings.Cut(constraint[start+len("member(ProcId, {"):], "}")
		return len(strings.Split(list, ",")), nil
	}
	return f, &calls
}

func (f *twoOwnerFixture) apply(t *testing.T, body string, auth func(*http.Request)) (int, UtilizationApplyResponse) {
	t.Helper()
	w := f.do(t, http.MethodPost, "/api/v1/utilization/apply", body, auth)
	var resp UtilizationApplyResponse
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decoding %s: %v", w.Body.String(), err)
		}
	}
	return w.Code, resp
}

// The detail carries the full workflow and how many of its jobs wait.
func TestUtilizationWorkflowDetail(t *testing.T) {
	f, _ := applyFixture(t)
	carol := f.bearer(t, "carol")
	key := workflowByExecutable(t, f.utilization(t, "/api/v1/utilization", carol), "big").Key
	code, wf, waiting := f.workflowDetail(t, key, carol)
	if code != http.StatusOK || wf.Key != key || wf.Jobs != 25 || wf.Memory.PeakMiB == nil || len(wf.Samples) != 25 {
		t.Fatalf("detail: %d %+v", code, wf)
	}
	if waiting == nil || *waiting != 3 {
		t.Errorf("waiting_jobs = %v, want carol's 3 idle jobs of this workflow", waiting)
	}
	var applies []string
	for _, a := range wf.Advice {
		if a.Applies {
			applies = append(applies, fmt.Sprintf("%s=%s:%v", a.ID, a.Change.Attribute, a.Change.Value))
		}
	}
	if want := []string{"disk-lower=RequestDisk:262144", "memory-lower=RequestMemory:1024"}; !slices.Equal(sortedCopy(applies), want) {
		t.Errorf("applicable advice = %v, want %v", applies, want)
	}
	if code, _, _ := f.workflowDetail(t, key, f.bearer(t, "bob")); code != http.StatusNotFound {
		t.Errorf("bob reading carol's workflow: %d, want 404", code)
	}
	if code, _, _ := f.workflowDetail(t, "nosuchkey000", carol); code != http.StatusNotFound {
		t.Errorf("unknown key: %d", code)
	}
}

func sortedCopy(s []string) []string {
	out := slices.Clone(s)
	slices.Sort(out)
	return out
}

// Applying edits only carol's idle jobs of this workflow, only their
// Request* attributes, to the values in the server's own advice; a
// formula request is left as written.
func TestUtilizationApply(t *testing.T) {
	f, calls := applyFixture(t)
	carol := f.bearer(t, "carol")
	key := workflowByExecutable(t, f.utilization(t, "/api/v1/utilization", carol), "big").Key

	// The body names advice, not values; a value in it is ignored.
	code, resp := f.apply(t, `{"w":"`+key+`","advice":["memory-lower","disk-lower"],"RequestMemory":1}`, carol)
	if code != http.StatusOK {
		t.Fatalf("apply: %d", code)
	}
	if resp.Edited != 3 || resp.Set["RequestMemory"] != 1024 || resp.Set["RequestDisk"] != 262144 {
		t.Errorf("response = %+v", resp)
	}
	if len(resp.Skipped) != 1 || resp.Skipped[0].Job != "901.0" || !strings.Contains(resp.Skipped[0].Reason, "RequestMemory") {
		t.Errorf("skipped = %+v, want 901.0 for its formula memory request", resp.Skipped)
	}
	edited := map[string]map[string]string{}
	for _, c := range *calls {
		if !strings.Contains(c.constraint, "JobStatus == 1") || !strings.Contains(c.constraint, `Owner == "carol"`) {
			t.Errorf("edit not confined to carol's idle jobs: %s", c.constraint)
		}
		for name := range c.attrs {
			if !strings.HasPrefix(name, "Request") {
				t.Errorf("edited %s", name)
			}
		}
		edited[c.constraint] = c.attrs
	}
	var procs []string
	for c, attrs := range edited {
		switch {
		case strings.Contains(c, "ClusterId == 900") && strings.Contains(c, "{0, 1}"):
			if attrs["RequestMemory"] != "1024" || attrs["RequestDisk"] != "262144" {
				t.Errorf("900: %v", attrs)
			}
			procs = append(procs, "900.0", "900.1")
		case strings.Contains(c, "ClusterId == 901"):
			if _, ok := attrs["RequestMemory"]; ok || attrs["RequestDisk"] != "262144" {
				t.Errorf("901 (formula memory): %v", attrs)
			}
			procs = append(procs, "901.0")
		default:
			t.Errorf("unexpected edit %s %v", c, attrs)
		}
	}
	if len(procs) != 3 {
		t.Errorf("edited %v", procs)
	}

	// Advice that is not this workflow's is refused before anything is
	// read; bob cannot reach carol's workflow at all.
	if code, _ := f.apply(t, `{"w":"`+key+`","advice":["cpus-lower"]}`, carol); code != http.StatusBadRequest {
		t.Errorf("advice not given: %d", code)
	}
	if code, _ := f.apply(t, `{"w":"`+key+`","advice":["memory-lower"],"owned_by_me":false}`, f.bearer(t, "bob")); code != http.StatusNotFound {
		t.Errorf("bob applying to carol's workflow: %d, want 404", code)
	}
	if code, _ := f.apply(t, `{"advice":["memory-lower"]}`, carol); code != http.StatusBadRequest {
		t.Errorf("missing w: %d", code)
	}
}

// The detail names the requests every waiting job writes as a formula --
// the ones apply would leave alone -- and nothing when only some do.
func TestUtilizationWaitingAdaptive(t *testing.T) {
	f := utilizationFixture(t)
	formula := `ifThenElse(MemoryUsage isnt undefined, 2 * MemoryUsage, 2048)`
	f.schedd.AddJobs(
		queueAd(t, 950, 0, "alice", "/home/alice/alice_sim", 1, formula),
		queueAd(t, 950, 1, "alice", "/home/alice/alice_sim", 1, formula),
	)
	alice := f.bearer(t, "alice")
	key := f.utilization(t, "/api/v1/utilization", alice).Workflows[0].Key
	w := f.do(t, http.MethodGet, "/api/v1/utilization/workflow?w="+key, "", alice)
	var detail UtilizationWorkflowDetail
	if err := json.Unmarshal(w.Body.Bytes(), &detail); err != nil || w.Code != http.StatusOK {
		t.Fatalf("detail: %d %s", w.Code, w.Body.String())
	}
	if detail.WaitingJobs == nil || *detail.WaitingJobs != 2 || !slices.Equal(detail.WaitingAdaptive, []string{"memory"}) {
		t.Errorf("waiting = %v, adaptive %v; want 2 and [memory]", detail.WaitingJobs, detail.WaitingAdaptive)
	}

	// carol's three waiting jobs: one formula, two plain -- not all.
	g, _ := applyFixture(t)
	carol := g.bearer(t, "carol")
	ckey := workflowByExecutable(t, g.utilization(t, "/api/v1/utilization", carol), "big").Key
	w = g.do(t, http.MethodGet, "/api/v1/utilization/workflow?w="+ckey, "", carol)
	detail = UtilizationWorkflowDetail{}
	if err := json.Unmarshal(w.Body.Bytes(), &detail); err != nil || detail.WaitingAdaptive != nil {
		t.Errorf("carol: waiting_adaptive = %v, want omitted", detail.WaitingAdaptive)
	}
}
