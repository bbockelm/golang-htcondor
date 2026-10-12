package httpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	"github.com/bbockelm/golang-htcondor/webapi/batches"
	"github.com/bbockelm/golang-htcondor/webapi/utilization"
)

// batchAd is a job ad: the given attributes over an owner, a cluster and
// a proc. Times are offsets from base.
func batchAd(t *testing.T, cluster, proc int, owner string, attrs ...string) *classad.ClassAd {
	t.Helper()
	text := fmt.Sprintf("ClusterId = %d\nProcId = %d\nOwner = %q\nJobUniverse = 5\nRequestCpus = 1\nRequestMemory = 1024\n%s",
		cluster, proc, owner, strings.Join(attrs, "\n"))
	ad, err := classad.ParseOld(text)
	if err != nil {
		t.Fatalf("parsing %q: %v", text, err)
	}
	return ad
}

// batchFixture is alice's DAG (root 500, a sub-DAG 502), her named batch
// "sweep" across clusters 600 and 601, her finished-only cluster 700,
// and bob's own "sweep", 800.
func batchFixture(t *testing.T) *twoOwnerFixture {
	t.Helper()
	f := twoOwnerScheddServer(t)
	base := time.Now().Unix() - 10000
	at := func(name string, off int64) string { return fmt.Sprintf("%s = %d", name, base+off) }
	dag := `JobBatchName = "ny50.dag+500"`
	done := func(off, wall int64) []string {
		return []string{"JobStatus = 4", at("QDate", off), at("JobStartDate", off+10), at("JobCurrentStartDate", off+10),
			at("CompletionDate", off+10+wall), at("EnteredHistoryTime", off+11+wall),
			fmt.Sprintf("RemoteWallClockTime = %d.0", wall), fmt.Sprintf("CommittedTime = %d", wall), "NumJobStarts = 1"}
	}
	f.schedd.AddJobs(
		batchAd(t, 500, 0, "alice", dag, `Cmd = "/usr/bin/condor_dagman"`, "JobUniverse = 7", "JobStatus = 2", at("QDate", 0),
			"DAG_NodesTotal = 6", "DAG_NodesDone = 3", "DAG_NodesFailed = 1", "DAG_NodesQueued = 1", "DAG_Status = 0", `DAG_Name = "ny50"`),
		batchAd(t, 502, 0, "alice", dag, `Cmd = "/usr/bin/condor_dagman"`, "JobUniverse = 7", "JobStatus = 2", at("QDate", 20),
			"DAGManJobId = 500", `DAGNodeName = "SUB"`, "DAG_NodesTotal = 2"),
		batchAd(t, 504, 0, "alice", dag, `Cmd = "/home/alice/fit.sh"`, "JobStatus = 5", at("QDate", 40), "DAGManJobId = 502", `DAGNodeName = "C"`,
			`HoldReason = "Error from slot1@ep7.example.org: memory usage exceeded request_memory"`, "HoldReasonCode = 34", "HoldReasonSubCode = 102"),
		// Uploading its inputs: held, but not a hold reason.
		batchAd(t, 506, 0, "alice", dag, `Cmd = "/home/alice/fit.sh"`, "JobStatus = 5", at("QDate", 60), "DAGManJobId = 502", `DAGNodeName = "E"`,
			`HoldReason = "Spooling input data files"`, "HoldReasonCode = 16"),
		// A node of alice's DAG run as bob, as a schedd not running as
		// root does: bob sees his job, alice's DAG takes it in.
		batchAd(t, 900, 0, "bob", dag, `Cmd = "/home/bob/x"`, "JobStatus = 1", at("QDate", 70)),
		batchAd(t, 601, 0, "alice", `JobBatchName = "sweep"`, `Cmd = "/home/alice/sweep"`, "JobStatus = 1", at("QDate", 500), "TotalSubmitProcs = 2"),
		batchAd(t, 601, 1, "alice", `JobBatchName = "sweep"`, `Cmd = "/home/alice/sweep"`, "JobStatus = 2", at("QDate", 500), "TotalSubmitProcs = 2",
			at("JobCurrentStartDate", 600)),
		batchAd(t, 800, 0, "bob", `JobBatchName = "sweep"`, `Cmd = "/home/bob/sweep"`, "JobStatus = 1", at("QDate", 900), "TotalSubmitProcs = 1"),
	)
	f.schedd.AddHistory(
		batchAd(t, 501, 0, "alice", append(done(10, 100), dag, `Cmd = "/home/alice/prep.sh"`, "DAGManJobId = 500", `DAGNodeName = "A"`, "ExitCode = 0")...),
		batchAd(t, 503, 0, "alice", append(done(30, 200), dag, `Cmd = "/home/alice/fit.sh"`, "DAGManJobId = 502", `DAGNodeName = "B"`, "ExitCode = 1")...),
		batchAd(t, 505, 0, "alice", dag, `Cmd = "/home/alice/fit.sh"`, "JobStatus = 3", at("QDate", 50), at("EnteredHistoryTime", 400),
			"DAGManJobId = 502", `DAGNodeName = "D"`, "RemoteWallClockTime = 50.0", "CommittedTime = 0",
			`HoldReason = "Error from slot2@ep9.example.org: memory usage exceeded request_memory"`, "HoldReasonCode = 34", "HoldReasonSubCode = 102"),
		batchAd(t, 600, 0, "alice", append(done(300, 100), `JobBatchName = "sweep"`, `Cmd = "/home/alice/sweep"`, "ExitCode = 0", "TotalSubmitProcs = 3",
			"ResidentSetSize_RAW = 512000",
			// Held once on the way, released, and finished.
			`LastHoldReason = "Transfer input files failure at access point ap1 while sending files"`,
			"LastHoldReasonCode = 13", "LastHoldReasonSubCode = 2")...),
		batchAd(t, 600, 1, "alice", append(done(300, 300), `JobBatchName = "sweep"`, `Cmd = "/home/alice/sweep"`, "ExitCode = 0", "TotalSubmitProcs = 3",
			"ResidentSetSize_RAW = 1024000", "RemoteWallClockTime = 400.0")...),
		batchAd(t, 600, 2, "alice", append(done(300, 50), `JobBatchName = "sweep"`, `Cmd = "/home/alice/sweep"`, "ExitBySignal = true", "ExitSignal = 9",
			"TotalSubmitProcs = 3")...),
		batchAd(t, 700, 0, "alice", append(done(800, 60), `Cmd = "/home/alice/one"`, "ExitCode = 0", "TotalSubmitProcs = 2")...),
		// Spooled: held while its inputs uploaded, which is no problem.
		batchAd(t, 700, 1, "alice", append(done(800, 70), `Cmd = "/home/alice/one"`, "ExitCode = 0", "TotalSubmitProcs = 2",
			`LastHoldReason = "Spooling input data files"`, "LastHoldReasonCode = 16")...),
	)
	return f
}

func (f *twoOwnerFixture) batch(t *testing.T, path string, auth func(*http.Request)) BatchResponse {
	t.Helper()
	w := f.do(t, http.MethodGet, path, "", auth)
	if w.Code != http.StatusOK {
		t.Fatalf("GET %s: %d %s", path, w.Code, w.Body.String())
	}
	var resp BatchResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding %s: %v", w.Body.String(), err)
	}
	return resp
}

func (f *twoOwnerFixture) batchJobs(t *testing.T, path string, auth func(*http.Request)) BatchJobsResponse {
	t.Helper()
	w := f.do(t, http.MethodGet, path, "", auth)
	if w.Code != http.StatusOK {
		t.Fatalf("GET %s: %d %s", path, w.Code, w.Body.String())
	}
	var resp BatchJobsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding %s: %v", w.Body.String(), err)
	}
	return resp
}

func rowIDs(rows []BatchJobRow) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.ID
	}
	return out
}

// A DAG, found by any of its clusters -- the root, a node finished long
// ago, a nested sub-DAG's node -- is the whole tree, named and numbered
// for its root, with its root DAGMan job's own counts.
//
//nolint:gocyclo // one fixture, many facts about it
func TestBatchDAG(t *testing.T) {
	f := batchFixture(t)
	alice := f.bearer(t, "alice")
	for _, id := range []string{"500", "501", "504"} {
		b := f.batch(t, "/api/v1/batches/"+id, alice)
		if b.Kind != batches.KindDAG || b.ID != 500 || b.Name != "ny50.dag" || b.Owner != "alice" || b.DagmanJobID != "500.0" {
			t.Errorf("/batches/%s: %s %d %q %q %q", id, b.Kind, b.ID, b.Name, b.Owner, b.DagmanJobID)
		}
		if !slices.Equal(b.Clusters, []int64{500, 501, 502, 503, 504, 505, 506}) {
			t.Errorf("/batches/%s: clusters %v", id, b.Clusters)
		}
		if b.Constraint != `JobBatchName == "ny50.dag+500"` || b.RemoveConstraint != `JobBatchName == "ny50.dag+500" || ClusterId == 500` {
			t.Errorf("/batches/%s: constraints %q, %q", id, b.Constraint, b.RemoveConstraint)
		}
	}
	b := f.batch(t, "/api/v1/batches/500", alice)
	if p := b.Progress; !p.Known || p.Unit != "nodes" || p.Total != 6 || p.Done != 3 || p.Failed != 1 {
		t.Errorf("progress = %+v", p)
	}
	if b.Dag == nil || b.Dag.Source != "queue" || b.Dag.Attributes["DAG_NodesTotal"] != float64(6) ||
		b.Dag.Attributes["DAG_Name"] != "ny50" || b.Dag.Status == nil || *b.Dag.Status != 2 {
		t.Errorf("dag = %+v", b.Dag)
	}
	if _, leaked := b.Dag.Attributes["JobStatus"]; leaked {
		t.Error("dag attributes carry more than DAG_*")
	}
	if b.LiveJobs != 4 || b.Live[batches.StatusRunning] != 2 || b.Live[batches.StatusHeld] != 1 || b.Live[batches.StatusUploading] != 1 {
		t.Errorf("live = %d %v", b.LiveJobs, b.Live)
	}
	if fin := b.Finished; fin.Jobs != 3 || fin.Succeeded != 1 || fin.Failed != 1 || fin.Removed != 1 || !b.HasHistory {
		t.Errorf("finished = %+v", fin)
	}
	// One memory hold now and one on a removed job: the same problem,
	// told apart by whether it is still holding a job.
	kinds := map[string]int{}
	for _, h := range b.HoldReasons {
		kinds[h.Kind] += h.Count
		if !strings.Contains(h.Template, "memory usage exceeded request_memory") || len(h.Codes) != 1 || h.Codes[0].Code != 34 {
			t.Errorf("hold reason = %+v", h)
		}
	}
	if kinds["held"] != 1 || kinds["was_held"] != 1 {
		t.Errorf("hold reasons = %+v", b.HoldReasons)
	}
	// Two programs; the DAGMan jobs are not a workflow.
	var exes []string
	for _, w := range b.Workflows {
		exes = append(exes, fmt.Sprintf("%s:%d/%d", w.Executable, w.Jobs, w.FinishedJobs))
	}
	if !slices.Equal(exes, []string{"fit.sh:4/2", "prep.sh:1/1"}) {
		t.Errorf("workflows = %v", exes)
	}
}

// A named batch is one owner's jobs under the name, across clusters,
// queued and finished; its id is the smallest cluster, wherever it is.
//
//nolint:gocyclo // one fixture, many facts about it
func TestBatchNamed(t *testing.T) {
	f := batchFixture(t)
	b := f.batch(t, "/api/v1/batches/601", f.bearer(t, "alice"))
	if b.Kind != batches.KindNamed || b.ID != 600 || b.Name != "sweep" || !slices.Equal(b.Clusters, []int64{600, 601}) ||
		b.Constraint != `JobBatchName == "sweep" && Owner == "alice"` {
		t.Fatalf("batch = %s %d %q %v %q", b.Kind, b.ID, b.Name, b.Clusters, b.Constraint)
	}
	// 600's three procs have left the queue; 601's two are in it.
	if p := b.Progress; !p.Known || p.Unit != "jobs" || p.Total != 5 || p.Done != 3 {
		t.Errorf("progress = %+v", p)
	}
	fin := b.Finished
	if fin.Succeeded != 2 || fin.Failed != 1 || fin.Removed != 0 {
		t.Errorf("finished = %+v", fin)
	}
	want := []string{"exit:0:2", "signal:9:1"}
	var got []string
	for _, o := range fin.Outcomes {
		got = append(got, fmt.Sprintf("%s:%d:%d", o.Outcome, val64(o.Code), o.Count))
	}
	if !slices.Equal(got, want) {
		t.Errorf("outcomes = %v, want %v", got, want)
	}
	// Runtimes 50, 100, 300 (CommittedTime); 600.1 ran 400 s of wall for
	// its 300, so 100 s of badput.
	if r := fin.Runtime; r == nil || r.Count != 3 || r.P50 != 100 || r.Max != 300 || r.P10 != 60 {
		t.Errorf("runtime = %+v", r)
	}
	if fin.BadputHours != 100.0/3600 || fin.WallHours != (100+400+50)/3600.0 {
		t.Errorf("wall %v badput %v", fin.WallHours, fin.BadputHours)
	}
	if m := fin.Memory; m == nil || m.Count != 2 || m.PeakMax != 1000 || m.RequestP50 != 1024 {
		t.Errorf("memory = %+v", m)
	}
	// A job that was held and then finished says why it was held.
	if len(b.HoldReasons) != 1 || b.HoldReasons[0].Kind != "was_held" || b.HoldReasons[0].Count != 1 ||
		!strings.Contains(b.HoldReasons[0].Template, "Transfer input files failure") || b.HoldReasons[0].Codes[0].Code != 13 ||
		len(b.HoldReasons[0].Examples) != 1 || b.HoldReasons[0].Examples[0].ID != "600.0" {
		t.Errorf("hold reasons = %+v", b.HoldReasons)
	}
	if b.Submitted == nil || b.LastCompletion == nil || b.FirstStart == nil || *b.LastCompletion <= *b.FirstStart {
		t.Errorf("times %v %v %v", b.Submitted, b.FirstStart, b.LastCompletion)
	}
}

// A batch that has left the queue entirely is read from history alone.
func TestBatchFinishedOnly(t *testing.T) {
	f := batchFixture(t)
	b := f.batch(t, "/api/v1/batches/700", f.bearer(t, "alice"))
	if b.Kind != batches.KindCluster || b.ID != 700 || b.Name != "700" || b.LiveJobs != 0 || b.Finished.Jobs != 2 || !b.HasHistory {
		t.Errorf("batch = %+v", b)
	}
	if p := b.Progress; !p.Known || p.Total != 2 || p.Done != 2 {
		t.Errorf("progress = %+v", p)
	}
	// The spooling hold is not a hold reason, in the summary or a row.
	if len(b.HoldReasons) != 0 {
		t.Errorf("hold reasons = %+v", b.HoldReasons)
	}
	for _, r := range f.batchJobs(t, "/api/v1/batches/700/jobs", f.bearer(t, "alice")).Jobs {
		if r.HoldReason != "" || r.HoldCode != nil {
			t.Errorf("row %s: hold %q %v", r.ID, r.HoldReason, r.HoldCode)
		}
	}
}

// Someone else's batch is not there; an administrator sees it; an id is
// a cluster id.
func TestBatchScopeAndErrors(t *testing.T) {
	f := batchFixture(t)
	bob := f.bearer(t, "bob")
	for _, id := range []string{"500", "600", "700", "999"} {
		if w := f.do(t, http.MethodGet, "/api/v1/batches/"+id, "", bob); w.Code != http.StatusNotFound {
			t.Errorf("bob GET /batches/%s: %d %s", id, w.Code, w.Body.String())
		}
		if w := f.do(t, http.MethodGet, "/api/v1/batches/"+id+"/jobs", "", bob); w.Code != http.StatusNotFound {
			t.Errorf("bob GET /batches/%s/jobs: %d", id, w.Code)
		}
	}
	// bob's own "sweep" is his alone, though alice has one too.
	if b := f.batch(t, "/api/v1/batches/800", bob); b.ID != 800 || !slices.Equal(b.Clusters, []int64{800}) ||
		b.Constraint != `JobBatchName == "sweep" && Owner == "bob"` {
		t.Errorf("bob's sweep = %+v", b)
	}
	root := f.bearer(t, "root")
	if b := f.batch(t, "/api/v1/batches/600", root); b.ID != 600 || b.Owner != "alice" {
		t.Errorf("admin: %+v", b)
	}
	// An administrator sees the whole DAG, whoever its jobs run as, and
	// it is the root DAGMan job's owner's.
	if b := f.batch(t, "/api/v1/batches/900", root); b.ID != 500 || b.Owner != "alice" || !slices.Contains(b.Clusters, 900) || len(b.Clusters) != 8 {
		t.Errorf("admin's view of alice's DAG: id %d owner %q clusters %v", b.ID, b.Owner, b.Clusters)
	}
	// A DAG's jobs are matched by batch name alone, whoever owns them --
	// a schedd not running as root runs a DAG's nodes as itself -- and
	// the read is still confined to what the caller may see.
	if b := f.batch(t, "/api/v1/batches/900", bob); b.Kind != batches.KindDAG || !slices.Equal(b.Clusters, []int64{900}) ||
		b.LiveJobs != 1 || b.Finished.Jobs != 0 || b.Dag != nil {
		t.Errorf("bob's job under alice's DAG name = %+v", b)
	}
	alice := f.bearer(t, "alice")
	for path, code := range map[string]int{
		"/api/v1/batches/abc":                      http.StatusBadRequest,
		"/api/v1/batches/-1":                       http.StatusBadRequest,
		"/api/v1/batches/500/other":                http.StatusNotFound,
		"/api/v1/batches/600/jobs?sort=x":          http.StatusBadRequest,
		"/api/v1/batches/600/jobs?status=sleeping": http.StatusBadRequest,
		"/api/v1/batches/600/jobs?order=up":        http.StatusBadRequest,
		"/api/v1/batches/600/jobs?page_size=0":     http.StatusBadRequest,
	} {
		if w := f.do(t, http.MethodGet, path, "", alice); w.Code != code {
			t.Errorf("GET %s: %d, want %d", path, w.Code, code)
		}
	}
	if w := f.do(t, http.MethodPost, "/api/v1/batches/600", "{}", alice); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", w.Code)
	}
}

// The jobs listing merges the queue and history: the queue first, then
// the finished, latest first; filtered, sorted and paged.
//
//nolint:gocyclo // one fixture, many facts about it
func TestBatchJobs(t *testing.T) {
	f := batchFixture(t)
	alice := f.bearer(t, "alice")
	all := f.batchJobs(t, "/api/v1/batches/600/jobs", alice)
	// 600.1 finished last (300+10+300), then 600.0 (410) and 600.2 (360).
	if got := rowIDs(all.Jobs); !slices.Equal(got, []string{"601.0", "601.1", "600.1", "600.0", "600.2"}) || all.Total != 5 || all.ID != 600 {
		t.Errorf("default order = %v (total %d)", got, all.Total)
	}
	byID := map[string]BatchJobRow{}
	for _, r := range all.Jobs {
		byID[r.ID] = r
	}
	if r := byID["600.2"]; r.Source != "history" || r.Outcome != "failed" || r.ExitSignal == nil || *r.ExitSignal != 9 || r.ExitCode != nil {
		t.Errorf("600.2 = %+v", r)
	}
	if r := byID["600.1"]; r.RuntimeSeconds == nil || *r.RuntimeSeconds != 300 || r.PeakMemoryMiB == nil || *r.PeakMemoryMiB != 1000 ||
		r.ExitCode == nil || *r.ExitCode != 0 || r.Outcome != "succeeded" {
		t.Errorf("600.1 = %+v", r)
	}
	if r := byID["601.1"]; r.Source != "queue" || r.Status != batches.StatusRunning || r.Started == nil || r.Outcome != "" || r.RuntimeSeconds != nil {
		t.Errorf("601.1 = %+v", r)
	}

	if got := rowIDs(f.batchJobs(t, "/api/v1/batches/600/jobs?status=finished&sort=runtime", alice).Jobs); !slices.Equal(got, []string{"600.1", "600.0", "600.2"}) {
		t.Errorf("finished by runtime = %v", got)
	}
	if got := rowIDs(f.batchJobs(t, "/api/v1/batches/600/jobs?sort=runtime&order=asc", alice).Jobs); !slices.Equal(got, []string{"600.2", "600.0", "600.1", "601.0", "601.1"}) {
		t.Errorf("runtime ascending, missing last = %v", got)
	}
	if got := rowIDs(f.batchJobs(t, "/api/v1/batches/600/jobs?status=idle,running", alice).Jobs); !slices.Equal(got, []string{"601.0", "601.1"}) {
		t.Errorf("idle,running = %v", got)
	}
	if got := rowIDs(f.batchJobs(t, "/api/v1/batches/600/jobs?status=live&sort=id&order=desc", alice).Jobs); !slices.Equal(got, []string{"601.1", "601.0"}) {
		t.Errorf("live by id desc = %v", got)
	}
	if got := rowIDs(f.batchJobs(t, "/api/v1/batches/600/jobs?sort=exit", alice).Jobs); !slices.Equal(got, []string{"600.0", "600.1", "600.2", "601.0", "601.1"}) {
		t.Errorf("by exit = %v", got)
	}
	p1 := f.batchJobs(t, "/api/v1/batches/600/jobs?page_size=2", alice)
	if p1.NextOffset == nil || *p1.NextOffset != 2 || len(p1.Jobs) != 2 {
		t.Fatalf("page 1 = %+v", p1)
	}
	p3 := f.batchJobs(t, "/api/v1/batches/600/jobs?page_size=2&offset=4", alice)
	if p3.NextOffset != nil || rowIDs(p3.Jobs)[0] != "600.2" {
		t.Errorf("page 3 = %+v", p3)
	}
	if p := f.batchJobs(t, "/api/v1/batches/600/jobs?offset=50", alice); len(p.Jobs) != 0 || p.Total != 5 || p.Jobs == nil {
		t.Errorf("past the end = %+v", p)
	}
	dag := f.batchJobs(t, "/api/v1/batches/503/jobs?sort=id", alice)
	if dag.ID != 500 || len(dag.Jobs) != 7 || !dag.Jobs[0].Dagman || dag.Jobs[0].Node != "" || dag.Jobs[1].Node != "A" ||
		dag.Jobs[4].HoldReason == "" || dag.Jobs[4].HoldCode == nil {
		t.Errorf("dag rows = %+v", dag.Jobs)
	}
}

// The routes are documented.
func TestBatchesAreDocumented(t *testing.T) {
	var doc struct {
		Paths map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal([]byte(openAPISchema), &doc); err != nil {
		t.Fatalf("openapi does not parse: %v", err)
	}
	for _, path := range []string{"/batches/{batchId}", "/batches/{batchId}/jobs"} {
		if _, ok := doc.Paths[path]; !ok {
			t.Errorf("%s missing from the OpenAPI paths", path)
		}
	}
}

// A DAGMan job's record is the workflow's span and verdict, not a job's
// work: it stays out of the finished-job statistics, which describe the
// nodes.
func TestBatchFinishedLeavesOutDAGMan(t *testing.T) {
	var reader utilization.JobReader
	rec := func(text string) batchRecord {
		ad, err := classad.ParseOld(text)
		if err != nil {
			t.Fatal(err)
		}
		return newBatchRecord(ad, false, &reader)
	}
	recs := []batchRecord{
		rec("ClusterId = 1\nProcId = 0\nCmd = \"/usr/bin/condor_dagman\"\nJobUniverse = 7\nJobStatus = 4\nExitCode = 1\n" +
			"RemoteWallClockTime = 3600.0\nCommittedTime = 0\nDAG_NodesTotal = 2\nJobBatchName = \"a.dag+1\""),
		rec("ClusterId = 2\nProcId = 0\nCmd = \"/bin/x\"\nJobStatus = 4\nExitCode = 0\nRemoteWallClockTime = 60.0\nCommittedTime = 60\n" +
			"DAGManJobId = 1\nJobBatchName = \"a.dag+1\""),
	}
	ident, _ := batches.Identify(&recs[0].f)
	snap := summarizeBatch(ident, recs, nil)
	fin := snap.summary.Finished
	if fin.Jobs != 1 || fin.Succeeded != 1 || fin.Failed != 0 || fin.WallHours != 60.0/3600 || fin.BadputHours != 0 ||
		fin.Runtime == nil || fin.Runtime.Max != 60 || !snap.summary.HasHistory || len(snap.rows) != 2 {
		t.Errorf("finished = %+v, rows %d", fin, len(snap.rows))
	}
	// Only the DAGMan job has finished: there is history, and no job
	// statistics yet.
	snap = summarizeBatch(ident, recs[:1], nil)
	if !snap.summary.HasHistory || snap.summary.Finished.Jobs != 0 || snap.summary.LastCompletion != nil {
		t.Errorf("dagman only: %+v", snap.summary)
	}
}
